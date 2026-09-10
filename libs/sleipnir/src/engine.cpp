#include "sleipnir/engine.hpp"
#include "sleipnir/auth.hpp"
#include "sleipnir/crawler.hpp"
#include "sleipnir/fuzz.hpp"
#include "sleipnir/netio.hpp"
#include "sleipnir/syn_scan.hpp"
#include "sleipnir/targets.hpp"
#include "sleipnir/udp_scan.hpp"
#include "sleipnir/verify.hpp"

#include <asio.hpp>

#ifdef SLEIPNIR_HAVE_TLS
#include "sleipnir/tls_checks.hpp"
#include "sleipnir/tls_client.hpp"
#endif

#include <chrono>
#include <set>
#include <thread>

namespace sln {

namespace {

// Maps the site graph and runs the active application probes on one
// (host, port) using the given transport.
template <typename Stream>
void crawl_and_assess(Stream& stream, const std::string& host, uint16_t port,
                      const ScanConfig& cfg, int timeout, const char* scheme,
                      ResultCollector& collector) {
    CrawlConfig cc;
    cc.max_pages = cfg.crawl_max_pages;
    cc.max_depth = cfg.crawl_depth;
    cc.scheme = scheme;
    cc.host = host;
    cc.port = port;
    HttpFetcher fetch = [&](const std::string& path) {
        return http_get(stream, host, port, path, timeout, cfg.user_agent);
    };
    HttpPostFetcher post = [&](const std::string& path, const std::string& body,
                               const std::string& ctype) {
        HttpOptions opts;
        opts.body = body;
        opts.content_type = ctype;
        return http_request_ex(stream, "POST", host, port, path, timeout,
                               cfg.user_agent, opts);
    };
    auto crawl = crawl_site(fetch, "/", cc);
    collector.log("  [crawl] " + host + ":" + std::to_string(port) + ": " +
                  std::to_string(crawl.pages.size()) + " page(s), " +
                  std::to_string(crawl.forms.size()) + " form(s), " +
                  std::to_string(crawl.param_urls.size()) +
                  " parameterized URL(s)");
    ActiveProbeConfig apc;
    apc.max_requests = cfg.crawl_max_requests;
    apc.allow_post = !cfg.safe;
    for (auto& f : check_crawled_app(fetch, post, crawl, host, port, apc))
        collector.add_finding(std::move(f));
}

// Adds version-matched CVE findings without running their checks (no HTTP
// transport available) — they stay "potential".
void flush_unverified(std::vector<Finding>& pending,
                      ResultCollector& collector) {
    for (auto& f : pending) collector.add_finding(std::move(f));
    pending.clear();
}

// Runs one finding's script-based check. Script checks carry their own
// transports (tcp_connect/http_get via the sandboxed Lua API), so they
// work for non-HTTP services like Redis just as well.
void apply_script_check(Finding& f, PluginHost& plugins,
                        const std::string& checks_dir,
                        const std::string& host, uint16_t port,
                        asio::io_context& io, int timeout, bool safe,
                        ResultCollector& collector) {
    if (!f.check || f.check->script.empty()) return;
    if (safe && !f.check->safe) return; // --safe policy: not safe-mode compatible
    auto r = plugins.run_check_script(checks_dir + f.check->script, host,
                                      port, io, timeout, collector);
    if (r.verified) {
        f.verified = true;
        f.confidence = "confirmed";
        if (!r.evidence.empty())
            f.evidence = f.evidence.empty() ? r.evidence
                                            : f.evidence + "; " + r.evidence;
    } else if (!r.error.empty()) {
        collector.log("  [verify] check script '" + f.check->script +
                      "' failed: " + r.error);
    }
}

// Non-HTTP services still get their script-based checks run; probe-based
// findings stay "potential" (no HTTP transport to verify them over).
void verify_scripts_and_flush(std::vector<Finding>& pending,
                              ResultCollector& collector, asio::io_context& io,
                              PluginHost& plugins,
                              const std::string& checks_dir,
                              const std::string& host, uint16_t port,
                              int timeout, bool safe) {
    for (auto& f : pending) {
        apply_script_check(f, plugins, checks_dir, host, port, io, timeout,
                           safe, collector);
        collector.add_finding(std::move(f));
    }
    pending.clear();
}

// Verification stage over an HTTP transport: the universal Log4Shell canary
// plus every CVE record's active check. A marker in a response upgrades the
// finding from potential to confirmed with probe evidence. Script-based
// checks (VulnCheck::script) run through the Lua host on their own
// transports, independent of this stream.
template <typename Stream>
void verification_stage(Stream& stream, const ScanConfig& cfg,
                        const std::string& host, uint16_t port, int timeout,
                        std::vector<Finding>& pending,
                        ResultCollector& collector, asio::io_context& io,
                        PluginHost& plugins, const std::string& checks_dir) {
    if (cfg.no_verify) {
        flush_unverified(pending, collector);
        return;
    }
    ProbeFetcher fetch = probe_fetcher(stream, host, port, timeout,
                                       cfg.user_agent);
    if (auto f = check_log4shell(fetch, host, port, canary_token()))
        collector.add_finding(std::move(*f));
    for (auto& f : pending) {
        if (f.check && !f.check->script.empty())
            apply_script_check(f, plugins, checks_dir, host, port, io,
                               timeout, cfg.safe, collector);
        else if (f.check)
            verify_finding(fetch, f, !cfg.safe);
        collector.add_finding(std::move(f));
    }
    pending.clear();
}

} // namespace

ScanEngine::ScanEngine(const ScanConfig& cfg)
    : cfg_(cfg),
      checks_dir_(cfg.plugins_dir + "/checks/"),
      probes_(ProbeDb::load(cfg.data_dir + "/service_probes.json")),
      cves_(CveDb::load(cfg.data_dir + "/cve_map.json")) {
    collector_.set_verbose(cfg.verbose);
    TimingProfile prof = timing_profile(cfg.timing);
    base_delay_ms_ = std::max(prof.delay_ms, cfg.delay_ms);
    adaptive_ceiling_ = prof.adaptive_ceiling;
    if (!cfg.disable_plugins) {
        for (const auto& rep : plugins_.load_dir(cfg.plugins_dir)) {
            if (rep.error.empty()) {
                collector_.log("[plugins] loaded " + rep.plugin);
            } else {
                collector_.log("[plugins] FAILED to load " + rep.plugin + ": " +
                               rep.error);
            }
        }
    }
    for (uint16_t p : expand_ports(cfg.tls_ports)) tls_ports_.insert(p);
}

ScanEngine::~ScanEngine() = default;

void ScanEngine::worker_loop() {
    asio::io_context io;
    TcpClient client(io);

    while (auto job = queue_.pop()) {
        if (stop_requested_) break;
        int failed_ms = process_job(*job, client, io);
        // Adaptive pacing: a connect that burned the whole timeout means a
        // filtered/ratelimiting target — back off. Fast RSTs and successful
        // connects recover toward the profile floor.
        if (failed_ms >= cfg_.timeout_ms * 9 / 10) {
            int d = adaptive_delay_ms_.load();
            int nd = std::min(d ? d * 2 : 40, adaptive_ceiling_);
            if (nd != d) {
                adaptive_delay_ms_.store(nd);
                if (cfg_.verbose)
                    collector_.log("[timing] backoff -> " +
                                   std::to_string(nd) + " ms");
            }
        } else {
            int d = adaptive_delay_ms_.load();
            int nd = std::max(d / 2, 0);
            if (nd != d) adaptive_delay_ms_.store(nd);
        }
        int pause = std::max(base_delay_ms_, adaptive_delay_ms_.load());
        if (pause > 0)
            std::this_thread::sleep_for(std::chrono::milliseconds(pause));
    }
}

int ScanEngine::process_job(const Job& job, TcpClient& client,
                            asio::io_context& io) {
    const int timeout = cfg_.timeout_ms;

    auto t0 = std::chrono::steady_clock::now();
    bool connected = client.connect(job.host, job.port, timeout);
    int connect_ms = static_cast<int>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - t0)
            .count());
    if (!connected) {
        if (cfg_.verbose) collector_.debug(job.host + ":" +
                                           std::to_string(job.port) + " closed");
        return connect_ms;
    }

    PortResult result;
    result.host = job.host;
    result.port = job.port;
    result.status = PortStatus::Open;

    // 1. fingerprint via probes (banner grabbing + active probes)
    auto reconnect = [&client, &job, timeout] {
        return client.connect(job.host, job.port, timeout);
    };
    if (auto info = probes_.identify(client, job.host, reconnect, timeout)) {
        result.service = info->service;
        result.product = info->product;
        result.version = info->version;
        result.banner = info->banner;
    } else {
        result.service = "unknown";
        // try to restore the connection for the checks below
        reconnect();
    }

    collector_.log("  [open] " + job.host + ":" + std::to_string(job.port) +
                   (result.service.empty()
                        ? ""
                        : "  (" + result.service +
                              (result.version.empty()
                                   ? ""
                                   : " " + result.product + "/" +
                                         result.version) +
                              ")"));

    // 2. CVE matching from the identified product/version. Findings with an
    // active check are buffered until we know whether an HTTP transport can
    // verify them; everything else is re-added below.
    std::vector<Finding> pending_cve;
    if (!result.product.empty()) {
        pending_cve = cves_.match(job.host, job.port, result.product,
                                  result.version);
    }

    // Cleartext credential exposure: telnet carries logins unencrypted.
    if (result.service == "telnet") {
        Finding f;
        f.host = job.host;
        f.port = job.port;
        f.title = "Telnet service transmits credentials in cleartext";
        f.severity = Severity::Low;
        f.description =
            "Telnet has no transport encryption: usernames, passwords and "
            "session content are visible to anyone on the network path. Use "
            "SSH instead.";
        f.evidence = "service identified as telnet";
        f.source = "builtin";
        collector_.add_finding(std::move(f));
    }

    PluginContext ctx;
    ctx.host = job.host;
    ctx.port = job.port;
    ctx.service = result.service;
    ctx.product = result.product;
    ctx.version = result.version;
    ctx.banner = result.banner;

    plugins_.on_port_open(ctx, io, timeout, collector_);

    // Authenticated scanning (--auth): headers established once per port,
    // then attached to every request of the HTTP pipelines below.
    std::vector<std::pair<std::string, std::string>> session_headers;
    if (auth_applies(cfg_.auth, job.host)) {
        session_headers = establish_auth_session(io, cfg_.auth, job.host,
                                                 timeout, cfg_.user_agent,
                                                 collector_);
        if (!session_headers.empty())
            collector_.log("  [auth] session active (" + cfg_.auth.method +
                           ")");
    }

#ifdef SLEIPNIR_HAVE_TLS
    // 3a. TLS endpoint: plaintext probes could not identify the service and
    // the port is a known TLS candidate -> handshake, certificate checks,
    // full HTTP pipeline over TLS.
    if (result.service == "unknown" && !cfg_.no_tls &&
        tls_ports_.count(job.port)) {
        client.close();
        TlsClient tls(io);
        if (tls.connect(job.host, job.port, timeout)) {
            const auto& peer = tls.peer();
            result.service = "https";
            result.tls = summarize_tls(job.host, peer);

            for (auto& f : check_tls_certificate(job.host, job.port, peer))
                collector_.add_finding(std::move(f));
            for (auto& f : check_tls_legacy_protocols(io, job.host, job.port,
                                                      timeout))
                collector_.add_finding(std::move(f));

            // session headers ride on every HTTP request over TLS
            AuthStream<TlsClient> http(tls, session_headers);
            bool http_ok = false;
            if (auto resp =
                    http_get(http, job.host, job.port, "/", timeout,
                             cfg_.user_agent)) {
                http_ok = true;
                result.http_status = resp->status;
                result.http_headers = resp->headers;

                auto root = check_root_response(job.host, job.port, *resp);
                for (auto& f : root.findings) collector_.add_finding(std::move(f));
                for (const auto& [product, version] : root.tech_stack) {
                    for (auto& f : cves_.match(job.host, job.port, product,
                                               version))
                        pending_cve.push_back(std::move(f));
                }

                for (auto& f : check_sensitive_paths(http, job.host, job.port,
                                                     timeout, cfg_.user_agent))
                    collector_.add_finding(std::move(f));
                for (auto& f : check_webapp_probes(http, job.host, job.port,
                                                   timeout, cfg_.user_agent,
                                                   !cfg_.safe))
                    collector_.add_finding(std::move(f));
                for (auto& f : check_http_methods(http, job.host, job.port,
                                                  timeout, cfg_.user_agent))
                    collector_.add_finding(std::move(f));

                if (!cfg_.no_crawl)
                    crawl_and_assess(http, job.host, job.port, cfg_, timeout,
                                     "https", collector_);

                ctx.service = "https";
                ctx.has_http = true;
                ctx.http_status = resp->status;
                ctx.http_headers = resp->headers;
                ctx.http_body = resp->body;
                plugins_.on_http_response(ctx, io, timeout, collector_);
            }
            plugins_.on_service(ctx, io, timeout, collector_);

             // Active CVE verification over the TLS transport.
             if (http_ok)
                 verification_stage(http, cfg_, job.host, job.port, timeout,
                                    pending_cve, collector_, io, plugins_,
                                    checks_dir_);
             else
                 verify_scripts_and_flush(pending_cve, collector_, io,
                                          plugins_, checks_dir_, job.host,
                                          job.port, timeout, cfg_.safe);

            collector_.add_port(std::move(result));
            return 0;
        }
        // not TLS after all: keep the "unknown" result from below
    }
#endif

    // 3b. plain HTTP pipeline
    bool http_ok = false;
    if (result.service == "http") {
        client.close();
        // session headers ride on every HTTP request
        AuthStream<TcpClient> http(client, session_headers);
        if (auto resp = http_get(http, job.host, job.port, "/", timeout,
                                 cfg_.user_agent)) {
            http_ok = true;
            result.http_status = resp->status;
            result.http_headers = resp->headers;

            auto root = check_root_response(job.host, job.port, *resp);
            for (auto& f : root.findings) collector_.add_finding(std::move(f));
            for (const auto& [product, version] : root.tech_stack) {
                for (auto& f :
                     cves_.match(job.host, job.port, product, version))
                    pending_cve.push_back(std::move(f));
            }

            for (auto& f :
                 check_sensitive_paths(http, job.host, job.port, timeout,
                                       cfg_.user_agent))
                collector_.add_finding(std::move(f));
            for (auto& f :
                 check_webapp_probes(http, job.host, job.port, timeout,
                                     cfg_.user_agent, !cfg_.safe))
                collector_.add_finding(std::move(f));
            for (auto& f :
                 check_http_methods(http, job.host, job.port, timeout,
                                    cfg_.user_agent))
                collector_.add_finding(std::move(f));

            if (!cfg_.no_crawl)
                crawl_and_assess(http, job.host, job.port, cfg_, timeout,
                                 "http", collector_);

            ctx.has_http = true;
            ctx.http_status = resp->status;
            ctx.http_headers = resp->headers;
            ctx.http_body = resp->body;
            plugins_.on_http_response(ctx, io, timeout, collector_);
        }
    }

#ifdef SLEIPNIR_HAVE_TLS
    // 3c. Ports that answered plain HTTP but sit on a TLS port number
    // (proxies, double listeners): still audit the certificate.
    if (result.service == "http" && !cfg_.no_tls && tls_ports_.count(job.port)) {
        client.close();
        TlsClient tls(io);
        if (tls.connect(job.host, job.port, timeout)) {
            const auto& peer = tls.peer();
            result.tls = summarize_tls(job.host, peer);
            for (auto& f : check_tls_certificate(job.host, job.port, peer))
                collector_.add_finding(std::move(f));
            for (auto& f : check_tls_legacy_protocols(io, job.host, job.port,
                                                      timeout))
                collector_.add_finding(std::move(f));
        }
    }
#endif

    // 4. hooks that want the final picture
    plugins_.on_service(ctx, io, timeout, collector_);

    // Active CVE verification: over HTTP the buffered findings can be proven
    // by their checks; without HTTP only script-based checks can still run.
    if (http_ok) {
        AuthStream<TcpClient> http(client, session_headers);
        verification_stage(http, cfg_, job.host, job.port, timeout,
                           pending_cve, collector_, io, plugins_, checks_dir_);
    } else
        verify_scripts_and_flush(pending_cve, collector_, io, plugins_,
                                 checks_dir_, job.host, job.port, timeout,
                                 cfg_.safe);

    // 5. robustness fuzzing (own stand only!)
    if (cfg_.fuzz) {
        client.close();
        run_fuzz(io, job.host, job.port, cfg_, collector_);
    }

    collector_.add_port(std::move(result));
    return 0;
}

std::vector<PortResult> ScanEngine::run(const std::vector<std::string>& hosts,
                                        const std::vector<uint16_t>& ports) {
    auto& stats = collector_.stats();
    stats.hosts = hosts.size();
    stats.jobs_total = 0;

    // Phase 1: SYN (stealth) discovery. When it runs, it replaces the
    // connect-based port state: open ports continue through the full
    // fingerprinting pipeline, closed/filtered ones are only counted.
    std::vector<Job> tcp_jobs;
    bool syn_used = false;
    if (cfg_.syn_scan) {
        auto outcomes = syn_discover(hosts, ports, cfg_.timeout_ms,
                                     cfg_.delay_ms, collector_);
        if (outcomes) {
            syn_used = true;
            size_t open_count = 0;
            stats.jobs_total += outcomes->size();
            for (const auto& o : *outcomes) {
                if (o.status == PortStatus::Open) {
                    tcp_jobs.push_back({o.host, o.port});
                    ++open_count;
                } else if (cfg_.verbose) {
                    PortResult row;
                    row.host = o.host;
                    row.port = o.port;
                    row.status = o.status;
                    row.service = "unknown";
                    collector_.add_port(std::move(row));
                } else {
                    collector_.count_port(o.status);
                }
            }
            stats.jobs_total += open_count;
            collector_.log("  [syn] " + std::to_string(outcomes->size()) +
                           " endpoint(s) probed: " +
                           std::to_string(open_count) + " open, " +
                           std::to_string(outcomes->size() - open_count) +
                           " closed/filtered");
        } else {
            collector_.log(
                "[syn] raw sockets unavailable (need root / CAP_NET_RAW) — "
                "falling back to TCP connect scan");
        }
    }
    if (!syn_used) {
        for (const auto& host : hosts)
            for (uint16_t port : ports) tcp_jobs.push_back({host, port});
        stats.jobs_total += tcp_jobs.size();
    }

    // Phase 2: UDP service scan — independent of the TCP pipeline.
    if (cfg_.udp_scan) {
        auto udp_ports = expand_ports(cfg_.udp_ports);
        stats.jobs_total += hosts.size() * udp_ports.size();
        auto rows = udp_discover(hosts, udp_ports, cfg_.timeout_ms,
                                 cfg_.threads, collector_);
        for (auto& r : rows) {
            if (r.status == PortStatus::Open || cfg_.verbose)
                collector_.add_port(std::move(r));
            else
                collector_.count_port(r.status);
        }
    }

    // Phase 3: TCP fingerprinting pipeline.
    for (const auto& job : tcp_jobs) queue_.push(job);
    queue_.close();

    asio::thread_pool pool(cfg_.threads);
    for (int i = 0; i < cfg_.threads; ++i)
        asio::post(pool, [this] { worker_loop(); });
    pool.join();

    return collector_.ports();
}

void ScanEngine::request_stop() {
    stop_requested_ = true;
    fuzz_request_stop();
}

void ScanEngine::reset_stop() {
    stop_requested_ = false;
    fuzz_reset_stop();
}

} // namespace sln
