#include "sleipnir/engine.hpp"
#include "sleipnir/fuzz.hpp"
#include "sleipnir/netio.hpp"
#include "sleipnir/targets.hpp"

#include <asio.hpp>

#ifdef SLEIPNIR_HAVE_TLS
#include "sleipnir/tls_checks.hpp"
#include "sleipnir/tls_client.hpp"
#endif

#include <chrono>
#include <set>
#include <thread>

namespace sln {

ScanEngine::ScanEngine(const ScanConfig& cfg)
    : cfg_(cfg),
      probes_(ProbeDb::load(cfg.data_dir + "/service_probes.json")),
      cves_(CveDb::load(cfg.data_dir + "/cve_map.json")) {
    collector_.set_verbose(cfg.verbose);
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
        process_job(*job, client, io);
        if (cfg_.delay_ms > 0)
            std::this_thread::sleep_for(
                std::chrono::milliseconds(cfg_.delay_ms));
    }
}

void ScanEngine::process_job(const Job& job, TcpClient& client,
                             asio::io_context& io) {
    const int timeout = cfg_.timeout_ms;

    if (!client.connect(job.host, job.port, timeout)) {
        if (cfg_.verbose) collector_.debug(job.host + ":" +
                                           std::to_string(job.port) + " closed");
        return;
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

    // 2. CVE matching from the identified product/version
    if (!result.product.empty()) {
        for (auto& f :
             cves_.match(job.host, job.port, result.product, result.version))
            collector_.add_finding(std::move(f));
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

            if (auto resp =
                    http_get(tls, job.host, job.port, "/", timeout,
                             cfg_.user_agent)) {
                result.http_status = resp->status;
                result.http_headers = resp->headers;

                auto root = check_root_response(job.host, job.port, *resp);
                for (auto& f : root.findings) collector_.add_finding(std::move(f));
                for (const auto& [product, version] : root.tech_stack) {
                    for (auto& f : cves_.match(job.host, job.port, product,
                                               version))
                        collector_.add_finding(std::move(f));
                }

                for (auto& f : check_sensitive_paths(tls, job.host, job.port,
                                                     timeout, cfg_.user_agent))
                    collector_.add_finding(std::move(f));
                for (auto& f : check_http_methods(tls, job.host, job.port,
                                                  timeout, cfg_.user_agent))
                    collector_.add_finding(std::move(f));

                ctx.service = "https";
                ctx.has_http = true;
                ctx.http_status = resp->status;
                ctx.http_headers = resp->headers;
                ctx.http_body = resp->body;
                plugins_.on_http_response(ctx, io, timeout, collector_);
            }
            plugins_.on_service(ctx, io, timeout, collector_);
            collector_.add_port(std::move(result));
            return;
        }
        // not TLS after all: keep the "unknown" result from below
    }
#endif

    // 3b. plain HTTP pipeline
    if (result.service == "http") {
        client.close();
        if (auto resp = http_get(client, job.host, job.port, "/", timeout,
                                 cfg_.user_agent)) {
            result.http_status = resp->status;
            result.http_headers = resp->headers;

            auto root = check_root_response(job.host, job.port, *resp);
            for (auto& f : root.findings) collector_.add_finding(std::move(f));
            for (const auto& [product, version] : root.tech_stack) {
                for (auto& f :
                     cves_.match(job.host, job.port, product, version))
                    collector_.add_finding(std::move(f));
            }

            for (auto& f :
                 check_sensitive_paths(client, job.host, job.port, timeout,
                                       cfg_.user_agent))
                collector_.add_finding(std::move(f));
            for (auto& f :
                 check_http_methods(client, job.host, job.port, timeout,
                                    cfg_.user_agent))
                collector_.add_finding(std::move(f));

            ctx.has_http = true;
            ctx.http_status = resp->status;
            ctx.http_headers = resp->headers;
            ctx.http_body = resp->body;
            plugins_.on_http_response(ctx, io, timeout, collector_);
        }
    }

    // 4. hooks that want the final picture
    plugins_.on_service(ctx, io, timeout, collector_);

    // 5. robustness fuzzing (own stand only!)
    if (cfg_.fuzz) {
        client.close();
        run_fuzz(io, job.host, job.port, cfg_, collector_);
    }

    collector_.add_port(std::move(result));
}

std::vector<PortResult> ScanEngine::run(const std::vector<std::string>& hosts,
                                        const std::vector<uint16_t>& ports) {
    auto& stats = collector_.stats();
    stats.hosts = hosts.size();
    stats.jobs_total = hosts.size() * ports.size();

    for (const auto& host : hosts)
        for (uint16_t port : ports) queue_.push({host, port});
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
