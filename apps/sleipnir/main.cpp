// Sleipnir CLI entry point: one-shot command line mode plus an interactive
// shell (the default when run from a terminal without arguments).
#include "sleipnir/engine.hpp"
#include "sleipnir/report.hpp"
#include "sleipnir/targets.hpp"

#ifndef SLEIPNIR_VERSION
#define SLEIPNIR_VERSION "dev"
#endif

#include <cli11/CLI11.hpp>
#include <nlohmann/json.hpp>

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <deque>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <string>
#include <unistd.h>
#include <vector>

namespace {

constexpr const char* C_RESET = "\033[0m";
constexpr const char* C_BOLD = "\033[1m";
constexpr const char* C_DIM = "\033[2m";
constexpr const char* C_CYAN = "\033[36m";

std::atomic<bool> g_interrupted{false};

// async-signal-safe: only atomic stores
void on_signal(int) {
    g_interrupted = true;
    sln::ScanEngine::request_stop();
}

// Parses the --auth JSON file into cfg.auth. Returns an error message on
// invalid configuration, empty on success.
std::string parse_auth_file(sln::ScanConfig& cfg) {
    std::ifstream in(cfg.auth_file);
    if (!in) return "cannot open auth file: " + cfg.auth_file;
    nlohmann::json j;
    try {
        in >> j;
    } catch (const std::exception& e) {
        return std::string("auth file is not valid JSON: ") + e.what();
    }

    auto& a = cfg.auth;
    a.method = j.value("method", "");
    for (char& c : a.method)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    a.url = j.value("url", "");
    a.user = j.value("user", "");
    a.password = j.value("password", "");
    a.success = j.value("success", "");
    a.cookie = j.value("cookie", "");
    a.cookie_file = j.value("cookie_file", "");
    if (j.contains("fields") && j["fields"].is_object())
        for (auto it = j["fields"].begin(); it != j["fields"].end(); ++it)
            a.fields[it.key()] = it.value().get<std::string>();
    if (j.contains("hosts") && j["hosts"].is_array())
        for (const auto& h : j["hosts"])
            a.hosts.push_back(h.get<std::string>());

    if (a.method == "basic") {
        if (a.user.empty() || a.password.empty())
            return "auth method 'basic' needs 'user' and 'password'";
    } else if (a.method == "form") {
        if (a.url.empty()) return "auth method 'form' needs 'url'";
        if (a.fields.empty()) return "auth method 'form' needs 'fields'";
    } else if (a.method == "cookie") {
        if (a.cookie.empty() && a.cookie_file.empty())
            return "auth method 'cookie' needs 'cookie' or 'cookie_file'";
    } else {
        return "auth method must be basic, form or cookie (got '" +
               a.method + "')";
    }
    return "";
}

// Directory containing the running executable. /proc/self/exe is exact on
// Linux; argv[0]-based resolution is the portable fallback.
std::filesystem::path exe_dir(const char* argv0) {
    std::error_code ec;
    auto self = std::filesystem::read_symlink("/proc/self/exe", ec);
    if (!ec) return self.parent_path();
    if (argv0 && *argv0) {
        auto exe = std::filesystem::weakly_canonical(argv0, ec);
        if (!ec && exe.has_parent_path()) return exe.parent_path();
    }
    return std::filesystem::current_path();
}

// Resolve data/ and plugins/ by walking up from the CWD and from the
// executable's directory, so the binary works from any working directory
// (e.g. build/apps/sleipnir/ or an unrelated shell location).
std::string auto_dir(const char* arg_value, const char* subdirectory,
                     const std::filesystem::path& exe_loc) {
    if (std::filesystem::exists(arg_value)) return arg_value;
    for (std::filesystem::path base :
         {std::filesystem::current_path(), exe_loc}) {
        std::filesystem::path dir = base;
        for (int depth = 0; depth < 8 && !dir.empty(); ++depth) {
            std::filesystem::path candidate = dir / subdirectory;
            if (std::filesystem::exists(candidate)) return candidate.string();
            auto parent = dir.parent_path();
            if (parent == dir) break;
            dir = parent;
        }
    }
    return arg_value;
}

// ---------------------------------------------------------------------------
// Scan execution (shared by CLI mode and the interactive shell)
// ---------------------------------------------------------------------------

// Severity threshold for --fail-on; rank = -1 disables the CI gate.
int fail_on_rank(const std::string& spec) {
    if (spec.empty()) return -1;
    sln::Severity s = sln::severity_from_string(spec);
    if (s == sln::Severity::Info) return -1; // "info"/unknown -> gate disabled
    return sln::severity_rank(s);
}

int run_scan(sln::ScanConfig& cfg, const char* argv0) {    if (cfg.targets.empty()) {
        std::cerr << "error: no targets given (usage: scan <targets...> "
                     "[options])\n";
        return 2;
    }

    // Safe mode is non-intrusive by definition: it overrides --fuzz and the
    // delay-based parametric probes.
    if (cfg.safe && cfg.fuzz) {
        std::cout << "[safe mode] fuzzing disabled (--safe overrides -f)\n";
        cfg.fuzz = false;
    }
    if (cfg.safe && cfg.time_probes) {
        std::cout << "[safe mode] time-based probes disabled (--safe "
                     "overrides --time-probes)\n";
        cfg.time_probes = false;
    }

    // Authenticated scanning: validate the config before touching targets.
    if (!cfg.auth_file.empty()) {
        if (std::string err = parse_auth_file(cfg); !err.empty()) {
            std::cerr << "error: " << err << "\n";
            return 2;
        }
    }

    // Timing profile: fill unset options from the profile; explicitly given
    // values win.
    if (cfg.timing != 3) {
        sln::TimingProfile prof = sln::timing_profile(cfg.timing);
        std::cout << "[timing] -T" << cfg.timing << ": base delay "
                  << prof.delay_ms << " ms, timeout " << prof.timeout_ms
                  << " ms, max " << prof.max_threads << " workers, adaptive "
                  << "backoff up to " << prof.adaptive_ceiling << " ms\n";
        if (!cfg.timeout_explicit) cfg.timeout_ms = prof.timeout_ms;
        if (!cfg.threads_explicit)
            cfg.threads = std::min(cfg.threads, prof.max_threads);
        if (!cfg.delay_explicit) cfg.delay_ms = prof.delay_ms;
    }

    std::filesystem::path exe_loc = exe_dir(argv0);
    cfg.plugins_dir = auto_dir(cfg.plugins_dir.c_str(), "plugins", exe_loc);
    cfg.data_dir = auto_dir(cfg.data_dir.c_str(), "data", exe_loc);

    try {
        auto hosts = sln::expand_targets(cfg.targets);
        auto ports = sln::expand_ports(cfg.ports);
        std::cout << "Sleipnir: " << hosts.size() << " host(s) x "
                  << ports.size() << " port(s), " << cfg.threads
                  << " workers\n";

        // Interactive sessions reuse the process after Ctrl+C; a stale stop
        // flag would abort the next scan immediately.
        sln::ScanEngine::reset_stop();
        g_interrupted = false;

        sln::ScanEngine engine(cfg);
        auto start = std::chrono::steady_clock::now();
        engine.run(hosts, ports);
        double elapsed = std::chrono::duration<double>(
                             std::chrono::steady_clock::now() - start)
                             .count();

        if (g_interrupted)
            std::cout << "\n[interrupt] scan stopped early, partial results "
                         "below\n";

        sln::print_console_report(engine.collector(), cfg, elapsed);

        if (!cfg.report_path.empty()) {
            bool ok = sln::write_report(cfg.report_path,
                                        engine.collector().ports(),
                                        engine.collector().findings(),
                                        engine.collector().stats(), cfg,
                                        elapsed);
            std::cout << (ok ? "Report written to " + cfg.report_path
                             : "FAILED to write " + cfg.report_path)
                      << "\n";
        }

        // CI gate: non-zero exit when findings reach the configured severity.
        if (int threshold = fail_on_rank(cfg.fail_on); threshold >= 0) {
            int hits = 0;
            for (const auto& f : engine.collector().findings())
                if (sln::severity_rank(f.severity) >= threshold) ++hits;
            if (hits > 0) {
                std::cout << "fail-on gate: " << hits
                          << " finding(s) at or above '" << cfg.fail_on
                          << "'\n";
                return 3;
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 1;
    }
    return 0;
}

int run_list_plugins(const sln::ScanConfig& cfg, const char* argv0) {
    sln::PluginHost host;
    auto reports = host.load_dir(auto_dir(cfg.plugins_dir.c_str(), "plugins",
                                          exe_dir(argv0)));
    if (reports.empty())
        std::cout << "no plugins found in '" << cfg.plugins_dir << "'\n";
    for (const auto& r : reports) {
        std::cout << r.plugin
                  << (r.error.empty() ? "  [ok]" : "  [error: " + r.error + "]")
                  << "\n";
    }
    return 0;
}

// ---------------------------------------------------------------------------
// Command-line surface. Scan execution is wired through the subcommand
// callback, so the CLI and the interactive shell accept exactly the same
// scan syntax.
// ---------------------------------------------------------------------------

struct ShellState {
    bool ran_scan = false;
    bool ran_plugins = false;
    bool version = false;
    bool interactive = false;
    int scan_exit = 0; // exit code from the scan (CI gate can make it 3)
};

std::unique_ptr<CLI::App> build_app(sln::ScanConfig& cfg, ShellState& state,
                                    bool interactive, const char* argv0) {
    auto app = std::make_unique<CLI::App>(
        "Sleipnir — network & web security scanner", "sleipnir");

    app->add_flag("-V,--version", state.version, "Print version and exit");
    app->add_flag("-i,--interactive", state.interactive,
                  "Run the interactive shell (default on a TTY)");

    auto scan = app->add_subcommand("scan", "Run a scan");
    scan->add_option("targets", cfg.targets, "Hosts: IP, CIDR or hostname");
    if (!interactive) scan->get_option("targets")->required();
    scan->add_option("-p,--ports", cfg.ports,
                     "Ports: 'top100', list or ranges (e.g. 80,443,1000-2000)")
        ->capture_default_str();
    scan->add_option("-t,--threads", cfg.threads, "Worker threads")
        ->capture_default_str()
        ->each([&](const std::string&) { cfg.threads_explicit = true; });
    scan->add_option("-T,--timing", cfg.timing,
                     "Timing profile 0-5 (0=paranoid, 3=normal, 5=insane); "
                     "sets delays/timeouts/thread cap and enables adaptive "
                     "backoff on filtered targets")
        ->capture_default_str();
    scan->add_option("--timeout", cfg.timeout_ms, "Per-operation timeout, ms")
        ->capture_default_str()
        ->each([&](const std::string&) { cfg.timeout_explicit = true; });
    scan->add_flag("--no-plugins", cfg.disable_plugins,
                   "Disable the Lua plugin engine");
    scan->add_option("--data", cfg.data_dir, "Data directory (probes, CVE db)")
        ->capture_default_str();
    scan->add_flag("-f,--fuzz", cfg.fuzz, "Enable robustness fuzzing");
    scan->add_option("--fuzz-max-len", cfg.fuzz_max_len,
                     "Maximum fuzz payload size")
        ->capture_default_str();
    scan->add_option("--fuzz-delay", cfg.fuzz_delay_ms,
                     "Delay between fuzz payloads, ms")
        ->capture_default_str();
    scan->add_option("--report", cfg.report_path, "Write a JSON report to FILE");
    scan->add_flag("-v,--verbose", cfg.verbose, "Verbose output");

    // TLS layer
    scan->add_flag("--no-tls", cfg.no_tls, "Disable TLS/HTTPS checks");
    scan->add_option("--tls-ports", cfg.tls_ports,
                     "Ports where a TLS handshake is attempted")
        ->capture_default_str();

    // Port-scan phase selection
    scan->add_flag("--syn", cfg.syn_scan,
                   "SYN (stealth) port scan via raw sockets (Linux, needs "
                   "root/CAP_NET_RAW; falls back to connect())");
    scan->add_flag("--udp", cfg.udp_scan,
                   "UDP service scan (DNS/NTP/SNMP/TFTP/SSDP/mDNS/memcached "
                   "probes)");
    scan->add_option("--udp-ports", cfg.udp_ports,
                     "Ports for --udp; list or ranges")
        ->capture_default_str();

    // Safety and pacing
    scan->add_flag("--safe", cfg.safe,
                   "Non-intrusive checks only (disables fuzzing)");
    scan->add_option("--delay", cfg.delay_ms,
                     "Pause between jobs per worker, ms")
        ->capture_default_str()
        ->each([&](const std::string&) { cfg.delay_explicit = true; });
    scan->add_option("--user-agent", cfg.user_agent, "HTTP User-Agent header")
        ->capture_default_str();

    // Web crawler
    scan->add_flag("--no-crawl", cfg.no_crawl, "Disable the web crawler");
    scan->add_option("--crawl-depth", cfg.crawl_depth,
                     "Crawler link depth from the start page")
        ->capture_default_str();
    scan->add_option("--crawl-max-pages", cfg.crawl_max_pages,
                     "Crawler page budget per port")
        ->capture_default_str();
    scan->add_option("--crawl-max-requests", cfg.crawl_max_requests,
                     "Active web probe budget (XSS, traversal, redirects)")
        ->capture_default_str();

    // Active CVE verification
    scan->add_flag("--no-verify", cfg.no_verify,
                   "Disable active CVE verification (Log4Shell canary, "
                   "CVE-record probes); findings stay 'potential'");

    // Authenticated scanning
    scan->add_option("--auth", cfg.auth_file,
                     "Authenticated scanning: JSON file with {method: "
                     "basic|form|cookie, user/password | url+fields+success | "
                     "cookie/cookie_file, hosts: [scope]}");

    // Directory brute-force
    scan->add_flag("--dirb", cfg.dirb,
                   "Discover hidden paths with a wordlist (built-in or "
                   "--wordlist); GET-only, reports 2xx/401/403");
    scan->add_option("--wordlist", cfg.wordlist_path,
                     "Wordlist file for --dirb (one path per line)")
        ->capture_default_str();

    // Delay-based parametric probes
    scan->add_flag("--time-probes", cfg.time_probes,
                   "Enable time-based SQLi and blind command-injection "
                   "probes (each costs seconds; never in --safe)");

    // CI gate
    scan->add_option("--fail-on", cfg.fail_on,
                     "Exit with code 3 when findings reach SEVERITY "
                     "(low|medium|high|critical)");

    scan->fallthrough();
    scan->callback([&] {
        state.scan_exit = run_scan(cfg, argv0);
        state.ran_scan = true;
    });

    // App-level so `sleipnir --list-plugins --plugins DIR` works too.
    app->add_option("--plugins", cfg.plugins_dir, "Plugins directory")
        ->capture_default_str();
    app->add_flag("--list-plugins", state.ran_plugins,
                  "Load plugins from --plugins dir, report status and exit");

    return app;
}

// ---------------------------------------------------------------------------
// Interactive shell (REPL)
// ---------------------------------------------------------------------------

std::filesystem::path history_path() {
    const char* home = std::getenv("HOME");
    if (!home || !*home) return {};
    return std::filesystem::path(home) / ".sleipnir_history";
}

void load_history(std::deque<std::string>& history) {
    auto path = history_path();
    if (path.empty()) return;
    std::ifstream in(path);
    std::string line;
    while (std::getline(in, line))
        if (!line.empty()) history.push_back(line);
    while (history.size() > 500) history.pop_front();
}

void save_history(const std::deque<std::string>& history) {
    auto path = history_path();
    if (path.empty()) return;
    std::ofstream out(path);
    for (const auto& h : history) out << h << "\n";
}

void print_repl_help() {
    std::cout
        << "Commands:\n"
           "  scan <targets...> [options]  Run a scan; same options as the\n"
           "                               CLI, e.g. scan 10.0.0.0/24 -p 80 -v\n"
           "  set                          Show current scan settings\n"
           "  plugins [DIR]                List plugins and load status\n"
           "  history                      Command history\n"
           "  clear                        Clear the screen\n"
           "  help                         This help\n"
           "  exit / quit                  Leave the shell\n"
           "\n"
           "Options given on a scan line (threads, timeout, fuzz, report,\n"
           "...) persist for subsequent scans in this session. Ctrl+C stops\n"
           "the running scan and returns to the prompt; Ctrl+D exits.\n";
}

void show_settings(const sln::ScanConfig& cfg) {
    std::cout << "ports          : " << cfg.ports << "\n"
              << "threads        : " << cfg.threads << "\n"
              << "timeout_ms     : " << cfg.timeout_ms << "\n"
              << "timing         : -T" << cfg.timing << "\n"
              << "syn_scan       : " << (cfg.syn_scan ? "on" : "off") << "\n"
              << "udp_scan       : " << (cfg.udp_scan ? "on" : "off")
              << (cfg.udp_scan ? " (" + cfg.udp_ports + ")" : "") << "\n"
              << "fuzz           : " << (cfg.fuzz ? "on" : "off") << "\n"
              << "fuzz_max_len   : " << cfg.fuzz_max_len << "\n"
              << "fuzz_delay_ms  : " << cfg.fuzz_delay_ms << "\n"
              << "verify         : " << (cfg.no_verify ? "off" : "on") << "\n"
              << "auth           : "
              << (cfg.auth.enabled()
                      ? cfg.auth.method +
                            (cfg.auth.hosts.empty()
                                 ? " (*)"
                                 : " (" +
                                       [&] {
                                           std::string s;
                                           for (const auto& h : cfg.auth.hosts)
                                               s += (s.empty() ? "" : ",") + h;
                                           return s;
                                       }() +
                                       ")")
                      : "(none)")
              << "\n"
              << "dirb           : " << (cfg.dirb ? "on" : "off")
              << (cfg.wordlist_path.empty() ? "" : " (" + cfg.wordlist_path + ")")
              << "\n"
              << "time_probes    : " << (cfg.time_probes ? "on" : "off") << "\n"
              << "plugins        : "
              << (cfg.disable_plugins ? "disabled" : cfg.plugins_dir) << "\n"
              << "data_dir       : " << cfg.data_dir << "\n"
              << "report         : "
              << (cfg.report_path.empty() ? "(none)" : cfg.report_path) << "\n"
              << "verbose        : " << (cfg.verbose ? "on" : "off") << "\n";
}

// Split a command line into argv-style tokens, honouring double and single
// quotes so `scan "host" -p 80` behaves like a shell command.
std::vector<std::string> tokenize(const std::string& line, bool& ok) {
    std::vector<std::string> out;
    ok = true;
    size_t i = 0;
    while (i < line.size()) {
        while (i < line.size() &&
               std::isspace(static_cast<unsigned char>(line[i])))
            ++i;
        if (i >= line.size()) break;
        char quote = (line[i] == '"' || line[i] == '\'') ? line[i] : '\0';
        if (quote) ++i;
        std::string tok;
        bool closed = false;
        for (; i < line.size(); ++i) {
            if (quote) {
                if (line[i] == quote) {
                    ++i;
                    closed = true;
                    break;
                }
                tok += line[i];
            } else if (std::isspace(static_cast<unsigned char>(line[i]))) {
                break;
            } else {
                tok += line[i];
            }
        }
        if (quote && !closed) {
            ok = false;
            return out;
        }
        out.push_back(std::move(tok));
    }
    return out;
}

void print_banner() {
    std::cout << C_CYAN <<
        R"(  _____ _____ _      _____ _____
 / ____|_   _| |    |_   _|_   _|
 \___ \  | | | |      | |   | |
 ____) | | | | |____ _| |_ _| |_
|_____/  |_| |______|_____|_____|
)" << C_RESET;
    std::cout << C_BOLD << "Sleipnir" << C_RESET << " v" << SLEIPNIR_VERSION
              << " — network & web security scanner\n"
              << C_DIM << "Interactive mode. Type " << C_RESET << C_BOLD
              << "help" << C_RESET << C_DIM << " for available commands, "
              << C_RESET << C_BOLD << "exit" << C_RESET << C_DIM
              << " to quit.\n\n";
}

int repl(const char* argv0) {
    print_banner();

    std::deque<std::string> history;
    load_history(history);

    sln::ScanConfig cfg;
    std::string line;

    for (;;) {
        std::cout << C_BOLD << "sleipnir" << C_RESET << C_DIM << "> " << C_RESET
                  << std::flush;
        if (!std::getline(std::cin, line)) { // EOF (Ctrl+D)
            std::cout << "\n";
            break;
        }

        size_t first = line.find_first_not_of(" \t");
        if (first == std::string::npos) continue;
        size_t last = line.find_last_not_of(" \t\r");
        line = line.substr(first, last - first + 1);
        if (line.empty()) continue;

        bool ok = false;
        std::vector<std::string> args = tokenize(line, ok);
        if (!ok) {
            std::cout << "parse error: unterminated quote\n";
            continue;
        }

        // Built-in shell commands that do not go through CLI11.
        if (args[0] == "exit" || args[0] == "quit") break;
        if (args[0] == "help" || args[0] == "?") {
            print_repl_help();
            continue;
        }
        if (args[0] == "set") {
            show_settings(cfg);
            continue;
        }
        if (args[0] == "clear") {
            std::cout << "\033[2J\033[H";
            continue;
        }
        if (args[0] == "history") {
            int n = 1;
            for (const auto& h : history) std::cout << "  " << n++ << "  " << h << "\n";
            continue;
        }
        if (args[0] == "plugins") {
            // reuse the app-level --list-plugins flag
            std::vector<std::string> pargs = {"--list-plugins"};
            pargs.insert(pargs.end(), args.begin() + 1, args.end());
            args = std::move(pargs);
        }

        history.push_back(line);
        while (history.size() > 500) history.pop_front();

        // Go through the argc/argv overload: the vector overload of this
        // vendored CLI11 build consumes its argument list from the back.
        std::vector<std::string> arg_storage = {"sleipnir"};
        arg_storage.insert(arg_storage.end(), args.begin(), args.end());
        std::vector<const char*> arg_ptrs;
        arg_ptrs.reserve(arg_storage.size());
        for (const auto& a : arg_storage) arg_ptrs.push_back(a.c_str());

        ShellState state;
        auto app = build_app(cfg, state, /*interactive=*/true, argv0);
        try {
            app->parse(static_cast<int>(arg_ptrs.size()), arg_ptrs.data());
        } catch (const CLI::ParseError& e) {
            std::cout << "error: " << e.what() << "\n" << C_DIM
                      << "(see 'help')" << C_RESET << "\n";
            continue;
        }
        if (state.version) {
            std::cout << "sleipnir " << SLEIPNIR_VERSION << "\n";
            continue;
        }
        if (state.ran_plugins) run_list_plugins(cfg, argv0);
    }

    save_history(history);
    return 0;
}

} // namespace

int main(int argc, char** argv) {
    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);

    ShellState state;
    sln::ScanConfig cfg;

    // `-i` can appear before the app is fully built; check for it manually
    // so `sleipnir -i` works even though the interactive flag is registered
    // on the (not yet parsed) app.
    for (int i = 1; i < argc; ++i) {
        std::string_view a = argv[i];
        if (a == "-i" || a == "--interactive") {
            return repl(argv[0]);
        }
    }

    // No arguments + a terminal -> interactive shell.
    if (argc == 1 && isatty(STDIN_FILENO)) return repl(argv[0]);

    auto app = build_app(cfg, state, /*interactive=*/false, argv[0]);

    try {
        app->parse(argc, argv);
    } catch (const CLI::ParseError& e) {
        return app->exit(e);
    }

    if (state.version) {
        std::cout << "sleipnir " << SLEIPNIR_VERSION << "\n";
        return 0;
    }
    if (state.ran_plugins) return run_list_plugins(cfg, argv[0]);
    if (state.ran_scan) return state.scan_exit;
    std::cout << app->help();
    return 0;
}
