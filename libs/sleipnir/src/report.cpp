#include "sleipnir/report.hpp"

#ifndef SLEIPNIR_VERSION
#define SLEIPNIR_VERSION "dev"
#endif

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cctype>
#include <ctime>
#include <fstream>
#include <iostream>
#include <set>
#include <sstream>

namespace sln {

namespace {

using json = nlohmann::json;

// ANSI colors (disabled automatically when not a TTY — caller responsibility)
constexpr const char* C_RESET = "\033[0m";
constexpr const char* C_BOLD = "\033[1m";
constexpr const char* C_DIM = "\033[2m";
constexpr const char* C_GREEN = "\033[32m";
constexpr const char* C_YELLOW = "\033[33m";
constexpr const char* C_RED = "\033[31m";
constexpr const char* C_BRIGHT_RED = "\033[91m";
constexpr const char* C_CYAN = "\033[36m";

const char* severity_color(Severity s) {
    switch (s) {
    case Severity::Info: return C_CYAN;
    case Severity::Low: return C_GREEN;
    case Severity::Medium: return C_YELLOW;
    case Severity::High: return C_RED;
    case Severity::Critical: return C_BRIGHT_RED;
    }
    return C_RESET;
}

std::string one_line(std::string s) {
    for (char& c : s) {
        if (c == '\n' || c == '\r' || c == '\t') c = ' ';
    }
    return s;
}

json finding_to_json(const Finding& f) {
    json j;
    j["host"] = f.host;
    j["port"] = f.port;
    j["title"] = f.title;
    j["severity"] = severity_name(f.severity);
    j["description"] = f.description;
    if (!f.evidence.empty()) j["evidence"] = f.evidence;
    if (!f.cve.empty()) j["cve"] = f.cve;
    j["source"] = f.source;
    return j;
}

} // namespace

void print_console_report(const ResultCollector& results,
                          const ScanConfig& cfg, double elapsed_seconds) {
    auto ports = results.ports();
    auto findings = results.findings();
    const auto& stats = results.stats();

    std::cout << "\n" << C_BOLD << "=========== Sleipnir scan report ==========="
              << C_RESET << "\n";
    std::cout << "hosts scanned : " << stats.hosts << "\n"
              << "jobs done     : " << stats.jobs_done.load() << "/"
              << stats.jobs_total << "\n"
              << "open ports    : " << stats.open_ports.load() << "\n"
              << "findings      : " << findings.size() << "\n"
              << C_DIM << "elapsed       : " << elapsed_seconds << "s"
              << C_RESET << "\n\n";

    std::sort(ports.begin(), ports.end(), [](const PortResult& a, const PortResult& b) {
        if (a.host != b.host) return a.host < b.host;
        return a.port < b.port;
    });
    for (const auto& p : ports) {
        std::cout << C_GREEN << "  " << p.host << ":" << p.port << C_RESET
                  << "  " << p.service;
        if (!p.product.empty())
            std::cout << " " << C_DIM << p.product
                      << (p.version.empty() ? "" : "/" + p.version) << C_RESET;
        if (p.tls)
            std::cout << "  " << C_DIM << "[" << p.tls->protocol << "]"
                      << C_RESET;
        std::cout << "\n";
    }
    if (!ports.empty()) std::cout << "\n";

    std::sort(findings.begin(), findings.end(),
              [](const Finding& a, const Finding& b) {
                  if (severity_rank(a.severity) != severity_rank(b.severity))
                      return severity_rank(a.severity) > severity_rank(b.severity);
                  if (a.host != b.host) return a.host < b.host;
                  return a.port < b.port;
              });
    if (!findings.empty()) {
        std::cout << C_BOLD << "Findings:" << C_RESET << "\n";
        for (const auto& f : findings) {
            std::cout << "  " << severity_color(f.severity) << "[" << C_BOLD
                      << severity_name(f.severity) << C_RESET
                      << severity_color(f.severity) << "]" << C_RESET << " "
                      << f.title << "  " << C_DIM << "(" << f.host << ":"
                      << f.port << ", " << f.source << ")" << C_RESET << "\n";
            if (!f.cve.empty())
                std::cout << "         " << f.cve << "\n";
            if (!f.evidence.empty())
                std::cout << "         " << C_DIM << one_line(f.evidence)
                          << C_RESET << "\n";
        }
    }

    if (cfg.report_path.empty())
        std::cout << C_DIM << "\n(re-run with --report FILE to save a JSON "
                           "report)" << C_RESET << "\n";
    std::cout << C_BOLD << "=============================================" << C_RESET
              << "\n";
}

bool write_json_report(const std::string& path,
                       const std::vector<PortResult>& ports,
                       const std::vector<Finding>& findings,
                       const ScanConfig& cfg, double elapsed_seconds) {
    json report;
    report["meta"] = {
        {"tool", "sleipnir"},
        {"version", SLEIPNIR_VERSION},
        {"elapsed_seconds", elapsed_seconds},
        {"config",
         {{"ports", cfg.ports},
          {"threads", cfg.threads},
          {"timeout_ms", cfg.timeout_ms},
          {"fuzz", cfg.fuzz},
          {"plugins_disabled", cfg.disable_plugins}}}};
    std::set<std::string> unique_hosts;
    for (const auto& p : ports) unique_hosts.insert(p.host);
    report["stats"] = {
        {"hosts", unique_hosts.size()},
        {"open_ports", ports.size()},
        {"findings", findings.size()}};

    json jports = json::array();
    for (const auto& p : ports) {
        json j;
        j["host"] = p.host;
        j["port"] = p.port;
        j["status"] = "open";
        j["service"] = p.service;
        j["product"] = p.product;
        j["version"] = p.version;
        j["banner"] = p.banner;
        if (p.http_status) {
            j["http"] = {{"status", p.http_status}, {"headers", p.http_headers}};
        }
        if (p.tls) {
            j["tls"] = {
                {"protocol", p.tls->protocol},
                {"cipher", p.tls->cipher},
                {"subject", p.tls->subject},
                {"issuer", p.tls->issuer},
                {"not_before", p.tls->not_before},
                {"not_after", p.tls->not_after},
                {"self_signed", p.tls->self_signed},
                {"chain_trusted", p.tls->chain_trusted},
                {"hostname_match", p.tls->hostname_match}};
        }
        jports.push_back(std::move(j));
    }
    report["targets"] = std::move(jports);

    json jfindings = json::array();
    for (const auto& f : findings) jfindings.push_back(finding_to_json(f));
    report["findings"] = std::move(jfindings);

    std::ofstream out(path);
    if (!out) return false;
    out << report.dump(2) << "\n";
    return static_cast<bool>(out);
}

// ---------------------------------------------------------------------------
// HTML report
// ---------------------------------------------------------------------------

namespace {

std::string html_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        switch (c) {
        case '<': out += "&lt;"; break;
        case '>': out += "&gt;"; break;
        case '&': out += "&amp;"; break;
        case '"': out += "&quot;"; break;
        default: out += c;
        }
    }
    return out;
}

const char* severity_css_class(Severity s) {
    switch (s) {
    case Severity::Info: return "info";
    case Severity::Low: return "low";
    case Severity::Medium: return "medium";
    case Severity::High: return "high";
    case Severity::Critical: return "critical";
    }
    return "info";
}

std::string utc_timestamp() {
    std::time_t t = std::time(nullptr);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%SZ",
                  std::gmtime(&t));
    return buf;
}

} // namespace

bool write_html_report(const std::string& path,
                       const std::vector<PortResult>& ports,
                       const std::vector<Finding>& findings,
                       const ScanConfig& cfg, double elapsed_seconds) {
    // sort a local copy: severity first, then host/port
    std::vector<Finding> sorted = findings;
    std::sort(sorted.begin(), sorted.end(),
              [](const Finding& a, const Finding& b) {
                  if (severity_rank(a.severity) != severity_rank(b.severity))
                      return severity_rank(a.severity) > severity_rank(b.severity);
                  if (a.host != b.host) return a.host < b.host;
                  return a.port < b.port;
              });

    std::map<Severity, int> by_sev;
    for (const auto& f : sorted) ++by_sev[f.severity];

    std::set<std::string> unique_hosts;
    for (const auto& p : ports) unique_hosts.insert(p.host);

    std::ostringstream html;
    html << "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n"
         << "<title>Sleipnir scan report</title>\n<style>\n"
            "body{font-family:'Segoe UI',system-ui,sans-serif;margin:0;background:#f4f5f7;color:#1c2733}\n"
            "header{background:#102a43;color:#fff;padding:28px 40px}\n"
            "header h1{margin:0 0 4px;font-size:22px}\n"
            "header .meta{color:#9fb3c8;font-size:13px}\n"
            ".cards{display:flex;gap:16px;padding:24px 40px;flex-wrap:wrap}\n"
            ".card{background:#fff;border-radius:8px;padding:16px 24px;min-width:130px;box-shadow:0 1px 3px rgba(0,0,0,.12)}\n"
            ".card .n{font-size:26px;font-weight:600}\n"
            ".card .l{font-size:12px;color:#627d98;text-transform:uppercase;letter-spacing:.05em}\n"
            "section{background:#fff;border-radius:8px;margin:0 40px 24px;padding:20px 24px;box-shadow:0 1px 3px rgba(0,0,0,.12)}\n"
            "h2{font-size:16px;margin:0 0 12px;color:#243b53}\n"
            "table{border-collapse:collapse;width:100%;font-size:13px}\n"
            "th{text-align:left;color:#627d98;font-weight:600;border-bottom:2px solid #d9e2ec;padding:8px 10px}\n"
            "td{border-bottom:1px solid #f0f4f8;padding:8px 10px;vertical-align:top}\n"
            ".badge{display:inline-block;padding:2px 10px;border-radius:10px;font-size:11px;font-weight:600;color:#fff;text-transform:uppercase}\n"
            ".badge.info{background:#0ea5e9}.badge.low{background:#22c55e}.badge.medium{background:#f59e0b}\n"
            ".badge.high{background:#ef4444}.badge.critical{background:#7f1d1d}\n"
            ".evi{color:#64748b;font-size:12px;margin-top:2px;word-break:break-all}\n"
            "footer{color:#829ab1;font-size:12px;padding:0 40px 28px}\n"
            "</style>\n</head>\n<body>\n";

    html << "<header><h1>Sleipnir scan report</h1><div class=\"meta\">"
         << html_escape(SLEIPNIR_VERSION) << " &middot; generated "
         << utc_timestamp() << " &middot; elapsed " << elapsed_seconds
         << "s</div></header>\n";

    auto card = [&](int n, const char* label) {
        html << "<div class=\"card\"><div class=\"n\">" << n
             << "</div><div class=\"l\">" << label << "</div></div>\n";
    };
    html << "<div class=\"cards\">\n";
    card(static_cast<int>(unique_hosts.size()), "Hosts");
    card(static_cast<int>(ports.size()), "Open ports");
    card(static_cast<int>(sorted.size()), "Findings");
    card(by_sev[Severity::Critical], "Critical");
    card(by_sev[Severity::High], "High");
    card(by_sev[Severity::Medium], "Medium");
    html << "</div>\n";

    // findings
    html << "<section><h2>Findings</h2>\n";
    if (sorted.empty()) {
        html << "<p>No findings.</p>\n";
    } else {
        html << "<table><tr><th>Severity</th><th>Location</th><th>Title"
             << "</th><th>Source</th><th>Description</th></tr>\n";
        for (const auto& f : sorted) {
            html << "<tr><td><span class=\"badge " << severity_css_class(f.severity)
                 << "\">" << severity_name(f.severity) << "</span></td>"
                 << "<td>" << html_escape(f.host) << ":" << f.port << "</td>"
                 << "<td>" << html_escape(f.title);
            if (!f.cve.empty())
                html << "<div class=\"evi\">" << html_escape(f.cve) << "</div>";
            html << "</td>"
                 << "<td>" << html_escape(f.source) << "</td>"
                 << "<td>" << html_escape(f.description);
            if (!f.evidence.empty())
                html << "<div class=\"evi\">"
                     << html_escape(one_line(f.evidence).substr(0, 300))
                     << "</div>";
            html << "</td></tr>\n";
        }
        html << "</table>\n";
    }
    html << "</section>\n";

    // endpoints
    html << "<section><h2>Endpoints</h2>\n<table><tr><th>Endpoint</th>"
         << "<th>Service</th><th>Product</th><th>TLS</th><th>HTTP</th></tr>\n";
    std::vector<PortResult> sorted_ports = ports;
    std::sort(sorted_ports.begin(), sorted_ports.end(),
              [](const PortResult& a, const PortResult& b) {
                  if (a.host != b.host) return a.host < b.host;
                  return a.port < b.port;
              });
    for (const auto& p : sorted_ports) {
        html << "<tr><td>" << html_escape(p.host) << ":" << p.port << "</td><td>"
             << html_escape(p.service) << "</td><td>"
             << html_escape(p.product + (p.version.empty() ? "" : " " + p.version))
             << "</td><td>";
        if (p.tls)
            html << html_escape(p.tls->protocol) << ", "
                 << html_escape(p.tls->cipher)
                 << "<div class=\"evi\">cert until "
                 << html_escape(p.tls->not_after) << "</div>";
        html << "</td><td>";
        if (p.http_status) html << p.http_status;
        html << "</td></tr>\n";
    }
    html << "</table>\n</section>\n";

    html << "<footer>Configuration: ports " << html_escape(cfg.ports)
         << ", threads " << cfg.threads << ", timeout " << cfg.timeout_ms
         << "ms, fuzz " << (cfg.fuzz ? "on" : "off") << ", safe mode "
         << (cfg.safe ? "on" : "off") << ", TLS checks "
         << (cfg.no_tls ? "off" : "on")
         << ". Generated by an authorized vulnerability assessment; "
            "interpret findings in context.</footer>\n";

    html << "</body>\n</html>\n";

    std::ofstream out(path);
    if (!out) return false;
    out << html.str();
    return static_cast<bool>(out);
}

bool write_report(const std::string& path,
                  const std::vector<PortResult>& ports,
                  const std::vector<Finding>& findings,
                  const ScanConfig& cfg, double elapsed_seconds) {
    std::string ext;
    size_t dot = path.rfind('.');
    if (dot != std::string::npos) {
        ext = path.substr(dot + 1);
        for (char& c : ext) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    if (ext == "html" || ext == "htm")
        return write_html_report(path, ports, findings, cfg, elapsed_seconds);
    return write_json_report(path, ports, findings, cfg, elapsed_seconds);
}

} // namespace sln
