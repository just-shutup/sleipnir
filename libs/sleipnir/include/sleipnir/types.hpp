// Sleipnir — core data types shared across all subsystems.
#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace sln {

enum class Severity { Info, Low, Medium, High, Critical };

const char* severity_name(Severity s);       // "info" ... "critical"
int severity_rank(Severity s);               // ordering / coloring
Severity severity_from_string(const std::string& s); // unknown -> Info

enum class PortStatus { Open, Closed, Filtered };

// Report-facing TLS facts (handshake + certificate) for a single endpoint.
struct TlsInfo {
    std::string protocol;    // negotiated, e.g. "TLSv1.2"
    std::string cipher;
    std::string subject;
    std::string issuer;
    std::string not_before;  // "YYYY-MM-DD HH:MM:SSZ"
    std::string not_after;
    bool self_signed = false;
    bool chain_trusted = true;
    bool hostname_match = true;
};

// Result of probe-based service identification.
struct ServiceInfo {
    std::string service;
    std::string product;
    std::string version;
    std::string banner;
};

// What we learned about a single (host, port).
struct PortResult {
    std::string host;
    uint16_t port = 0;
    PortStatus status = PortStatus::Closed;
    std::string service;   // "ssh", "http", "https", ... or "unknown"
    std::string product;   // "OpenSSH", "Apache", ...
    std::string version;   // "8.4p1"
    std::string banner;    // raw bytes collected from the service
    int http_status = 0;   // 0 if not HTTP
    std::map<std::string, std::string> http_headers; // keys lowercased
    std::optional<TlsInfo> tls; // present for endpoints inspected over TLS
};

struct Finding {
    std::string host;
    uint16_t port = 0;
    std::string title;
    Severity severity = Severity::Info;
    std::string description;
    std::string evidence;   // snippet proving the issue
    std::string cve;        // empty when not CVE-backed
    std::string source;     // "cve-db" | "builtin" | "tls" | "plugin:<name>" | "fuzz"
};

struct ScanConfig {
    std::vector<std::string> targets;
    std::string ports = "top100";
    int threads = 32;
    int timeout_ms = 2500;
    std::string data_dir = "data";
    std::string plugins_dir = "plugins";
    bool disable_plugins = false;
    bool fuzz = false;
    int fuzz_max_len = 8192;
    int fuzz_delay_ms = 20;
    std::string report_path;   // empty -> no JSON report
    bool verbose = false;

    // TLS: ports where a TLS handshake is attempted when service probes
    // cannot identify the endpoint; --no-tls disables the whole layer.
    bool no_tls = false;
    std::string tls_ports = "443,465,563,636,989,990,992,993,995,8443,9443";

    // Safety and pacing controls.
    bool safe = false;         // non-intrusive checks only (fuzzing off)
    int delay_ms = 0;          // pause between jobs per worker
    std::string user_agent = "Sleipnir/0.1 (vulnerability scanner)";

    // Web crawler and active application probes.
    bool no_crawl = false;
    int crawl_depth = 3;         // link depth from the start page
    int crawl_max_pages = 40;    // page fetch budget per HTTP port
    int crawl_max_requests = 120; // active probe budget (XSS, traversal, ...)

    // CI gate (--fail-on SEVERITY): empty -> disabled.
    std::string fail_on;
};

} // namespace sln
