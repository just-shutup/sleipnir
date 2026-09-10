// Sleipnir — core data types shared across all subsystems.
#pragma once

#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace sln {

enum class Severity { Info, Low, Medium, High, Critical };

const char* severity_name(Severity s);       // "info" ... "critical"
int severity_rank(Severity s);               // ordering / coloring
Severity severity_from_string(const std::string& s); // unknown -> Info

enum class PortStatus { Open, Closed, Filtered };

const char* status_name(PortStatus s); // "open" / "closed" / "filtered"

// Timing profile (-T0..-T5, nmap-style): base pacing, timeouts and worker
// caps. The engine additionally adapts the delay at runtime (backoff when
// connects hit the timeout, recovery when they complete fast).
struct TimingProfile {
    int delay_ms;         // base per-worker pause between jobs
    int timeout_ms;       // per-operation timeout
    int max_threads;      // worker pool cap
    int adaptive_ceiling; // upper bound for the adaptive delay
};

// t: 0 (paranoid) .. 5 (insane); values outside 0..5 clamp to 3.
TimingProfile timing_profile(int t);

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

// One active verification probe of a CVE record's "check" block: a single
// HTTP request whose response is searched for confirmation markers. The
// payloads only make a vulnerable target return the markers, so a hit is
// proof, not a version suspicion.
struct VulnCheckProbe {
    std::string method; // empty -> GET (or POST when a body is present)
    std::string path;
    std::string body;         // non-empty -> sent as request body
    std::string content_type; // default "application/x-www-form-urlencoded" with a body
    std::vector<std::pair<std::string, std::string>> headers; // extra headers
    std::vector<std::string> markers;     // confirmation: any-of, case-sensitive
    std::vector<std::string> not_markers; // must ALL be absent (anti-reflection)
};

// Data-driven active check attached to a CVE record (cve_map.json "check").
// The database stays plain data: new verifications need no recompilation.
struct VulnCheck {
    std::vector<VulnCheckProbe> probes;

    // Script-based check (plugins/checks/<file>): a Lua verify(ctx) function
    // returning {verified=bool, evidence=string}. Covers what HTTP probes
    // cannot express: binary protocols (Redis RESP), chunked request
    // framing (Jenkins CLI), multi-request correlation.
    std::string script;
    // false -> the probe changes state (e.g. a POST) and is skipped in
    // --safe mode regardless of transport.
    bool safe = true;

    bool empty() const { return script.empty() && probes.empty(); }
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
    // Verification status. verified=true means the scanner actively
    // demonstrated the issue (a marker only a vulnerable target produces);
    // false = signature/version-based suspicion. confidence: "confirmed" or
    // "potential" (empty = plain observation, neither).
    bool verified = false;
    std::string confidence;
    // Active check to run against the endpoint, when the CVE record has one.
    std::shared_ptr<const VulnCheck> check;
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
    int timing = 3;            // -T0..-T5 profile (3 = default)
    std::string user_agent = "Sleipnir/0.1 (vulnerability scanner)";

    // SYN (stealth) scan for the port phase; requires root/CAP_NET_RAW on
    // Linux and falls back to the connect scan otherwise.
    bool syn_scan = false;

    // UDP service scan (opt-in): probe-driven with per-port payloads.
    bool udp_scan = false;
    std::string udp_ports =
        "53,69,123,137,161,162,500,514,4500,1900,5353,11211";

    // Web crawler and active application probes.
    bool no_crawl = false;
    int crawl_depth = 3;         // link depth from the start page
    int crawl_max_pages = 40;    // page fetch budget per HTTP port
    int crawl_max_requests = 120; // active probe budget (XSS, traversal, ...)

    // Active CVE verification (--no-verify disables): each CVE record with a
    // "check" block gets its probes executed and the finding upgraded from
    // potential to confirmed when a marker returns.
    bool no_verify = false;

    // CI gate (--fail-on SEVERITY): empty -> disabled.
    std::string fail_on;

    // True when the user passed the option explicitly (timing profiles only
    // fill unset values).
    bool threads_explicit = false;
    bool timeout_explicit = false;
    bool delay_explicit = false;
};

} // namespace sln
