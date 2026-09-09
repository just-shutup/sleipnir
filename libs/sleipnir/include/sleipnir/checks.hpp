// Built-in (C++) misconfiguration checks. HTTP-oriented checks use the
// http_get helper; anything a user might want to tune is better expressed as
// a Lua plugin (see plugins/), while these stay compiled in for speed.
//
// All HTTP-facing checks are templates over the transport (TcpClient or
// TlsClient), so the same rules apply to plain and TLS endpoints; their
// bodies therefore live in this header.
#pragma once

#include "sleipnir/http_client.hpp"
#include "sleipnir/results.hpp"

#include <string>
#include <vector>

namespace sln {

struct HttpCheckResult {
    std::vector<Finding> findings;
    std::string server_product;  // from Server header, for CVE matching
    std::string server_version;
};

// Checks the response of the site root: server version disclosure,
// directory listing, missing security headers, CORS wildcard, cookie flags.
HttpCheckResult check_root_response(const std::string& host, uint16_t port,
                                    const HttpResponse& resp);

// Probes a list of sensitive paths and reports the exposed ones.
template <typename Stream>
std::vector<Finding> check_sensitive_paths(Stream& stream,
                                           const std::string& host,
                                           uint16_t port, int timeout_ms,
                                           const std::string& user_agent);

// HTTP method hygiene: TRACE (cross-site tracing), verbose OPTIONS.
template <typename Stream>
std::vector<Finding> check_http_methods(Stream& stream,
                                        const std::string& host,
                                        uint16_t port, int timeout_ms,
                                        const std::string& user_agent);

namespace detail {

inline Finding make_finding(const std::string& host, uint16_t port,
                            const std::string& title, Severity sev,
                            const std::string& description,
                            const std::string& evidence) {
    Finding f;
    f.host = host;
    f.port = port;
    f.title = title;
    f.severity = sev;
    f.description = description;
    f.evidence = evidence;
    f.source = "builtin";
    return f;
}

} // namespace detail

template <typename Stream>
std::vector<Finding> check_sensitive_paths(Stream& stream,
                                           const std::string& host,
                                           uint16_t port, int timeout_ms,
                                           const std::string& user_agent) {
    struct PathCheck {
        const char* path;
        const char* title;
        Severity sev;
        const char* description;
        // body must contain this marker (case-sensitive) to be reported;
        // empty marker -> any 200 response counts
        const char* body_marker;
    };
    static const PathCheck paths[] = {
        {"/.git/HEAD", "Exposed .git directory", Severity::High,
         "The repository metadata is served over HTTP; source code can be "
         "reconstructed with standard tools.",
         "ref: refs/"},
        {"/.svn/entries", "Exposed .svn directory", Severity::Medium,
         "Subversion metadata is served over HTTP; the working copy layout "
         "and file list can be reconstructed.",
         nullptr},
        {"/.env", "Exposed .env file", Severity::High,
         "The application environment file (often containing credentials) is "
         "publicly downloadable.",
         "="},
        {"/.aws/credentials", "Exposed AWS credentials file", Severity::High,
         "An AWS credentials file with access keys is publicly downloadable; "
         "the keys grant access to the linked cloud account.",
         "[default]"},
        {"/.htaccess", "Exposed .htaccess", Severity::Low,
         "The Apache access-control file is downloadable; it reveals "
         "rewrite and authorization rules useful for further attacks.",
         nullptr},
        {"/server-status", "Apache server-status exposed", Severity::Medium,
         "The mod_status status page is available without authentication and "
         "reveals requests, IPs and configuration.",
         "Server Status"},
        {"/phpinfo.php", "phpinfo() page exposed", Severity::Medium,
         "A phpinfo() script is reachable without authentication; it reveals "
         "paths, extensions, environment variables and often secrets.",
         "phpinfo"},
        {"/phpmyadmin/", "phpMyAdmin exposed", Severity::Low,
         "A phpMyAdmin login page is reachable; expect brute-force attempts.",
         "phpMyAdmin"},
        {"/robots.txt", "robots.txt discloses private paths", Severity::Info,
         "robots.txt enumerates directories the site prefers to keep out of "
         "search engines; these paths are a useful target list. Informational.",
         "Disallow"},
    };

    std::vector<Finding> out;
    for (const auto& pc : paths) {
        auto resp = http_get(stream, host, port, pc.path, timeout_ms,
                             user_agent);
        if (!stream.is_open()) break; // server gone / connection consumed
        if (!resp || resp->status != 200) continue;
        if (pc.body_marker &&
            resp->body.find(pc.body_marker) == std::string::npos)
            continue;
        Finding f = detail::make_finding(host, port, pc.title, pc.sev,
                                         pc.description, "");
        f.evidence = "GET " + std::string(pc.path) + " -> " +
                     std::to_string(resp->status) + ", " +
                     std::to_string(resp->body.size()) + " bytes";
        out.push_back(std::move(f));
    }
    return out;
}

template <typename Stream>
std::vector<Finding> check_http_methods(Stream& stream,
                                        const std::string& host,
                                        uint16_t port, int timeout_ms,
                                        const std::string& user_agent) {
    std::vector<Finding> out;

    // TRACE: the request line/body is echoed by the server when enabled —
    // the classic Cross-Site Tracing (XST) vector against HttpOnly cookies.
    if (auto resp = http_request(stream, "TRACE", host, port, "/", timeout_ms,
                                 user_agent);
        resp && resp->status == 200 &&
        (resp->body.find("TRACE") != std::string::npos ||
         (resp->headers.count("content-type") &&
          resp->headers["content-type"].find("message/http") !=
              std::string::npos))) {
        out.push_back(detail::make_finding(
            host, port, "HTTP TRACE method enabled", Severity::Medium,
            "The server echoes TRACE requests. Combined with a cross-site "
            "scripting flaw this exposes cookies even when the HttpOnly "
            "flag is set (Cross-Site Tracing).",
            "TRACE / -> " + std::to_string(resp->status) + ", echo " +
                std::to_string(resp->body.size()) + " bytes"));
    }

    // OPTIONS: the Allow header is useful reconnaissance, informational only.
    if (auto resp = http_request(stream, "OPTIONS", host, port, "/", timeout_ms,
                                 user_agent);
        resp && resp->status < 500) {
        if (auto allow = resp->header("allow")) {
            out.push_back(detail::make_finding(
                host, port, "HTTP methods enumerated via OPTIONS",
                Severity::Info,
                "The server publishes the supported method set in the Allow "
                "header. Informational.",
                "Allow: " + *allow));
        }
    }
    return out;
}

// Convenience wrappers for plain-TCP call sites (engine, plugins, tests).
inline std::vector<Finding> check_sensitive_paths(
    TcpClient& client, const std::string& host, uint16_t port, int timeout_ms,
    const std::string& user_agent = "Sleipnir/0.1 (vulnerability scanner)") {
    return check_sensitive_paths<TcpClient>(client, host, port, timeout_ms,
                                            user_agent);
}

inline std::vector<Finding> check_http_methods(
    TcpClient& client, const std::string& host, uint16_t port, int timeout_ms,
    const std::string& user_agent = "Sleipnir/0.1 (vulnerability scanner)") {
    return check_http_methods<TcpClient>(client, host, port, timeout_ms,
                                         user_agent);
}

} // namespace sln
