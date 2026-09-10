// Active verification: turns version-matched CVE findings into proven ones.
//
// Every CVE record may carry a "check" block (data/cve_map.json): a list of
// HTTP probes (method, path, payload, confirmation markers). verify_finding()
// executes the probes over any transport and upgrades the finding from
// "potential" to "confirmed" only when the response contains a marker that a
// patched target would never produce (e.g. /etc/passwd content from a
// traversal payload). No exploitation: probes read state, they do not change
// it — POST bodies carry echo-only payloads.
//
// The same header also provides the built-in universal checks that are not
// tied to a product banner: the Log4Shell JNDI canary.
#pragma once

#include "sleipnir/http_client.hpp"
#include "sleipnir/types.hpp"

#include <functional>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace sln {

// Transport-agnostic probe executor: one HTTP request with full control over
// method, path, body, content type, extra headers and the User-Agent value.
// Template adapters below wrap TcpClient/TlsClient; unit tests pass doubles.
using ProbeFetcher = std::function<std::optional<HttpResponse>(
    const std::string& method, const std::string& path,
    const std::string& body, const std::string& content_type,
    const std::vector<std::pair<std::string, std::string>>& extra_headers,
    const std::string& user_agent)>;

// Wraps any transport (TcpClient, TlsClient, test double) into a ProbeFetcher.
// The stream is captured by reference and must outlive the fetcher; every
// other parameter is captured by value.
template <typename Stream>
ProbeFetcher probe_fetcher(Stream& stream, const std::string& host,
                           uint16_t port, int timeout_ms,
                           const std::string& user_agent) {
    return [&stream, host, port, timeout_ms, user_agent](
               const std::string& method, const std::string& path,
               const std::string& body, const std::string& content_type,
               const std::vector<std::pair<std::string, std::string>>& extra,
               const std::string& ua) -> std::optional<HttpResponse> {
        HttpOptions opts;
        opts.headers = extra;
        opts.body = body;
        opts.content_type = content_type;
        opts.user_agent = ua;
        return http_request_ex(stream, method, host, port, path, timeout_ms,
                               user_agent, opts);
    };
}

// Random hex token distinguishing canary payloads per scan (thread-safe).
std::string canary_token();

// Executes a CVE record's active check: sends probes until one response
// contains a confirmation marker (and none of the not_markers). POST probes
// are skipped when allow_post is false (--safe). Returns the evidence string
// ("GET /path -> 200, marker ... at offset N: ...snippet...") on success.
std::optional<std::string> run_vuln_check(const ProbeFetcher& fetch,
                                          const VulnCheck& check,
                                          bool allow_post);

// Runs the check attached to a CVE finding; sets verified/confidence and
// appends the probe evidence in place. Returns true on confirmation.
bool verify_finding(const ProbeFetcher& fetch, Finding& f, bool allow_post);

// Log4Shell (CVE-2021-44228): injects a JNDI canary into the request headers
// (User-Agent, Referer, X-Api-Version). Confirmed only when the response
// references the canary host without the literal ${jndi payload — a raw echo
// proves nothing, but a lookup failure for the unique host proves the target
// evaluated the expression. Returns the verified finding or nullopt.
std::optional<Finding> check_log4shell(const ProbeFetcher& fetch,
                                       const std::string& host, uint16_t port,
                                       const std::string& token);

} // namespace sln
