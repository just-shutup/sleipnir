#include "sleipnir/verify.hpp"

#include <cctype>
#include <random>

namespace sln {

namespace {

std::string ascii_lower(std::string s) {
    for (char& c : s)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

std::string one_line(std::string s) {
    for (char& c : s)
        if (c == '\n' || c == '\r' || c == '\t') c = ' ';
    return s;
}

// Snippet around the first marker hit, bounded to +-60 characters.
std::string snippet_around(const std::string& body, size_t pos) {
    size_t begin = pos > 60 ? pos - 60 : 0;
    std::string s = one_line(body.substr(begin, 180));
    return s;
}

} // namespace

std::string canary_token() {
    static thread_local std::mt19937_64 rng{std::random_device{}()};
    static const char* hex = "0123456789abcdef";
    std::string s;
    uint64_t v = rng();
    for (int i = 0; i < 12; ++i) {
        s += hex[v & 0xf];
        v >>= 4;
    }
    return s;
}

std::optional<std::string> run_vuln_check(const ProbeFetcher& fetch,
                                          const VulnCheck& check,
                                          bool allow_post) {
    for (const auto& probe : check.probes) {
        std::string method = probe.method.empty() ? "GET" : probe.method;
        std::string body = probe.body;
        if (!body.empty() && probe.method.empty()) method = "POST";
        // --safe policy: never send state-changing requests, whatever way
        // the probe declares them (body or an explicit unsafe method).
        if (!allow_post &&
            (method == "POST" || method == "PUT" || method == "PATCH" ||
             method == "DELETE"))
            continue;

        auto resp = fetch(method, probe.path, body, probe.content_type,
                          probe.headers, "");
        if (!resp) continue;

        // not_markers: raw reflection of the payload is not evidence (e.g. an
        // app echoing the request); they must all be absent.
        bool poisoned = false;
        for (const auto& nm : probe.not_markers)
            if (resp->body.find(nm) != std::string::npos) {
                poisoned = true;
                break;
            }
        if (poisoned) continue;

        for (const auto& marker : probe.markers) {
            size_t pos = resp->body.find(marker);
            if (pos == std::string::npos) continue;
            std::string evidence =
                method + " " + probe.path + " -> " +
                std::to_string(resp->status) + ", marker '" + marker +
                "' in response: ..." + snippet_around(resp->body, pos) + "...";
            return evidence;
        }
    }
    return std::nullopt;
}

bool verify_finding(const ProbeFetcher& fetch, Finding& f, bool allow_post) {
    if (!f.check || f.check->empty()) return false;
    auto evidence = run_vuln_check(fetch, *f.check, allow_post);
    if (!evidence) return false;
    f.verified = true;
    f.confidence = "confirmed";
    if (!evidence->empty())
        f.evidence = f.evidence.empty() ? *evidence : f.evidence + "; " + *evidence;
    return true;
}

std::optional<Finding> check_log4shell(const ProbeFetcher& fetch,
                                       const std::string& host, uint16_t port,
                                       const std::string& token) {
    const std::string canary_host = "sln-l4s-" + token + ".invalid";
    const std::string payload = "${jndi:dns://" + canary_host + "/s}";
    std::vector<std::pair<std::string, std::string>> headers = {
        {"X-Api-Version", payload},
        {"Referer", payload},
    };
    auto resp = fetch("GET", "/", "", "", headers, payload);
    if (!resp) return std::nullopt;

    // Evaluation proof: the canary host shows up (the lookup failed and the
    // failure text names it) but the literal expression does not — a plain
    // echo would carry both. Strict on purpose: never report without proof.
    if (resp->body.find(canary_host) == std::string::npos) return std::nullopt;
    if (ascii_lower(resp->body).find("${jndi") != std::string::npos)
        return std::nullopt;

    Finding f;
    f.host = host;
    f.port = port;
    f.title = "Log4Shell: JNDI lookup of canary confirmed (CVE-2021-44228)";
    f.severity = Severity::Critical;
    f.description =
        "A JNDI expression injected into request headers was evaluated by "
        "the target: it attempted to resolve a unique canary hostname and "
        "reported the lookup failure. Log4j versions 2.x below 2.15 allow "
        "this to escalate to remote code execution. Upgrade log4j to 2.17.1 "
        "or later / apply vendor mitigations.";
    size_t pos = resp->body.find(canary_host);
    f.evidence = "GET / with ${jndi:dns://" + canary_host + "/s} in headers -> "
                 "evaluated, response: ..." + snippet_around(resp->body, pos) + "...";
    f.cve = "CVE-2021-44228";
    f.source = "verify";
    f.verified = true;
    f.confidence = "confirmed";
    return f;
}

} // namespace sln
