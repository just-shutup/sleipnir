// Directory brute-force (--dirb): wordlist-driven discovery of paths that
// the site serves but nothing links to (admin panels, backups, config
// leftovers). GET-only, so it is read-only by construction; 2xx/401/403
// responses are reported, soft-404 patterns (catch-all pages) filtered by
// a random-path baseline.
#pragma once

#include "sleipnir/http_client.hpp"
#include "sleipnir/types.hpp"
#include "sleipnir/verify.hpp" // canary_token

#include <set>
#include <string>
#include <vector>

namespace sln {

struct DirbConfig {
    std::vector<std::string> words; // path segments, e.g. "admin", ".git"
    int max_requests = 0;           // 0 -> words.size()
};

// The built-in wordlist (~90 common paths) used when no --wordlist is given.
const std::vector<std::string>& builtin_wordlist();

// Loads a wordlist file (one path per line, '#' comments, empty lines
// skipped). Returns the built-in list when the file cannot be read.
std::vector<std::string> load_wordlist(const std::string& path);

// A served path is an observation, never a guess — findings carry
// verified=true; soft-404 catch-all pages are filtered by a random-path
// baseline.
namespace detail {
inline bool dirb_soft_404(const HttpResponse& word_resp, int base_status,
                          size_t base_len, const std::string& base_body) {
    if (word_resp.status != base_status) return false;
    size_t len = word_resp.body.size();
    if (base_len < 64 && len < 64) return word_resp.body == base_body;
    return len + 8 >= base_len && len <= base_len + 8;
}
} // namespace detail

template <typename Stream>
std::vector<Finding> run_dirb(Stream& stream, const std::string& host,
                              uint16_t port, int timeout_ms,
                              const std::string& user_agent,
                              const DirbConfig& cfg,
                              const std::set<std::string>& known) {
    std::vector<Finding> out;
    if (cfg.words.empty()) return out;

    auto add = [&](const std::string& title, Severity sev,
                   const std::string& description,
                   const std::string& evidence) {
        Finding f;
        f.host = host;
        f.port = port;
        f.title = title;
        f.severity = sev;
        f.description = description;
        f.evidence = evidence;
        f.source = "dirb";
        f.verified = true; // a served path is directly observed
        f.confidence = "confirmed";
        out.push_back(std::move(f));
    };

    // soft-404 baseline from a guaranteed-to-not-exist path
    int base_status = 404;
    size_t base_len = 0;
    std::string base_body;
    std::string token = canary_token();
    if (auto base = http_get(stream, host, port,
                             "/" + token + "-sln-dirb", timeout_ms,
                             user_agent)) {
        base_status = base->status;
        base_len = base->body.size();
        base_body = base->body.substr(0, 64);
    }

    int budget = cfg.max_requests > 0 ? cfg.max_requests
                                      : static_cast<int>(cfg.words.size());
    for (const auto& word : cfg.words) {
        if (budget-- <= 0) break;
        std::string path = "/" + word;
        // the crawler already knows this page — not a discovery
        if (known.count(path)) continue;

        auto resp = http_get(stream, host, port, path, timeout_ms, user_agent);
        if (!resp) continue;
        if (detail::dirb_soft_404(*resp, base_status, base_len, base_body))
            continue;

        if (resp->status >= 200 && resp->status < 300) {
            add("Hidden path discovered: " + path, Severity::Low,
                "The path " + path + " is served with status " +
                    std::to_string(resp->status) +
                    " although nothing links to it. Review whether it "
                    "should be exposed: unlinked admin interfaces and "
                    "leftover files are prime attack surface.",
                "GET " + path + " -> " + std::to_string(resp->status) +
                    ", " + std::to_string(resp->body.size()) + " bytes");
        } else if (resp->status == 401 || resp->status == 403) {
            add("Protected path: " + path, Severity::Info,
                "The path " + path + " answers " +
                    std::to_string(resp->status) +
                    " (authentication required / forbidden). Its existence "
                    "is reconnaissance intel: it names an interface worth "
                    "protecting properly.",
                "GET " + path + " -> " + std::to_string(resp->status));
        }
        // 3xx redirects and plain errors are too noisy to report
    }
    return out;
}

} // namespace sln
