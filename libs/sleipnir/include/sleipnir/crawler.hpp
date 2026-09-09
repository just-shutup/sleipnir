// Web application discovery and active assessment.
//
// crawl_site() maps a small site graph within the scan scope: it follows
// <a href> links (staying on the target host:port), collects POST forms and
// parameterized URLs. check_crawled_app() then probes the discovered surface
// with bounded budgets: reflected-XSS markers, CSRF-less POST forms, path
// traversal and open-redirect parameters.
//
// Both halves are driven through an HttpFetcher callback so they are
// transport-agnostic (plain TCP or TLS) and unit-testable against a fake.
#pragma once

#include "sleipnir/http_client.hpp"
#include "sleipnir/results.hpp"

#include <functional>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace sln {

// ---------------------------------------------------------------------------
// HTML extraction (attribute-level parsing, no external dependencies)
// ---------------------------------------------------------------------------

struct WebForm {
    std::string action;      // raw attribute value; empty = current page
    std::string method;      // uppercased; empty = GET
    std::vector<std::pair<std::string, std::string>> fields; // name, value
    bool has_csrf_token = false;
};

// Resolves an href against the base path (same host). Returns "" for
// out-of-scope schemes (javascript:, mailto:, ...) and pure fragments.
std::string resolve_url(const std::string& base_path, const std::string& href);

std::vector<std::string> extract_links(const std::string& html);
std::vector<WebForm> extract_forms(const std::string& html);

// ---------------------------------------------------------------------------
// Crawler
// ---------------------------------------------------------------------------

struct CrawlConfig {
    int max_pages = 40;
    int max_depth = 3;
    // Scope for absolute links: only URLs with this scheme and host:port
    // are followed.
    std::string scheme = "http";
    std::string host;
    uint16_t port = 80;
};

struct CrawlForm {
    std::string action_path;   // resolved path (with query)
    std::string method;        // "GET" / "POST" / ...
    std::vector<std::pair<std::string, std::string>> fields;
    bool has_csrf_token = false;
};

struct CrawlResult {
    std::vector<std::string> pages;      // fetched in-scope paths
    std::vector<std::string> param_urls; // unique URLs with >= 1 query param
    std::vector<CrawlForm> forms;        // discovered forms
};

// fetch(path) performs GET path on the target host:port.
using HttpFetcher =
    std::function<std::optional<HttpResponse>(const std::string& path)>;

CrawlResult crawl_site(const HttpFetcher& fetch, const std::string& start_path,
                       const CrawlConfig& cfg);

// ---------------------------------------------------------------------------
// Active checks over the discovered surface
// ---------------------------------------------------------------------------

struct ActiveProbeConfig {
    int max_requests = 120; // total budget for active probes per job
    bool probe_xss = true;
    bool probe_traversal = true;
    bool probe_open_redirect = true;
    bool check_csrf = true;
};

std::vector<Finding> check_crawled_app(const HttpFetcher& fetch,
                                       const CrawlResult& crawl,
                                       const std::string& host, uint16_t port,
                                       const ActiveProbeConfig& cfg);

} // namespace sln
