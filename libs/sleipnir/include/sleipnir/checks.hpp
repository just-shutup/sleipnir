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
#include <utility>
#include <vector>

namespace sln {

struct HttpCheckResult {
    std::vector<Finding> findings;
    std::string server_product;  // from Server header, for CVE matching
    std::string server_version;
    // Every (product, version) pair worth CVE-matching: Server header
    // product plus backend runtimes disclosed via X-Powered-By etc.
    std::vector<std::pair<std::string, std::string>> tech_stack;
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

// Content-level probes for web applications: GraphQL introspection, Spring
// Boot actuator, API documentation, application manifests, PHPUnit eval-stdin
// RCE (POST, opt-out with allow_post=false in --safe), and a bounded
// single-quote probe of search endpoints with strict database-error markers.
template <typename Stream>
std::vector<Finding> check_webapp_probes(Stream& stream,
                                         const std::string& host,
                                         uint16_t port, int timeout_ms,
                                         const std::string& user_agent,
                                         bool allow_post = true);

// Testable classifiers used by check_webapp_probes.
bool looks_like_sql_error(const std::string& body);
bool graphql_introspection_reply(const std::string& body);

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
    // Built-in checks report observed responses only, never version guesses.
    f.verified = true;
    f.confidence = "confirmed";
    return f;
}

inline bool ascii_lower_contains(const std::string& haystack,
                                 const std::string& needle) {
    std::string low;
    low.reserve(haystack.size());
    for (char c : haystack)
        low += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return low.find(needle) != std::string::npos;
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
        {"/manager/html", "Tomcat Manager exposed", Severity::High,
         "The Tomcat web application manager is reachable; it allows WAR "
         "deployment, which means remote code execution with valid "
         "credentials (and brute-force now knows the door).",
         "Apache Tomcat"},
        {"/wp-json/wp/v2/users", "WordPress user enumeration via REST API",
         Severity::Medium,
         "The WordPress REST API returns the list of registered users "
         "without authentication; the logins feed password attacks.",
         "\"slug\""},
        {"/robots.txt", "robots.txt discloses private paths", Severity::Info,
         "robots.txt enumerates directories the site prefers to keep out of "
         "search engines; these paths are a useful target list. Informational.",
         "Disallow"},
    };

    std::vector<Finding> out;
    for (const auto& pc : paths) {
        auto resp = http_get(stream, host, port, pc.path, timeout_ms,
                             user_agent);
        // no is_open() shortcut here: with Connection: close the socket is
        // typically closed after each request; http_get reconnects anyway
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
template <typename Stream>
std::vector<Finding> check_webapp_probes(Stream& stream,
                                         const std::string& host,
                                         uint16_t port, int timeout_ms,
                                         const std::string& user_agent,
                                         bool allow_post) {
    std::vector<Finding> out;
    auto add = [&](const std::string& title, Severity sev,
                   const std::string& description,
                   const std::string& evidence) {
        out.push_back(detail::make_finding(host, port, title, sev, description,
                                           evidence));
    };

    // GraphQL: detect the endpoint first, then try introspection. Enabled
    // introspection hands an attacker the complete API schema.
    if (auto gq = http_get(stream, host, port, "/graphql", timeout_ms,
                           user_agent);
        gq && !gq->body.empty() &&
        (detail::ascii_lower_contains(gq->body, "graphql") ||
         detail::ascii_lower_contains(gq->body, "graphiql") ||
         gq->status == 400 || gq->status == 405 || gq->status == 200)) {
        auto intro = http_get(
            stream, host, port,
            "/graphql?query={__schema%20{types%20{name}}}", timeout_ms,
            user_agent);
        if (intro && intro->status == 200 &&
            graphql_introspection_reply(intro->body)) {
            add("GraphQL introspection enabled", Severity::Medium,
                "The GraphQL endpoint answers introspection queries without "
                "authentication, disclosing the full API schema: types, "
                "fields and relations. That map drives targeted queries, "
                "including mutations outside the intended UI.",
                "GET /graphql?query={__schema{types{name}}} -> " +
                    std::to_string(intro->body.size()) + " bytes of schema");
        } else {
            add("GraphQL endpoint detected", Severity::Info,
                "A GraphQL endpoint is reachable. Worth manual review: "
                "introspection state, batched queries and authorization on "
                "nested fields.",
                "GET /graphql -> " + std::to_string(gq->status));
        }
    }

    // Spring Boot actuator: the root endpoint lists operational routes;
    // /env often leaks credentials.
    if (auto act = http_get(stream, host, port, "/actuator", timeout_ms,
                            user_agent);
        act && act->status == 200 &&
        act->body.find("_links") != std::string::npos) {
        add("Spring Boot actuator exposed", Severity::High,
            "The actuator management API is reachable without authentication. "
            "Depending on the enabled endpoints it discloses configuration, "
            "environment variables (often credentials), heap dumps and "
            "shutdown controls.",
            "GET /actuator -> 200, _links present");
    }

    // API documentation: OpenAPI/Swagger describes every internal route.
    for (const char* path : {"/swagger.json", "/api-docs", "/v3/api-docs"}) {
        if (auto doc = http_get(stream, host, port, path, timeout_ms,
                                user_agent);
            doc && doc->status == 200 &&
            (doc->body.find("\"openapi\"") != std::string::npos ||
             doc->body.find("\"swagger\"") != std::string::npos)) {
            add("API documentation exposed", Severity::Low,
                std::string("OpenAPI/Swagger specification at ") + path +
                    " enumerates every API route, parameter and model — "
                    "reconnaissance for free.",
                "GET " + std::string(path) + " -> 200, " +
                    std::to_string(doc->body.size()) + " bytes");
            break; // one spec is enough
        }
    }

    // Application manifest (npm SPAs ship package.json to the web root).
    if (auto pkg = http_get(stream, host, port, "/package.json", timeout_ms,
                            user_agent);
        pkg && pkg->status == 200 &&
        pkg->body.find("\"name\"") != std::string::npos &&
        pkg->body.find("\"version\"") != std::string::npos) {
        add("Application manifest exposed", Severity::Info,
            "package.json is served from the web root. It names the "
            "application and its dependency versions — a dependency lookup "
            "produces a targeted CVE list.",
            "GET /package.json -> 200");
    }

    // PHPUnit eval-stdin RCE (CVE-2017-9841): the script evaluates the raw
    // POST body as PHP. The payload only echoes an md5 constant, so a hit is
    // remote-code-execution proof while staying read-only. POST -> skipped
    // in --safe mode.
    if (allow_post) {
        static const char* eval_paths[] = {
            "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
            "/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
            "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php/",
        };
        const std::string marker = "05f43fed0e82268cba041a6b303c81f7"; // md5('sleipnir')
        HttpOptions php_opts;
        php_opts.body = "<?php echo(md5('sleipnir')); ?>";
        php_opts.content_type = "text/html";
        for (const char* ep : eval_paths) {
            auto resp = http_request_ex(stream, "POST", host, port, ep,
                                        timeout_ms, user_agent, php_opts);
            if (!resp || resp->body.find(marker) == std::string::npos)
                continue;
            out.push_back(detail::make_finding(
                host, port,
                "PHPUnit eval-stdin.php exposed (CVE-2017-9841)",
                Severity::Critical,
                "The PHPUnit eval-stdin.php script is reachable and executes "
                "the raw request body as PHP code — unauthenticated remote "
                "code execution. Remove vendor test files from the deployed "
                "web root.",
                "POST " + std::string(ep) + " with <?php echo(md5('sleipnir')); "
                "?> -> md5 marker returned"));
            break;
        }
    }

    // Bounded SQL-injection probe: quote-only payloads against typical search
    // endpoints, reported only when a real database error string comes back.
    struct SqliProbe {
        const char* path;
        const char* param;
    };
    static const SqliProbe sqli[] = {
        {"/search", "q"}, {"/rest/products/search", "q"}, {"/api/search", "q"},
    };
    for (const auto& s : sqli) {
        std::string path = std::string(s.path) + "?" + s.param + "=')";
        auto resp = http_get(stream, host, port, path, timeout_ms, user_agent);
        if (!resp) continue;
        if (resp->status >= 500 || resp->status == 200) {
            if (looks_like_sql_error(resp->body)) {
                add("Possible SQL injection in search parameter", Severity::High,
                    std::string("A single quote in the search parameter (") +
                        s.param + " of " + s.path +
                        ") produces a database error in the response. The "
                        "endpoint concatenates input into SQL — test with "
                        "standard injection syntax for confirmation.",
                    "GET " + path + " -> " + std::to_string(resp->status) +
                        ", DB error in body");
            }
        }
    }
    return out;
}

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
