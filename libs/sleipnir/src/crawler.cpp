#include "sleipnir/crawler.hpp"

#include <algorithm>
#include <cctype>
#include <deque>
#include <set>

namespace sln {

namespace {

std::string to_lower(std::string s) {
    for (char& c : s)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

std::string trim(const std::string& s) {
    size_t b = s.find_first_not_of(" \t\r\n");
    if (b == std::string::npos) return "";
    size_t e = s.find_last_not_of(" \t\r\n");
    return s.substr(b, e - b + 1);
}

// Finds the next tag of interest (`a`, `base`, `form`, `input`, `textarea`,
// `select`) starting at `from`. Returns the position of '<' and the tag name,
// or npos. Skips comments and closing tags.
size_t find_tag(const std::string& html, size_t from, std::string& name) {
    static const char* tags[] = {"a", "base", "form", "input", "textarea",
                                 "select"};
    for (size_t pos = from; pos < html.size();) {
        size_t lt = html.find('<', pos);
        if (lt == std::string::npos) return std::string::npos;
        if (html.compare(lt, 4, "<!--") == 0) {
            size_t end = html.find("-->", lt + 4);
            pos = (end == std::string::npos) ? html.size() : end + 3;
            continue;
        }
        size_t i = lt + 1;
        if (i < html.size() && html[i] == '/') { // closing tag
            pos = lt + 1;
            continue;
        }
        std::string candidate;
        while (i < html.size() && std::isalpha(static_cast<unsigned char>(html[i])))
            candidate += static_cast<char>(
                std::tolower(static_cast<unsigned char>(html[i++])));
        if (candidate.empty()) {
            pos = lt + 1;
            continue;
        }
        for (const char* t : tags) {
            if (candidate == t) {
                name = candidate;
                return lt;
            }
        }
        pos = lt + 1;
    }
    return std::string::npos;
}

// Extracts the full tag body (between '<' and the matching '>'), honouring
// quoted attribute values that may contain '>'.
std::string tag_body(const std::string& html, size_t lt) {
    size_t i = lt + 1;
    bool in_quote = false;
    char quote = 0;
    for (; i < html.size(); ++i) {
        char c = html[i];
        if (in_quote) {
            if (c == quote) in_quote = false;
        } else if (c == '"' || c == '\'') {
            in_quote = true;
            quote = c;
        } else if (c == '>') {
            return html.substr(lt + 1, i - lt - 1);
        }
    }
    return html.substr(lt + 1);
}

// Parses `name="value"` pairs from a tag body. Attribute names are
// lowercased; values keep their original case.
std::vector<std::pair<std::string, std::string>> parse_attrs(
    const std::string& body) {
    std::vector<std::pair<std::string, std::string>> attrs;
    size_t i = 0;
    while (i < body.size()) {
        while (i < body.size() && !std::isalpha(static_cast<unsigned char>(body[i])))
            ++i;
        if (i >= body.size()) break;
        std::string name;
        while (i < body.size() && body[i] != '=' && body[i] != ' ' &&
               body[i] != '/' && body[i] != '>')
            name += body[i++];
        while (i < body.size() && body[i] != '=' && body[i] != ' ' &&
               body[i] != '>')
            ++i;
        if (i >= body.size()) break;
        if (body[i] != '=') { // boolean attribute (e.g. `required`)
            attrs.push_back({to_lower(name), ""});
            continue;
        }
        ++i; // '='
        while (i < body.size() && (body[i] == ' ' || body[i] == '\t')) ++i;
        std::string value;
        if (i < body.size() && (body[i] == '"' || body[i] == '\'')) {
            char q = body[i++];
            while (i < body.size() && body[i] != q) value += body[i++];
            if (i < body.size()) ++i; // closing quote
        } else {
            while (i < body.size() && body[i] != ' ' && body[i] != '>')
                value += body[i++];
        }
        attrs.push_back({to_lower(name), value});
    }
    return attrs;
}

const std::string* find_attr(
    const std::vector<std::pair<std::string, std::string>>& attrs,
    const std::string& name) {
    for (const auto& [k, v] : attrs)
        if (k == name) return &v;
    return nullptr;
}

// Removes "." and ".." segments from an absolute path.
std::string normalize_path(std::string path) {
    std::string prefix; // query part is kept verbatim
    size_t q = path.find('?');
    if (q != std::string::npos) {
        prefix = path.substr(q);
        path = path.substr(0, q);
    }
    std::vector<std::string> segs;
    size_t pos = 0;
    while (pos <= path.size()) {
        size_t slash = path.find('/', pos);
        std::string seg = (slash == std::string::npos)
                              ? path.substr(pos)
                              : path.substr(pos, slash - pos);
        if (slash == std::string::npos) pos = path.size() + 1;
        else pos = slash + 1;
        if (seg == "..") {
            if (!segs.empty()) segs.pop_back();
        } else if (seg != "." && !seg.empty()) {
            segs.push_back(seg);
        }
    }
    std::string out;
    for (const auto& s : segs) out += "/" + s;
    if (out.empty()) out = "/";
    return out + prefix;
}

bool has_web_scheme(const std::string& href, std::string& scheme) {
    size_t sep = href.find("://");
    if (sep == std::string::npos || sep == 0) return false;
    scheme = to_lower(href.substr(0, sep));
    return true;
}

// True when the href names a non-HTTP resource or is a pure fragment.
bool is_unusable_href(const std::string& href) {
    if (href.empty() || href[0] == '#') return true;
    std::string scheme;
    if (has_web_scheme(href, scheme))
        return scheme != "http" && scheme != "https";
    static const char* blocked[] = {"javascript:", "mailto:", "tel:",
                                    "data:", "ftp:", "file:"};
    std::string low = to_lower(href);
    for (const char* b : blocked)
        if (low.rfind(b, 0) == 0) return true;
    return false;
}

struct UrlParts {
    std::string path;              // "/x/y"
    std::vector<std::pair<std::string, std::string>> params; // raw name/value
};

UrlParts split_url(const std::string& path_with_query) {
    UrlParts up;
    size_t q = path_with_query.find('?');
    up.path = (q == std::string::npos) ? path_with_query
                                       : path_with_query.substr(0, q);
    if (up.path.empty()) up.path = "/";
    if (q == std::string::npos) return up;
    std::string query = path_with_query.substr(q + 1);
    size_t pos = 0;
    while (pos < query.size()) {
        size_t amp = query.find('&', pos);
        std::string pair =
            (amp == std::string::npos) ? query.substr(pos) : query.substr(pos, amp - pos);
        pos = (amp == std::string::npos) ? query.size() : amp + 1;
        if (pair.empty()) continue;
        size_t eq = pair.find('=');
        if (eq == std::string::npos) up.params.push_back({pair, ""});
        else up.params.push_back({pair.substr(0, eq), pair.substr(eq + 1)});
    }
    return up;
}

std::string join_url(const UrlParts& up) {
    if (up.params.empty()) return up.path;
    std::string q;
    for (const auto& [n, v] : up.params) {
        if (!q.empty()) q += "&";
        q += n + "=" + v;
    }
    return up.path + "?" + q;
}

// Deduplication key: path + sorted parameter NAMES (values ignored — the
// crawler explores parameter combinations via one representative URL).
std::string page_key(const UrlParts& up) {
    std::vector<std::string> names;
    for (const auto& [n, v] : up.params) names.push_back(n);
    std::sort(names.begin(), names.end());
    std::string key = up.path;
    for (const auto& n : names) key += "&" + n;
    return key;
}

bool is_csrf_field(const std::string& field_name) {
    std::string low = to_lower(field_name);
    static const char* markers[] = {"csrf", "token", "nonce",
                                    "authenticity", "verification"};
    for (const char* m : markers)
        if (low.find(m) != std::string::npos) return true;
    return false;
}

// Resolves href (relative, root-relative or absolute) against the base path
// and the crawl scope. Returns "" when the target is out of scope.
std::string resolve_in_scope(const std::string& base_path,
                             const std::string& href,
                             const CrawlConfig& cfg) {
    std::string resolved = resolve_url(base_path, href);
    if (resolved.empty()) return "";
    std::string scheme;
    if (has_web_scheme(resolved, scheme)) {
        if (scheme != to_lower(cfg.scheme)) return "";
        size_t rest = scheme.size() + 3;
        size_t slash = resolved.find('/', rest);
        std::string authority = (slash == std::string::npos)
                                    ? resolved.substr(rest)
                                    : resolved.substr(rest, slash - rest);
        std::string link_host = to_lower(authority);
        int link_port = (scheme == "https") ? 443 : 80;
        size_t colon = authority.rfind(':');
        if (colon != std::string::npos &&
            authority.find(']') == std::string::npos) {
            link_host = to_lower(authority.substr(0, colon));
            link_port = std::stoi(authority.substr(colon + 1));
        }
        if (link_host != to_lower(cfg.host) ||
            link_port != static_cast<int>(cfg.port))
            return "";
        resolved = (slash == std::string::npos) ? "/" : resolved.substr(slash);
        if (resolved.empty()) resolved = "/";
    }
    return resolved;
}

std::string snippet(const std::string& s, size_t max = 200) {
    std::string one = s;
    for (char& c : one)
        if (c == '\n' || c == '\r' || c == '\t') c = ' ';
    return one.substr(0, max);
}

} // namespace

std::string resolve_url(const std::string& base_path, const std::string& href) {
    std::string h = trim(href);
    if (is_unusable_href(h)) return "";

    std::string scheme;
    if (has_web_scheme(h, scheme)) {
        // Absolute URL: the caller is responsible for scope checks; here we
        // cannot know the scope host, so it is passed through untouched and
        // the crawler decides.
        return h;
    }

    if (!h.empty() && h[0] == '/') return normalize_path(h);
    if (h[0] == '?') {
        size_t q = base_path.find('?');
        std::string base =
            (q == std::string::npos) ? base_path : base_path.substr(0, q);
        return normalize_path(base + h);
    }

    // Relative: resolve against the base directory.
    size_t q = base_path.find('?');
    std::string base =
        (q == std::string::npos) ? base_path : base_path.substr(0, q);
    size_t last_slash = base.rfind('/');
    std::string dir =
        (last_slash == std::string::npos) ? "/" : base.substr(0, last_slash + 1);
    return normalize_path(dir + h);
}

std::vector<std::string> extract_links(const std::string& html) {
    std::vector<std::string> out;
    size_t pos = 0;
    for (;;) {
        std::string tag;
        size_t lt = find_tag(html, pos, tag);
        if (lt == std::string::npos) break;
        pos = lt + 1;
        if (tag != "a") continue;
        auto attrs = parse_attrs(tag_body(html, lt));
        if (auto href = find_attr(attrs, "href"))
            out.push_back(*href);
    }
    return out;
}

std::vector<WebForm> extract_forms(const std::string& html) {
    std::vector<WebForm> out;
    size_t pos = 0;
    for (;;) {
        std::string tag;
        size_t lt = find_tag(html, pos, tag);
        if (lt == std::string::npos) break;
        pos = lt + 1;
        if (tag != "form") continue;

        WebForm form;
        auto fattrs = parse_attrs(tag_body(html, lt));
        if (auto a = find_attr(fattrs, "action")) form.action = *a;
        if (auto m = find_attr(fattrs, "method")) form.method = to_lower(*m);
        if (form.method.empty()) form.method = "get";
        form.method = to_lower(form.method) == "post" ? "POST" : "GET";

        // scan the form region for input fields
        size_t region_end = html.find("</form>", lt + 1);
        if (region_end == std::string::npos) region_end = html.size();
        size_t inner = lt + 1;
        for (;;) {
            std::string itag;
            size_t ilt = find_tag(html, inner, itag);
            if (ilt == std::string::npos || ilt >= region_end) break;
            inner = ilt + 1;
            if (itag != "input" && itag != "textarea" && itag != "select")
                continue;
            auto iattrs = parse_attrs(tag_body(html, ilt));
            auto name = find_attr(iattrs, "name");
            if (!name || name->empty()) continue;
            std::string value;
            if (auto v = find_attr(iattrs, "value")) value = *v;
            form.fields.push_back({*name, value});
            if (is_csrf_field(*name)) form.has_csrf_token = true;
        }
        out.push_back(std::move(form));
    }
    return out;
}

CrawlResult crawl_site(const HttpFetcher& fetch, const std::string& start_path,
                       const CrawlConfig& cfg) {
    CrawlResult out;
    std::set<std::string> visited;
    std::deque<std::pair<std::string, int>> queue; // path, depth

    queue.push_back({normalize_path(start_path), 0});

    while (!queue.empty() &&
           static_cast<int>(out.pages.size()) < cfg.max_pages) {
        auto [path, depth] = queue.front();
        queue.pop_front();

        UrlParts up = split_url(path);
        std::string key = page_key(up);
        if (visited.count(key)) continue;
        visited.insert(key);

        auto resp = fetch(join_url(up));
        if (!resp) continue;
        out.pages.push_back(join_url(up));

        if (!up.params.empty()) out.param_urls.push_back(join_url(up));

        // redirects: follow within scope (the fetcher already binds host/port)
        if (resp->status >= 300 && resp->status < 400) {
            if (auto loc = resp->header("location")) {
                std::string target = resolve_in_scope(path, *loc, cfg);
                if (!target.empty()) queue.push_back({target, depth + 1});
            }
            continue;
        }

        if (resp->body.empty()) continue;

        // links
        if (depth < cfg.max_depth) {
            for (const auto& href : extract_links(resp->body)) {
                std::string resolved = resolve_in_scope(path, href, cfg);
                if (resolved.empty()) continue;
                UrlParts rup = split_url(resolved);
                if (!visited.count(page_key(rup)))
                    queue.push_back({join_url(rup), depth + 1});
            }
        }

        // forms
        for (const auto& f : extract_forms(resp->body)) {
            std::string action = f.action.empty()
                                     ? join_url(up)
                                     : resolve_in_scope(path, f.action, cfg);
            if (action.empty()) continue;
            CrawlForm cf;
            cf.action_path = action;
            cf.method = f.method;
            cf.fields = f.fields;
            cf.has_csrf_token = f.has_csrf_token;
            out.forms.push_back(std::move(cf));
            if (f.method == "GET" && !f.fields.empty()) {
                // a GET form is just a parameterized URL
                std::string q;
                for (const auto& [n, v] : f.fields) {
                    if (!q.empty()) q += "&";
                    q += n + "=" + v;
                }
                UrlParts fup = split_url(action + (action.find('?') == std::string::npos ? "?" : "") + q);
                if (!visited.count(page_key(fup)))
                    out.param_urls.push_back(join_url(fup));
            }
        }
    }

    // dedupe param URLs by path + parameter names
    std::set<std::string> seen;
    std::vector<std::string> uniq;
    for (const auto& u : out.param_urls) {
        if (seen.insert(page_key(split_url(u))).second)
            uniq.push_back(u);
    }
    out.param_urls = std::move(uniq);
    return out;
}

std::vector<Finding> check_crawled_app(const HttpFetcher& fetch,
                                       const CrawlResult& crawl,
                                       const std::string& host, uint16_t port,
                                       const ActiveProbeConfig& cfg) {
    std::vector<Finding> out;
    auto add = [&](const std::string& title, Severity sev,
                   const std::string& description, const std::string& evidence) {
        Finding f;
        f.host = host;
        f.port = port;
        f.title = title;
        f.severity = sev;
        f.description = description;
        f.evidence = evidence;
        f.source = "webapp";
        out.push_back(std::move(f));
    };
    int budget = cfg.max_requests;

    // CSRF: POST forms without a token field.
    if (cfg.check_csrf) {
        std::set<std::string> reported;
        for (const auto& f : crawl.forms) {
            if (f.has_csrf_token || f.method != "POST") continue;
            if (!reported.insert(f.action_path).second) continue;
            bool login_form = false;
            std::string field_list;
            for (const auto& [n, v] : f.fields) {
                if (to_lower(n) == "password" || to_lower(n) == "passwd" ||
                    to_lower(n) == "pass")
                    login_form = true;
                if (!field_list.empty()) field_list += ", ";
                field_list += n;
            }
            add("POST form without CSRF protection",
                login_form ? Severity::Low : Severity::Medium,
                std::string("The form at ") + f.action_path +
                    " submits state-changing data (fields: " + field_list +
                    ") without an anti-CSRF token. A third-party site can "
                    "submit it on behalf of an authenticated visitor.",
                "form action=" + f.action_path + " method=POST fields=[" +
                    field_list + "]");
        }
    }

    // Reflected XSS: substitute each parameter with a marker payload and
    // look for the unencoded marker in an HTML response.
    if (cfg.probe_xss) {
        const std::string payload = "\"><svg/onload=alert(1)>";
        const std::string marker = "<svg/onload=alert(1)>";
        for (const auto& url : crawl.param_urls) {
            if (budget <= 0) break;
            UrlParts up = split_url(url);
            for (auto& [name, value] : up.params) {
                if (budget-- <= 0) break;
                std::string orig = value;
                value = payload;
                auto resp = fetch(join_url(up));
                value = orig;
                if (!resp) continue;
                bool html_context = true;
                if (auto ct = resp->header("content-type"))
                    html_context = ct->find("html") != std::string::npos;
                if (!html_context) continue;
                if (resp->body.find(marker) == std::string::npos) continue;
                size_t pos = resp->body.find(marker);
                add("Reflected input in HTML context (possible XSS)",
                    Severity::High,
                    std::string("The parameter '") + name +
                        "' is echoed back into the HTML response without "
                        "encoding: injected markup would execute in the "
                        "victim's browser. Confirm the execution context and "
                        "apply context-aware output encoding.",
                    "GET " + join_url(up) + " -> reflected at offset " +
                        std::to_string(pos) + ": ..." +
                        snippet(resp->body.substr(
                            std::max(0, static_cast<int>(pos) - 40), 120)) +
                        "...");
            }
        }
    }

    // Path traversal: common file-parameter names, /etc/passwd marker.
    if (cfg.probe_traversal) {
        static const char* file_params[] = {"file",  "path",  "page",   "include",
                                            "template", "doc", "dir", "show",
                                            "read",  "cat",   "download", "view",
                                            "lang",  "module", "action"};
        const std::string payload = "../../../../etc/passwd";
        for (const auto& url : crawl.param_urls) {
            if (budget <= 0) break;
            UrlParts up = split_url(url);
            for (auto& [name, value] : up.params) {
                bool match = false;
                for (const char* p : file_params)
                    if (to_lower(name) == p) { match = true; break; }
                if (!match) continue;
                if (budget-- <= 0) break;
                std::string orig = value;
                value = payload;
                auto resp = fetch(join_url(up));
                value = orig;
                if (!resp) continue;
                if (resp->body.find("root:x:0:0:") == std::string::npos &&
                    resp->body.find("root:*:0:0:") == std::string::npos)
                    continue;
                add("Possible path traversal in file parameter",
                    Severity::High,
                    std::string("The parameter '") + name +
                        "' appears to reach the filesystem: a ../ sequence "
                        "returned /etc/passwd content. Restrict the parameter "
                        "to an allow-list of served files.",
                    "GET " + join_url(up) + " -> passwd content returned");
            }
        }
    }

    // Open redirect: redirect-ish parameter names pointing at an external URL.
    if (cfg.probe_open_redirect) {
        static const char* redirect_params[] = {
            "url",     "redirect", "redir",  "next",  "return", "returnto",
            "returnurl", "goto",   "target", "dest",  "destination",
            "continue", "link",   "rurl",   "to",    "out"};
        const std::string payload = "https://sln-open-redirect-probe.invalid/";
        for (const auto& url : crawl.param_urls) {
            if (budget <= 0) break;
            UrlParts up = split_url(url);
            for (auto& [name, value] : up.params) {
                bool match = false;
                for (const char* p : redirect_params)
                    if (to_lower(name) == p) { match = true; break; }
                if (!match) continue;
                if (budget-- <= 0) break;
                std::string orig = value;
                value = payload;
                auto resp = fetch(join_url(up));
                value = orig;
                if (!resp) continue;
                bool reflected = false;
                if (resp->status >= 300 && resp->status < 400) {
                    if (auto loc = resp->header("location"))
                        reflected = loc->find(payload) != std::string::npos;
                } else {
                    reflected =
                        resp->body.find(payload) != std::string::npos;
                }
                if (!reflected) continue;
                add("Open redirect in navigation parameter", Severity::Medium,
                    std::string("The parameter '") + name +
                        "' accepts an absolute URL and redirects to it. "
                        "Attackers abuse this to launder phishing links "
                        "through a trusted domain. Allow-list redirect "
                        "targets.",
                    "GET " + join_url(up) + " -> " +
                        std::to_string(resp->status));
            }
        }
    }

    return out;
}

} // namespace sln
