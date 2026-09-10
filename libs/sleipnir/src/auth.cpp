#include "sleipnir/auth.hpp"
#include "sleipnir/http_client.hpp"
#include "sleipnir/results.hpp"

#ifdef SLEIPNIR_HAVE_TLS
#include "sleipnir/tls_client.hpp"
#endif

#include <algorithm>
#include <cctype>
#include <fstream>

namespace sln {

namespace {

std::string ascii_lower(std::string s) {
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

// "name=value" from one Set-Cookie line (attributes after ';' dropped).
std::string cookie_pair(const std::string& set_cookie) {
    size_t semi = set_cookie.find(';');
    std::string pair = trim(semi == std::string::npos
                                ? set_cookie
                                : set_cookie.substr(0, semi));
    size_t eq = pair.find('=');
    if (eq == std::string::npos) return "";
    std::string name = trim(pair.substr(0, eq));
    if (name.empty()) return "";
    return pair;
}

} // namespace

std::string base64_encode(const std::string& in) {
    static const char* table =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve((in.size() + 2) / 3 * 4);
    size_t i = 0;
    for (; i + 2 < in.size(); i += 3) {
        uint32_t v = (static_cast<unsigned char>(in[i]) << 16) |
                     (static_cast<unsigned char>(in[i + 1]) << 8) |
                     static_cast<unsigned char>(in[i + 2]);
        out += table[(v >> 18) & 0x3f];
        out += table[(v >> 12) & 0x3f];
        out += table[(v >> 6) & 0x3f];
        out += table[v & 0x3f];
    }
    if (i + 1 == in.size()) {
        uint32_t v = static_cast<unsigned char>(in[i]) << 16;
        out += table[(v >> 18) & 0x3f];
        out += table[(v >> 12) & 0x3f];
        out += "==";
    } else if (i + 2 == in.size()) {
        uint32_t v = (static_cast<unsigned char>(in[i]) << 16) |
                     (static_cast<unsigned char>(in[i + 1]) << 8);
        out += table[(v >> 18) & 0x3f];
        out += table[(v >> 12) & 0x3f];
        out += table[(v >> 6) & 0x3f];
        out += '=';
    }
    return out;
}

bool auth_applies(const AuthConfig& auth, const std::string& scan_host) {
    if (!auth.enabled()) return false;
    if (auth.hosts.empty()) return true;
    std::string needle = ascii_lower(scan_host);
    for (const auto& h : auth.hosts) {
        if (h == "*") return true;
        if (ascii_lower(h) == needle) return true;
    }
    return false;
}

std::optional<AuthTarget> parse_auth_url(const std::string& url) {
    size_t sep = url.find("://");
    if (sep == std::string::npos || sep == 0) return std::nullopt;
    AuthTarget t;
    t.scheme = ascii_lower(url.substr(0, sep));
    if (t.scheme != "http" && t.scheme != "https") return std::nullopt;
    t.port = t.scheme == "https" ? 443 : 80;
    size_t rest = sep + 3;
    size_t slash = url.find('/', rest);
    std::string authority = (slash == std::string::npos)
                                ? url.substr(rest)
                                : url.substr(rest, slash - rest);
    t.path = (slash == std::string::npos) ? "/" : url.substr(slash);
    // strip userinfo if present
    size_t at = authority.rfind('@');
    if (at != std::string::npos) authority = authority.substr(at + 1);
    // [v6]:port
    if (!authority.empty() && authority[0] == '[') {
        size_t close = authority.find(']');
        if (close == std::string::npos) return std::nullopt;
        t.host = authority.substr(1, close - 1);
        if (close + 1 < authority.size() && authority[close + 1] == ':') {
            try {
                t.port = static_cast<uint16_t>(
                    std::stoi(authority.substr(close + 2)));
            } catch (...) {
                return std::nullopt;
            }
        }
    } else {
        size_t colon = authority.rfind(':');
        if (colon != std::string::npos) {
            t.host = authority.substr(0, colon);
            try {
                t.port = static_cast<uint16_t>(
                    std::stoi(authority.substr(colon + 1)));
            } catch (...) {
                return std::nullopt;
            }
        } else {
            t.host = authority;
        }
    }
    if (t.host.empty()) return std::nullopt;
    return t;
}

std::string cookie_jar_header(const std::string& file_path) {
    std::ifstream in(file_path);
    if (!in) return "";
    std::vector<std::string> pairs;
    std::string line;
    while (std::getline(in, line)) {
        if (line.rfind("#HttpOnly_", 0) == 0) line = line.substr(10);
        if (line.empty() || line[0] == '#') continue;
        // domain \t flag \t path \t secure \t expiry \t name \t value
        std::vector<std::string> fields;
        size_t pos = 0;
        while (pos <= line.size() && fields.size() < 7) {
            size_t tab = line.find('\t', pos);
            fields.push_back(tab == std::string::npos
                                 ? line.substr(pos)
                                 : line.substr(pos, tab - pos));
            if (tab == std::string::npos) break;
            pos = tab + 1;
        }
        if (fields.size() >= 7 && !fields[5].empty())
            pairs.push_back(fields[5] + "=" + fields[6]);
    }
    std::string out;
    for (const auto& p : pairs) {
        if (!out.empty()) out += "; ";
        out += p;
    }
    return out;
}

std::vector<std::pair<std::string, std::string>> establish_auth_session(
    asio::io_context& io, const AuthConfig& auth, const std::string& scan_host,
    int timeout_ms, const std::string& user_agent, ResultCollector& out) {
    std::vector<std::pair<std::string, std::string>> headers;

    if (auth.method == "basic") {
        headers.push_back({"Authorization",
                           "Basic " + base64_encode(auth.user + ":" +
                                                    auth.password)});
        return headers;
    }

    if (auth.method == "cookie") {
        std::string value = auth.cookie;
        if (value.empty()) value = cookie_jar_header(auth.cookie_file);
        if (value.empty()) {
            out.log("  [auth] no usable cookies (cookie/cookie_file empty)");
            return {};
        }
        headers.push_back({"Cookie", value});
        return headers;
    }

    if (auth.method == "form") {
        auto target = parse_auth_url(auth.url);
        if (!target) {
            out.log("  [auth] invalid login URL: " + auth.url);
            return {};
        }

        // urlencoded body from the configured fields (map order = sorted)
        std::string body;
        for (const auto& [name, value] : auth.fields) {
            if (!body.empty()) body += "&";
            body += name + "=" + value;
        }
        if (body.empty()) {
            out.log("  [auth] form method configured without fields");
            return {};
        }

        std::optional<HttpResponse> resp;
#ifdef SLEIPNIR_HAVE_TLS
        if (target->scheme == "https") {
            TlsClient client(io);
            HttpOptions opts;
            opts.body = body;
            opts.content_type = "application/x-www-form-urlencoded";
            resp = http_request_ex(client, "POST", target->host, target->port,
                                   target->path, timeout_ms, user_agent, opts);
        } else
#endif
        {
            TcpClient client(io);
            HttpOptions opts;
            opts.body = body;
            opts.content_type = "application/x-www-form-urlencoded";
            resp = http_request_ex(client, "POST", target->host, target->port,
                                   target->path, timeout_ms, user_agent, opts);
        }
        if (!resp) {
            out.log("  [auth] login request failed: " + auth.url);
            return {};
        }

        bool ok = resp->status >= 200 && resp->status < 400;
        if (!auth.success.empty())
            ok = ok && resp->body.find(auth.success) != std::string::npos;
        if (!ok) {
            out.log("  [auth] login failed for " + scan_host + " (status " +
                    std::to_string(resp->status) +
                    (auth.success.empty()
                         ? ")"
                         : ", no success marker '" + auth.success + "')"));
            return {};
        }

        // collect Set-Cookie pairs (parse_response joins multiple with \n)
        std::string cookie_value;
        if (const std::string* setc = resp->header("set-cookie")) {
            std::string joined = *setc;
            size_t pos = 0;
            while (pos <= joined.size()) {
                size_t nl = joined.find('\n', pos);
                std::string line = (nl == std::string::npos)
                                       ? joined.substr(pos)
                                       : joined.substr(pos, nl - pos);
                std::string pair = cookie_pair(line);
                if (!pair.empty()) {
                    if (!cookie_value.empty()) cookie_value += "; ";
                    cookie_value += pair;
                }
                if (nl == std::string::npos) break;
                pos = nl + 1;
            }
        }
        if (cookie_value.empty()) {
            out.log("  [auth] login succeeded but no session cookie was set");
            return {};
        }
        headers.push_back({"Cookie", cookie_value});
        return headers;
    }

    return {};
}

} // namespace sln
