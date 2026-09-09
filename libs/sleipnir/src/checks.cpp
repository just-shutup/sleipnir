#include "sleipnir/checks.hpp"

#include <cctype>

namespace sln {

namespace {

Finding make_finding(const std::string& host, uint16_t port,
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

bool looks_like_directory_listing(const std::string& body) {
    return body.find("Index of /") != std::string::npos ||
           body.find("Directory listing for") != std::string::npos ||
           (body.find("<table") != std::string::npos &&
            body.find("Parent Directory") != std::string::npos);
}

// Server: Apache/2.4.49 (Unix) -> product "Apache", version "2.4.49"
void split_server_header(const std::string& value, std::string& product,
                         std::string& version) {
    size_t slash = value.find('/');
    if (slash == std::string::npos) {
        product = value.substr(0, value.find(' '));
        version.clear();
        return;
    }
    product = value.substr(0, slash);
    std::string rest = value.substr(slash + 1);
    size_t space = rest.find(' ');
    version = (space == std::string::npos) ? rest : rest.substr(0, space);

    // "Apache-Coyote/1.1" reports the Tomcat connector version, not an httpd
    // version; matching it against the Apache httpd CVEs would be a false
    // positive. The product stays Tomcat, but the version is unusable.
    if (product == "Apache-Coyote") {
        product = "Apache Tomcat";
        version.clear();
    }
}

std::string ascii_lower(std::string s) {
    for (char& c : s)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

} // namespace

HttpCheckResult check_root_response(const std::string& host, uint16_t port,
                                    const HttpResponse& resp) {
    HttpCheckResult out;

    if (const std::string* server = resp.header("server")) {
        split_server_header(*server, out.server_product, out.server_version);
        if (!out.server_version.empty()) {
            out.findings.push_back(make_finding(
                host, port, "Server version disclosed in HTTP header",
                Severity::Info,
                "The Server header reveals the exact software version: '" +
                    *server + "'. This simplifies targeted attacks.",
                "Server: " + *server));
        }
    }

    if (looks_like_directory_listing(resp.body)) {
        out.findings.push_back(make_finding(
            host, port, "Directory listing enabled", Severity::Medium,
            "The web server displays an auto-generated directory index "
            "instead of a page. Visitors can browse the file system.",
            resp.body.substr(0, 200)));
    }

    struct HeaderCheck {
        const char* name;
        const char* why;
        Severity sev;
    };
    static const HeaderCheck missing_headers[] = {
        {"content-security-policy",
         "No Content-Security-Policy header: increased XSS risk.", Severity::Low},
        {"x-content-type-options",
         "No X-Content-Type-Options header: browsers may MIME-sniff "
         "responses.",
         Severity::Low},
        {"x-frame-options",
         "No X-Frame-Options header: the site can be framed (clickjacking).",
         Severity::Low},
    };
    for (const auto& hc : missing_headers) {
        if (!resp.header(hc.name)) {
            out.findings.push_back(make_finding(
                host, port, std::string("Missing security header: ") + hc.name,
                hc.sev, hc.why, ""));
        }
    }

    // CORS: a wildcard origin combined with credentials defeats the same-
    // origin policy for any third-party site.
    if (auto acao = resp.header("access-control-allow-origin")) {
        std::string v = ascii_lower(*acao);
        if (v == "*" || v == "null") {
            out.findings.push_back(make_finding(
                host, port, "Permissive CORS policy", Severity::Low,
                "Access-Control-Allow-Origin is '" + v +
                    "', which authorizes arbitrary origins to read the "
                    "response. Any website the victim visits can read data "
                    "from this endpoint.",
                "Access-Control-Allow-Origin: " + *acao));
        }
    }

    // Cookie flags: session cookies without Secure/HttpOnly/SameSite.
    // (The header map keeps only the last Set-Cookie of a response — a known
    // simplification; the first session cookie is usually the interesting
    // one.)
    if (auto cookie = resp.header("set-cookie")) {
        std::string v = ascii_lower(*cookie);
        std::vector<std::string> missing;
        if (v.find("httponly") == std::string::npos)
            missing.push_back("HttpOnly");
        if (v.find("secure") == std::string::npos)
            missing.push_back("Secure");
        if (v.find("samesite") == std::string::npos)
            missing.push_back("SameSite");
        if (!missing.empty()) {
            std::string list;
            for (size_t i = 0; i < missing.size(); ++i)
                list += (i ? ", " : "") + missing[i];
            out.findings.push_back(make_finding(
                host, port, "Session cookie without protective flags",
                Severity::Low,
                "The Set-Cookie response lacks the " + list +
                    " attribute(s): the cookie is readable from script / "
                    "sent over cleartext / exposed to cross-site requests.",
                "Set-Cookie: " + *cookie));
        }
    }

    return out;
}

} // namespace sln
