#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include "sleipnir/checks.hpp"
#include "sleipnir/crawler.hpp"
#include "sleipnir/http_client.hpp"
#include "sleipnir/cve_db.hpp"
#include "sleipnir/fuzz.hpp"
#include "sleipnir/syn_scan.hpp"
#include "sleipnir/targets.hpp"
#include "sleipnir/types.hpp"
#include "sleipnir/udp_scan.hpp"
#include "sleipnir/version.hpp"

#include <algorithm>
#include <cstdio>
#include <fstream>
#include <map>

using namespace sln;

TEST_CASE("version parsing and ordering") {
    CHECK(version_compare("8.4p1", "9.8p1") < 0);
    CHECK(version_compare("9.8p1", "9.8") > 0);   // p1 is a sub-version
    CHECK(version_compare("2.3.4", "2.3.4") == 0);
    CHECK(version_compare("2.4.49", "2.4.5") > 0);
    CHECK(version_compare("1.21.0", "1.3.0") > 0);
    CHECK(version_compare("2.4.49 (Unix)", "2.4.50") < 0);
    CHECK(version_compare("", "1.0") > 0);        // unknown > known
    CHECK(version_compare("garbage", "") == 0);   // both unknown
}

TEST_CASE("constraint evaluation via CveDb::match") {
    // write a tiny DB and match against it
    const char* path = "/tmp/sleipnir_test_cve.json";
    {
        std::ofstream out(path);
        out << R"({
            "testprod": {
                "product": "TestProd",
                "aliases": ["testprod"],
                "vulns": [
                    {"cve": "CVE-1000-0001", "affected": "<9.8p1", "cvss": 9.0},
                    {"cve": "CVE-1000-0002", "affected": "==2.3.4", "cvss": 5.0},
                    {"cve": "CVE-1000-0003", "affected": ">=1.0 <2.0", "cvss": 3.0}
                ]
            }
        })";
    }
    auto db = CveDb::load(path);
    std::remove(path);

    auto v1 = db.match("h", 1, "TestProd", "9.6p1");
    REQUIRE(v1.size() == 1);
    CHECK(v1[0].cve == "CVE-1000-0001");

    CHECK(db.match("h", 1, "TestProd", "9.8p1").empty());
    CHECK(db.match("h", 1, "TestProd", "10.0").empty());

    auto v2 = db.match("h", 1, "testprod", "2.3.4"); // alias, lowercase
    REQUIRE(v2.size() == 2); // "<9.8p1" and "==2.3.4" both hold
    bool has_exact = false;
    for (const auto& f : v2)
        if (f.cve == "CVE-1000-0002") has_exact = true;
    CHECK(has_exact);

    auto v3 = db.match("h", 1, "TestProd", "1.5");
    REQUIRE(v3.size() == 2); // "<9.8p1" and ">=1.0 <2.0" both hold

    // version disclosed in the banner but not in DB -> no match
    CHECK(db.match("h", 1, "OtherProd", "1.0").empty());
    CHECK(db.match("h", 1, "", "1.0").empty());
}

TEST_CASE("port spec expansion") {
    auto p = expand_ports("80,443");
    CHECK(p.size() == 2);
    CHECK(p[0] == 80);
    CHECK(p[1] == 443);

    p = expand_ports("100-103");
    CHECK(p.size() == 4);

    CHECK_THROWS_AS(expand_ports("70000"), std::runtime_error);
    CHECK_THROWS_AS(expand_ports("50-30"), std::runtime_error);
    CHECK_THROWS_AS(expand_ports(""), std::runtime_error);
}

TEST_CASE("fuzz payload builder") {
    auto payloads = build_fuzz_payloads(8192);
    CHECK(payloads.size() >= 8);
    for (const auto& p : payloads) {
        CHECK(p.size() <= 65536u);
        CHECK(p.size() <= static_cast<size_t>(8192)); // max_len caps sizes
    }

    // the 64 KiB overflow-style payload appears only when allowed
    bool has_big = false;
    for (const auto& p : build_fuzz_payloads(65536))
        if (p.size() == 65536) has_big = true;
    CHECK(has_big);

    // max_len caps the payload sizes
    for (const auto& p : build_fuzz_payloads(512))
        CHECK(p.size() <= 512u);
}

TEST_CASE("target expansion handles literals") {
    auto hosts = expand_targets({"127.0.0.1"});
    CHECK(hosts.size() == 1);
    CHECK(hosts[0] == "127.0.0.1");

    // /30 network contains 4 addresses
    CHECK(expand_targets({"192.168.100.4/30"}).size() == 4);

    CHECK_THROWS_AS(expand_targets({"300.300.300.300"}), std::runtime_error);
    CHECK_THROWS_AS(expand_targets({"10.0.0.0/33"}), std::runtime_error);
}

TEST_CASE("parse_version extracts dotted components") {
    auto v = parse_version("8.4p1");
    REQUIRE(v.parts.size() == 3);
    CHECK(v.parts[0] == 8);
    CHECK(v.parts[1] == 4);
    CHECK(v.parts[2] == 1);

    CHECK_FALSE(parse_version("").valid());
    CHECK_FALSE(parse_version("garbage").valid());
    CHECK(parse_version("2.4.49 (Unix)").parts.size() == 3);
}

TEST_CASE("severity helpers round-trip") {
    CHECK(std::string(severity_name(Severity::Critical)) == "critical");
    CHECK(severity_from_string("HIGH") == Severity::Info); // case-sensitive by design
    CHECK(severity_from_string("high") == Severity::High);
    CHECK(severity_from_string("nonsense") == Severity::Info);
    CHECK(severity_rank(Severity::Critical) > severity_rank(Severity::Low));
}

TEST_CASE("check_root_response flags misconfigurations") {
    HttpResponse resp;
    resp.status = 200;
    resp.headers["server"] = "Apache/2.4.49 (Unix)";
    resp.body = "<html><title>Index of /</title></html>";

    auto out = check_root_response("h", 80, resp);
    REQUIRE(out.findings.size() == 5); // version + dirlist + 3 missing headers
    CHECK(out.server_product == "Apache");
    CHECK(out.server_version == "2.4.49");

    bool has_dirlist = false, has_version = false;
    for (const auto& f : out.findings) {
        if (f.title == "Directory listing enabled") has_dirlist = true;
        if (f.title == "Server version disclosed in HTTP header")
            has_version = true;
    }
    CHECK(has_dirlist);
    CHECK(has_version);

    // a well-configured response with a versionless Server header
    HttpResponse clean;
    clean.status = 200;
    clean.headers["server"] = "nginx";
    clean.headers["content-security-policy"] = "default-src 'self'";
    clean.headers["x-content-type-options"] = "nosniff";
    clean.headers["x-frame-options"] = "DENY";
    clean.body = "<html>hello</html>";
    auto out2 = check_root_response("h", 80, clean);
    CHECK(out2.findings.empty());
    CHECK(out2.server_version.empty());
}

TEST_CASE("tech stack collects Server and X-Powered-By products") {
    HttpResponse resp;
    resp.status = 200;
    resp.headers["server"] = "nginx/1.18.0";
    resp.headers["x-powered-by"] = "PHP/7.2.24";

    auto out = check_root_response("h", 80, resp);
    // nginx + PHP: both go through CVE matching
    REQUIRE(out.tech_stack.size() == 2);
    CHECK(out.tech_stack[0].first == "nginx");
    CHECK(out.tech_stack[0].second == "1.18.0");
    CHECK(out.tech_stack[1].first == "PHP");
    CHECK(out.tech_stack[1].second == "7.2.24");
    CHECK(out.server_product == "nginx"); // Server header wins for display

    bool has_xpb = false;
    for (const auto& f : out.findings)
        if (f.title == "Backend technology disclosed via X-Powered-By")
            has_xpb = true;
    CHECK(has_xpb);

    // no Server header: X-Powered-By product is used for display too
    HttpResponse resp2;
    resp2.status = 200;
    resp2.headers["x-powered-by"] = "PHP/8.1.0";
    auto out2 = check_root_response("h", 80, resp2);
    CHECK(out2.server_product == "PHP");
    CHECK(out2.server_version == "8.1.0");
}

TEST_CASE("web app probe classifiers are strict") {
    // real database driver messages match
    CHECK(looks_like_sql_error(
        "{\"errors\":[{\"message\":\"SQLITE_ERROR: near \\\")\\\": syntax"
        " error\"}]}"));
    CHECK(looks_like_sql_error("Warning: sqlite3.query(): no such column"));
    CHECK(looks_like_sql_error("ORA-00942: table or view does not exist"));
    CHECK(looks_like_sql_error("You have an error in your SQL syntax; check"));
    CHECK(looks_like_sql_error("psql: ERROR: syntax error at or near \"'\""));

    // generic error pages do not
    CHECK_FALSE(looks_like_sql_error("<html><body><h1>500 Internal Server "
                                     "Error</h1></body></html>"));
    CHECK_FALSE(looks_like_sql_error("{\"message\":\"invalid request\"}"));

    CHECK(graphql_introspection_reply(
        "{\"data\":{\"__schema\":{\"types\":[{\"name\":\"Query\"}]}}}"));
    CHECK_FALSE(
        graphql_introspection_reply("{\"errors\":[{\"message\":\"GET query"
                                    " missing.\"}]}"));
}

TEST_CASE("html link and form extraction") {
    const std::string html =
        "<a href='/docs/guide.html'>Guide</a>"
        "<A HREF=\"/contact\">Contact</A>"
        "<a href=\"javascript:void(0)\">noop</a>"
        "<a href='#top'>anchor</a>"
        "<a href='mailto:x@y.z'>mail</a>"
        "<a href=\"https://other.example.org/away\">out</a>"
        "<img src='x.png'>"
        "<a href=blog/post.php?month=5>unquoted</a>";

    auto links = extract_links(html);
    // raw extraction: every href comes back, unusable ones are filtered by
    // resolve_url at crawl time
    REQUIRE(links.size() == 7);
    CHECK(links[0] == "/docs/guide.html");
    CHECK(links[1] == "/contact");
    CHECK(links[5] == "https://other.example.org/away");
    CHECK(links[6] == "blog/post.php?month=5");
    // unusable schemes/fragments are dropped during resolution
    CHECK(resolve_url("/", links[2]).empty()); // javascript:
    CHECK(resolve_url("/", links[3]).empty()); // #frag
    CHECK(resolve_url("/", links[4]).empty()); // mailto:
}

TEST_CASE("url resolution handles relative and dot segments") {
    CHECK(resolve_url("/a/b/c.html", "d.html") == "/a/b/d.html");
    CHECK(resolve_url("/a/b/c.html", "../x/y") == "/a/x/y");
    CHECK(resolve_url("/a/b/", "c") == "/a/b/c");
    CHECK(resolve_url("/a/b/c.html", "/root.html") == "/root.html");
    CHECK(resolve_url("/a/b/c.html", "?tab=2") == "/a/b/c.html?tab=2");
    CHECK(resolve_url("/a/b/c.html", "/x/../y") == "/y");
    CHECK(resolve_url("/a/", "javascript:alert(1)").empty());
    CHECK(resolve_url("/a/", "#frag").empty());
    CHECK(resolve_url("/a/", "mailto:a@b.c").empty());
    // absolute URLs pass through for the caller's scope check
    CHECK(resolve_url("/a/", "https://x.example/p") == "https://x.example/p");
}

TEST_CASE("form extraction finds fields and CSRF tokens") {
    const std::string html =
        "<form action='/login' method='POST'>"
        "<input type='text' name='user'>"
        "<input type='password' name='pass'>"
        "<input type='hidden' name='csrf_token' value='abc'>"
        "<button>Go</button></form>"
        "<form action='/comment'>"
        "<input name='body'>"
        "</form>"
        "<form action='/search' method='get'>"
        "<select name='cat'><option>1</option></select>"
        "</form>";

    auto forms = extract_forms(html);
    REQUIRE(forms.size() == 3);

    CHECK(forms[0].method == "POST");
    CHECK(forms[0].action == "/login");
    CHECK(forms[0].fields.size() == 3);
    CHECK(forms[0].has_csrf_token);

    CHECK(forms[1].method == "GET"); // default
    CHECK(forms[1].fields.size() == 1);
    CHECK_FALSE(forms[1].has_csrf_token);

    CHECK(forms[2].fields.size() == 1);
    CHECK(forms[2].fields[0].first == "cat");
}

TEST_CASE("crawler maps a site graph within scope and depth") {
    std::map<std::string, HttpResponse> pages;
    auto body = [](std::string b) {
        HttpResponse r;
        r.status = 200;
        r.body = std::move(b);
        r.headers["content-type"] = "text/html";
        return r;
    };
    pages["/"] = body(
        "<a href='/a'>A</a><a href='/missing'>M</a>"
        "<a href='https://external.example.org/x'>Out</a>"
        "<form action='/login' method='POST'><input name='user'>"
        "<input name='pass'></form>"
        "<form action='/search' method='GET'><input name='q'></form>");
    pages["/a"] = body("<a href='/b'>B</a>");
    pages["/b"] = body("<a href='/deep/x'>Deep</a>");
    pages["/deep/x"] = body("<a href='/never'>N</a>"); // depth 3 > max_depth 2
    pages["/login"] = body("login page");
    pages["/search?q="] = body("results");

    HttpFetcher fetch = [&](const std::string& p) -> std::optional<HttpResponse> {
        auto it = pages.find(p);
        return it == pages.end() ? std::nullopt : std::optional(it->second);
    };

    CrawlConfig cfg;
    cfg.max_pages = 20;
    cfg.max_depth = 2;
    cfg.scheme = "http";
    cfg.host = "testhost";
    cfg.port = 80;
    auto r = crawl_site(fetch, "/", cfg);

    auto has_page = [&](const std::string& p) {
        return std::find(r.pages.begin(), r.pages.end(), p) != r.pages.end();
    };
    CHECK(has_page("/"));
    CHECK(has_page("/a"));
    CHECK(has_page("/b"));
    CHECK_FALSE(has_page("/deep/x")); // beyond depth
    CHECK_FALSE(has_page("/never"));

    // external absolute link skipped, both forms captured (GET form also
    // becomes a parameterized URL for the probe budget)
    REQUIRE(r.forms.size() == 2);
    CHECK(r.forms[0].method == "POST");
    CHECK(r.forms[0].action_path == "/login");
    CHECK_FALSE(r.forms[0].has_csrf_token);

    bool has_search = false;
    for (const auto& u : r.param_urls)
        if (u.rfind("/search", 0) == 0) has_search = true;
    CHECK(has_search);
}

TEST_CASE("active web probes report xss, csrf and traversal") {
    std::map<std::string, HttpResponse> pages;
    auto mk = [](std::string b, const char* ctype = "text/html",
                 int status = 200) {
        HttpResponse r;
        r.status = status;
        r.body = std::move(b);
        r.headers["content-type"] = ctype;
        return r;
    };
    // raw reflection -> XSS finding
    pages["/search?q="] = mk("Results for: <b>INPUT</b>");
    // encoded reflection -> no finding
    pages["/safe?q="] = mk("Results for: &lt;svg/onload=alert(1)&gt;");
    // JSON endpoint reflecting -> no finding (not an HTML context)
    pages["/api/search?q="] = mk("{\"q\":\"INPUT\"}", "application/json");
    // traversal marker
    pages["/profile?page="] = mk("root:x:0:0:0:root:/root:/bin/bash");
    // open redirect
    {
        HttpResponse r = mk("", "text/plain", 302);
        r.headers["location"] = "https://sln-open-redirect-probe.invalid/";
        pages["/redirect?to="] = r;
    }

    CrawlResult crawl;
    crawl.param_urls = {"/search?q=hello", "/safe?q=x", "/api/search?q=x",
                        "/profile?page=1", "/redirect?to=%2Fhome"};
    crawl.forms = {CrawlForm{"/login", "POST",
                             {{"user", ""}, {"pass", ""}}, false},
                   CrawlForm{"/logout", "POST", {{"csrf", "x"}}, true}};

    HttpFetcher fetch = [&](const std::string& p) -> std::optional<HttpResponse> {
        // substitute the probe payload so the reflection sites match
        std::string key = p;
        if (key.find("/search?") == 0)
            return pages["/search?q="].body.find("INPUT") != std::string::npos
                       ? mk("Results for: <b>" + p + "</b>")
                       : pages["/search?q="];
        if (key.find("/safe?") == 0) return pages["/safe?q="];
        if (key.find("/api/search?") == 0) return pages["/api/search?q="];
        if (key.find("/profile?") == 0) return pages["/profile?page="];
        if (key.find("/redirect?") == 0) return pages["/redirect?to="];
        auto it = pages.find(key);
        return it == pages.end() ? std::nullopt : std::optional(it->second);
    };

    ActiveProbeConfig apc;
    apc.max_requests = 50;
    auto out = check_crawled_app(fetch, crawl, "h", 80, apc);

    bool has_xss = false, has_csrf = false, has_traversal = false,
         has_redirect = false, no_false_xss = true;
    for (const auto& f : out) {
        if (f.title.find("Reflected input in HTML context") == 0 &&
            f.port == 80 && f.evidence.find("/search") != std::string::npos)
            has_xss = true;
        if (f.title.find("Reflected") == 0 &&
            f.evidence.find("/safe") != std::string::npos)
            no_false_xss = false;
        if (f.title == "POST form without CSRF protection") has_csrf = true;
        if (f.title == "Possible path traversal in file parameter")
            has_traversal = true;
        if (f.title == "Open redirect in navigation parameter")
            has_redirect = true;
    }
    CHECK(has_xss);
    CHECK(no_false_xss);
    CHECK(has_csrf);
    CHECK(has_traversal);
    CHECK(has_redirect);
}

TEST_CASE("http response header keys are lowercased for lookup") {
    HttpResponse resp;
    resp.headers["Content-Type"] = "text/html"; // simulate raw insertion
    // real http_get lowercases; the accessor requires the lowercase key
    CHECK(resp.header("content-type") == nullptr);
    resp.headers["content-type"] = "text/html";
    CHECK(resp.header("content-type") != nullptr);
}

TEST_CASE("chunked transfer decoding") {
    // single chunk
    CHECK(decode_chunked("5\r\nhello\r\n0\r\n\r\n") == "hello");

    // several chunks, reassembled in order
    CHECK(decode_chunked("3\r\nabc\r\n3\r\ndef\r\n0\r\n\r\n") == "abcdef");

    // uppercase hex and chunk-size extensions (";name=value")
    CHECK(decode_chunked("A; q=1\r\n0123456789\r\n0\r\n\r\n") ==
          "0123456789");

    // empty body
    CHECK(decode_chunked("0\r\n\r\n").empty());

    // trailer section after the last chunk is dropped
    CHECK(decode_chunked("2\r\nhi\r\n0\r\nX-Trailer: v\r\n\r\n") == "hi");

    // truncated stream: keep whatever arrived
    CHECK(decode_chunked("5\r\nhe") == "he");
}

TEST_CASE("target expansion handles IPv6 literals and brackets") {
    // bare v6 literal passes through
    auto hosts = expand_targets({"::1"});
    REQUIRE(hosts.size() == 1);
    CHECK(hosts[0] == "::1");

    // URL-style bracketed form loses the brackets
    CHECK(expand_targets({"[2001:db8::1]"})[0] == "2001:db8::1");

    // a path after the bracketed host is dropped, scheme too
    CHECK(expand_targets({"http://[::1]/admin"})[0] == "::1");
}

TEST_CASE("target expansion handles IPv6 CIDR") {
    // /126 spans exactly 4 addresses, network bits preserved
    auto net = expand_targets({"2001:db8::/126"});
    REQUIRE(net.size() == 4);
    CHECK(net[0] == "2001:db8::");
    CHECK(net[1] == "2001:db8::1");
    CHECK(net[2] == "2001:db8::2");
    CHECK(net[3] == "2001:db8::3");

    // /128 is a single address written as a range
    auto single = expand_targets({"::1/128"});
    REQUIRE(single.size() == 1);
    CHECK(single[0] == "::1");

    // v4 and v6 targets mix in one sorted, deduplicated list
    auto mixed = expand_targets({"10.0.0.1", "::1", "10.0.0.1"});
    REQUIRE(mixed.size() == 2);
    CHECK(mixed[0] == "10.0.0.1");
    CHECK(mixed[1] == "::1");

    CHECK_THROWS_AS(expand_targets({"::1/129"}), std::runtime_error);
    // wider than /64 would span more than 2^64 hosts
    CHECK_THROWS_AS(expand_targets({"2001:db8::/63"}), std::runtime_error);
}

TEST_CASE("port status names cover every state") {
    CHECK(std::string(status_name(PortStatus::Open)) == "open");
    CHECK(std::string(status_name(PortStatus::Closed)) == "closed");
    CHECK(std::string(status_name(PortStatus::Filtered)) == "filtered");
}

TEST_CASE("timing profiles and clamping") {
    auto t0 = timing_profile(0);
    CHECK(t0.delay_ms == 400);
    CHECK(t0.timeout_ms == 10000);
    CHECK(t0.max_threads == 8);

    auto t3 = timing_profile(3);
    CHECK(t3.delay_ms == 0);
    CHECK(t3.timeout_ms == 2500);
    CHECK(t3.max_threads == 64);

    auto t5 = timing_profile(5);
    CHECK(t5.timeout_ms < t3.timeout_ms);
    CHECK(t5.max_threads > t3.max_threads);

    // out-of-range profiles clamp to normal (-T3)
    CHECK(timing_profile(9).delay_ms == t3.delay_ms);
    CHECK(timing_profile(-1).timeout_ms == t3.timeout_ms);
}

TEST_CASE("ones-complement checksum (RFC 1071)") {
    const uint8_t zeros2[] = {0, 0};
    CHECK(ones_complement_checksum(zeros2, 2) == 0xffff);

    // hand-computed: 0x0001 + 0xf203 = 0xf204 -> ~0xf204 = 0x0dfb
    const uint8_t v[] = {0x00, 0x01, 0xf2, 0x03};
    CHECK(ones_complement_checksum(v, 4) == 0x0dfb);

    // odd length: the trailing byte is padded into the high position
    const uint8_t odd[] = {0x01, 0x02, 0x03};
    CHECK(ones_complement_checksum(odd, 3) == 0xfbfd);

    // RFC 1071 property: data + its checksum sums to zero
    std::vector<uint8_t> msg(32);
    for (size_t i = 0; i < msg.size(); ++i)
        msg[i] = static_cast<uint8_t>(i * 7);
    uint16_t c = ones_complement_checksum(msg.data(), msg.size());
    msg.push_back(static_cast<uint8_t>(c >> 8));
    msg.push_back(static_cast<uint8_t>(c & 0xff));
    CHECK(ones_complement_checksum(msg.data(), msg.size()) == 0);
}

TEST_CASE("SYN reply classification by TCP flags") {
    CHECK(syn_status_from_flags(kTcpSyn | kTcpAck) == PortStatus::Open);
    CHECK(syn_status_from_flags(kTcpSyn) == PortStatus::Filtered);
    CHECK(syn_status_from_flags(kTcpRst) == PortStatus::Closed);
    CHECK(syn_status_from_flags(kTcpRst | kTcpAck) == PortStatus::Closed);
    CHECK(syn_status_from_flags(0) == PortStatus::Filtered);
    CHECK(syn_status_from_flags(kTcpFin | kTcpPsh) == PortStatus::Filtered);
}

TEST_CASE("UDP probe table") {
    const UdpProbe* snmp = udp_probe_for(161);
    REQUIRE(snmp != nullptr);
    CHECK(std::string(snmp->service) == "snmp");
    // community string "public" is embedded in the payload
    CHECK(std::string(snmp->payload_hex).find("7075626c6963") !=
          std::string::npos);

    CHECK(udp_probe_for(11211) != nullptr);
    CHECK(udp_probe_for(1) == nullptr);
}

TEST_CASE("UDP reply classification") {
    // DNS/mDNS: QR bit set in the flags word
    std::string dns_resp = std::string("\x00\x01\x81\x80", 4);
    CHECK(udp_classify(53, dns_resp) == "domain");
    CHECK(udp_classify(5353, dns_resp) == "mdns");
    // a query (QR=0) is not a service reply
    CHECK(udp_classify(53, std::string("\x00\x01\x01\x00", 4)).empty());

    // NTP: 48-byte server reply, mode 4
    std::string ntp(48, '\0');
    ntp[0] = 0x24; // LI=0, VN=4, Mode=4
    CHECK(udp_classify(123, ntp) == "ntp");
    CHECK(udp_classify(123, std::string(40, '\0')).empty()); // too short

    // SNMP: BER SEQUENCE tag
    CHECK(udp_classify(161, std::string("\x30\x29\x02\x01\x00", 5)) == "snmp");
    CHECK(udp_classify(162, std::string("\x30\x00", 2)) == "snmp");

    // TFTP: opcode 3 (DATA) in the first two bytes
    CHECK(udp_classify(69, std::string("\x00\x03\x00\x01", 4)) == "tftp");
    CHECK(udp_classify(69, std::string("\x00\x42", 2)).empty());

    // SSDP: HTTP-shaped reply
    CHECK(udp_classify(1900, "HTTP/1.1 200 OK\r\nST: upnp:rootdevice\r\n") ==
          "ssdp");
    CHECK(udp_classify(1900, "not http").empty());

    // memcached: 8-byte UDP frame header + VERSION
    CHECK(udp_classify(11211, std::string(8, '\0') + "VERSION 1.6.0\r\n") ==
          "memcached");
    CHECK(udp_classify(11211, std::string(8, '\0') + "bogus").empty());

    // reply-shape catch-alls
    CHECK(udp_classify(137, "any reply") == "netbios-ns");
    CHECK(udp_classify(500, "any reply") == "isakmp");
    CHECK(udp_classify(4500, "any reply") == "isakmp");
    CHECK(udp_classify(514, "any reply") == "syslog");
    CHECK(udp_classify(1701, "any reply") == "l2tp");

    // empty reply and ports with no expectations
    CHECK(udp_classify(53, "").empty());
    CHECK(udp_classify(8080, "whatever").empty());
}
