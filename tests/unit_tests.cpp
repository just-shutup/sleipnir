#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include "sleipnir/checks.hpp"
#include "sleipnir/http_client.hpp"
#include "sleipnir/cve_db.hpp"
#include "sleipnir/fuzz.hpp"
#include "sleipnir/targets.hpp"
#include "sleipnir/version.hpp"

#include <cstdio>
#include <fstream>

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
