// Minimal HTTP/1.1 GET client built on the TcpClient/TlsClient transports.
// Uses "Connection: close" and reads the whole response until EOF, so the
// body is complete even for servers that ignore the request's Connection
// preference. Chunked transfer coding is decoded transparently.
//
// The transport is a template parameter: any type providing
//   bool connect(host, port, timeout_ms);
//   std::string send_and_receive(payload, wait_ms, max_bytes);
// works — currently TcpClient (plain) and TlsClient (TLS).
#pragma once

#include "sleipnir/netio.hpp"

#include <cctype>
#include <map>
#include <optional>
#include <string>

namespace sln {

struct HttpResponse {
    int status = 0;
    std::string status_line;
    std::map<std::string, std::string> headers; // keys lowercased
    std::string body;

    const std::string* header(const std::string& lower_key) const;
};

// Decodes a chunked transfer-coded payload into the original content.
std::string decode_chunked(const std::string& in);

namespace detail {

inline std::string ascii_lower(std::string s) {
    for (char& c : s)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

// Parses a raw HTTP/1.x response (status line, headers, body incl. chunked
// decoding). Returns nullopt when the bytes are not parseable as HTTP.
inline std::optional<HttpResponse> parse_response(std::string raw) {
    if (raw.empty()) return std::nullopt;

    HttpResponse resp;
    size_t line_end = raw.find("\r\n");
    if (line_end == std::string::npos) return std::nullopt;
    resp.status_line = raw.substr(0, line_end);

    // "HTTP/1.1 200 OK"
    static const std::string version_prefix = "HTTP/";
    if (resp.status_line.rfind(version_prefix, 0) != 0) return std::nullopt;
    size_t sp1 = resp.status_line.find(' ');
    size_t sp2 = (sp1 == std::string::npos)
                     ? std::string::npos
                     : resp.status_line.find(' ', sp1 + 1);
    if (sp1 == std::string::npos || sp2 == std::string::npos) return std::nullopt;
    try {
        resp.status = std::stoi(resp.status_line.substr(sp1 + 1, sp2 - sp1 - 1));
    } catch (...) {
        return std::nullopt;
    }

    size_t pos = line_end + 2;
    size_t header_end = raw.find("\r\n\r\n", pos);
    size_t headers_stop = (header_end == std::string::npos) ? raw.size() : header_end;
    while (pos < headers_stop) {
        size_t eol = raw.find("\r\n", pos);
        if (eol == std::string::npos || eol > headers_stop) eol = headers_stop;
        std::string line = raw.substr(pos, eol - pos);
        pos = eol + 2;
        size_t colon = line.find(':');
        if (colon == std::string::npos) continue;
        std::string key = ascii_lower(line.substr(0, colon));
        size_t val_start = line.find_first_not_of(" \t", colon + 1);
        std::string value = (val_start == std::string::npos)
                                ? ""
                                : line.substr(val_start);
        while (!value.empty() &&
               (value.back() == '\r' || value.back() == ' ' || value.back() == '\t'))
            value.pop_back();
        resp.headers[key] = value;
    }

    if (header_end != std::string::npos) {
        resp.body = raw.substr(header_end + 4);
        if (auto te = resp.header("transfer-encoding");
            te && ascii_lower(*te).find("chunked") != std::string::npos)
            resp.body = decode_chunked(resp.body);
    }
    return resp;
}

template <typename Stream>
std::optional<HttpResponse> http_request_impl(Stream& stream,
                                              const std::string& method,
                                              const std::string& host,
                                              uint16_t port,
                                              const std::string& path,
                                              int timeout_ms,
                                              const std::string& user_agent) {
    if (!stream.connect(host, port, timeout_ms)) return std::nullopt;

    std::string host_header =
        host + ((port == 80) ? "" : ":" + std::to_string(port));
    std::string req = method + " " + (path.empty() ? "/" : path) +
                      " HTTP/1.1\r\n"
                      "Host: " + host_header + "\r\n"
                      "User-Agent: " + user_agent + "\r\n"
                      "Accept: */*\r\n"
                      "Connection: close\r\n\r\n";

    // The server closes the connection after answering (Connection: close),
    // so recv until EOF captures the entire message.
    std::string raw = stream.send_and_receive(req, timeout_ms + 1000, 4 << 20);
    return parse_response(std::move(raw));
}

} // namespace detail

// Performs GET http://host:port/path. Returns nullopt on any failure.
// Template overload accepts any transport (TlsClient, test doubles, ...);
// the non-template TcpClient overload below is preferred for plain TCP.
template <typename Stream>
std::optional<HttpResponse> http_get(
    Stream& stream, const std::string& host, uint16_t port,
    const std::string& path, int timeout_ms,
    const std::string& user_agent = "Sleipnir/0.1 (vulnerability scanner)") {
    return detail::http_request_impl(stream, "GET", host, port, path,
                                     timeout_ms, user_agent);
}

inline std::optional<HttpResponse> http_get(
    TcpClient& client, const std::string& host, uint16_t port,
    const std::string& path, int timeout_ms,
    const std::string& user_agent = "Sleipnir/0.1 (vulnerability scanner)") {
    return detail::http_request_impl(client, "GET", host, port, path,
                                     timeout_ms, user_agent);
}

// Arbitrary-method request (TRACE, OPTIONS, ...), same semantics as http_get.
template <typename Stream>
std::optional<HttpResponse> http_request(
    Stream& stream, const std::string& method, const std::string& host,
    uint16_t port, const std::string& path, int timeout_ms,
    const std::string& user_agent = "Sleipnir/0.1 (vulnerability scanner)") {
    return detail::http_request_impl(stream, method, host, port, path,
                                     timeout_ms, user_agent);
}

} // namespace sln
