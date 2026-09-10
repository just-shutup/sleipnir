// Authenticated scanning (--auth FILE).
//
// establish_auth_session() turns the parsed AuthConfig into a set of HTTP
// headers: a static Authorization header (basic), a literal or Netscape-jar
// Cookie header, or a form login performed once (fields POSTed to the login
// URL, success marker checked, Set-Cookie collected).
//
// AuthStream is a transparent transport wrapper that injects those headers
// into every request right before the blank line ending the header block.
// All templated HTTP helpers (http_get, checks, crawler, verification) work
// unchanged over it — the session simply rides along.
#pragma once

#include "sleipnir/netio.hpp"
#include "sleipnir/types.hpp"

#include <asio.hpp>

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace sln {

class ResultCollector;

// True when the configured credentials apply to this scan target (scope
// list empty or "*" means everywhere).
bool auth_applies(const AuthConfig& auth, const std::string& scan_host);

// standard base64 (RFC 4648) for the Basic scheme
std::string base64_encode(const std::string& in);

// Establishes the session described by auth. Returns the headers to attach
// to every request, or an empty vector on failure (already logged). Only
// the form method performs network I/O — exactly one POST to the login URL.
std::vector<std::pair<std::string, std::string>> establish_auth_session(
    asio::io_context& io, const AuthConfig& auth, const std::string& scan_host,
    int timeout_ms, const std::string& user_agent, ResultCollector& out);

// Parses "scheme://host[:port]/path" into its parts; nullopt on garbage.
struct AuthTarget {
    std::string scheme; // "http" | "https"
    std::string host;
    std::string path;
    uint16_t port = 80;
};
std::optional<AuthTarget> parse_auth_url(const std::string& url);

// Parses a Netscape cookie jar (one "name=value" per non-comment line with
// tab-separated fields; #HttpOnly_ prefixes honoured) into a Cookie header
// value. Returns "" when the file has no usable cookies.
std::string cookie_jar_header(const std::string& file_path);

// Transport adapter carrying the session headers. Injects them into every
// outgoing request just before the terminating blank line, so body-less and
// bodied requests (verification probes) are handled alike.
template <typename Stream>
class AuthStream {
public:
    AuthStream(Stream& inner,
               std::vector<std::pair<std::string, std::string>> headers)
        : inner_(inner), headers_(std::move(headers)) {}

    bool connect(const std::string& host, uint16_t port, int timeout_ms) {
        return inner_.connect(host, port, timeout_ms);
    }
    bool is_open() const { return inner_.is_open(); }
    void close() { inner_.close(); }
    std::string send_and_receive(std::string_view payload, int wait_ms,
                                 size_t max_bytes) {
        std::string req(payload);
        if (!headers_.empty()) {
            // The request always ends its header block with
            // "...last-header\r\n\r\n"; inject after that first CRLF so the
            // session headers land inside the block, before the blank line.
            size_t sep = req.find("\r\n\r\n");
            if (sep != std::string::npos) {
                std::string injected;
                for (const auto& [name, value] : headers_)
                    injected += name + ": " + value + "\r\n";
                req.insert(sep + 2, injected);
            }
        }
        return inner_.send_and_receive(req, wait_ms, max_bytes);
    }

private:
    Stream& inner_;
    std::vector<std::pair<std::string, std::string>> headers_;
};

} // namespace sln
