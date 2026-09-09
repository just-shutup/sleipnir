// TLS client for HTTPS and SSL/TLS service inspection. Mirrors the TcpClient
// interface (connect / send / recv_all / send_and_receive / close) so the
// HTTP client and check code work unchanged over either transport.
//
// Built only when OpenSSL development files are present (SLEIPNIR_HAVE_TLS).
// The peer certificate is collected but not enforced: the scanner needs to
// inspect self-signed and otherwise untrusted targets, so verification
// results are recorded and reported as findings instead of aborting the
// handshake.
#pragma once

#include "sleipnir/netio.hpp"

#include <asio.hpp>

#include <string>
#include <vector>

#ifdef SLEIPNIR_HAVE_TLS

#include <asio/ssl.hpp>

namespace sln {

// Raw handshake/certificate facts as observed by OpenSSL.
struct TlsPeerInfo {
    bool handshake_ok = false;
    std::string protocol;      // negotiated protocol, e.g. "TLSv1.2"
    std::string cipher;        // negotiated cipher name
    std::string subject;
    std::string issuer;
    std::string common_name;
    std::vector<std::string> san_dns;
    std::string not_before;    // "YYYY-MM-DD HH:MM:SSZ"
    std::string not_after;
    long long not_before_epoch = 0;
    long long not_after_epoch = 0;
    bool chain_trusted = true; // OpenSSL X509_V_OK
    long verify_error = 0;     // X509_V_ERR_* code when untrusted
    std::string verify_error_text;
};

class TlsClient {
public:
    explicit TlsClient(asio::io_context& io);

    // TCP connect + TLS handshake (with SNI for hostname targets).
    bool connect(const std::string& host, uint16_t port, int timeout_ms);

    bool send(std::string_view data);
    std::string recv_all(int total_wait_ms, int idle_gap_ms = 350,
                         size_t max_bytes = 65536);
    std::string send_and_receive(std::string_view payload, int wait_ms,
                                 size_t max_bytes = 1 << 20);
    void close();
    bool is_open() const;

    const TlsPeerInfo& peer() const { return peer_; }

private:
    void run_round();

    asio::io_context& io_;
    asio::ssl::context ctx_;
    std::optional<asio::ssl::stream<asio::ip::tcp::socket>> stream_;
    TlsPeerInfo peer_;
};

} // namespace sln

#endif // SLEIPNIR_HAVE_TLS
