#include "sleipnir/tls_client.hpp"

#ifdef SLEIPNIR_HAVE_TLS

#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <chrono>

namespace sln {

namespace {

// Days-from-civil (Howard Hinnant's algorithm): portable UTC epoch from a
// calendar date, no platform-specific timegm/_mkgmtime needed.
long long epoch_from_tm(const struct tm& t) {
    long long y = t.tm_year + 1900;
    unsigned m = static_cast<unsigned>(t.tm_mon + 1);
    unsigned d = static_cast<unsigned>(t.tm_mday);
    y -= m <= 2;
    long long era = (y >= 0 ? y : y - 399) / 400;
    unsigned yoe = static_cast<unsigned>(y - era * 400);
    unsigned doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    long long days = era * 146097 + static_cast<long long>(doe) - 719468;
    return days * 86400 + t.tm_hour * 3600 + t.tm_min * 60 + t.tm_sec;
}

std::string format_tm(const struct tm& t) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%04d-%02d-%02d %02d:%02d:%02dZ",
                  t.tm_year + 1900, t.tm_mon + 1, t.tm_mday, t.tm_hour,
                  t.tm_min, t.tm_sec);
    return buf;
}

#if OPENSSL_VERSION_NUMBER < 0x1010100fL
// Pre-1.1.1 fallback: parse the ASN.1 time string minimally ("YYMMDDHHMMSSZ").
bool asn1_time_to_tm_fallback(const ASN1_TIME* at, struct tm& out) {
    if (!at || at->length < 13) return false;
    auto two = [&](int off) {
        return (at->data[off] - '0') * 10 + (at->data[off + 1] - '0');
    };
    int year = two(0) * 100 + two(2);
    if (at->type == V_ASN1_UTCTIME) year += year < 50 ? 2000 : 1900;
    out.tm_year = year - 1900;
    out.tm_mon = two(4) - 1;
    out.tm_mday = two(6);
    out.tm_hour = two(8);
    out.tm_min = two(10);
    out.tm_sec = two(12);
    return true;
}
#define ASN1_TIME_TO_TM(at, out) asn1_time_to_tm_fallback((at), (out))
#else
#define ASN1_TIME_TO_TM(at, out) (ASN1_TIME_to_tm((at), &(out)) == 1)
#endif

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
auto peer_certificate(SSL* ssl) { return SSL_get1_peer_certificate(ssl); }
#else
auto peer_certificate(SSL* ssl) { return SSL_get_peer_certificate(ssl); }
#endif

// Collects everything the report layer needs from the negotiated session.
TlsPeerInfo extract_peer(SSL* ssl) {
    TlsPeerInfo info;
    info.handshake_ok = true;
    info.protocol = SSL_get_version(ssl);
    if (auto* cipher = SSL_get_current_cipher(ssl)) {
        info.cipher = SSL_CIPHER_get_name(cipher);
    }

    long err = SSL_get_verify_result(ssl);
    info.verify_error = err;
    info.chain_trusted = (err == X509_V_OK);
    if (!info.chain_trusted)
        info.verify_error_text = X509_verify_cert_error_string(err);

    X509* cert = peer_certificate(ssl);
    if (!cert) return info;

    char buf[512];
    X509_NAME* subj = X509_get_subject_name(cert);
    X509_NAME* issuer = X509_get_issuer_name(cert);
    X509_NAME_oneline(subj, buf, sizeof(buf));
    info.subject = buf;
    X509_NAME_oneline(issuer, buf, sizeof(buf));
    info.issuer = buf;

    int cn_len = X509_NAME_get_text_by_NID(subj, NID_commonName, buf,
                                           sizeof(buf));
    if (cn_len > 0) info.common_name.assign(buf, static_cast<size_t>(cn_len));

    if (auto* names = static_cast<STACK_OF(GENERAL_NAME)*>(
            X509_get_ext_d2i(cert, NID_subject_alt_name, nullptr, nullptr))) {
        for (int i = 0; i < sk_GENERAL_NAME_num(names); ++i) {
            GENERAL_NAME* gn = sk_GENERAL_NAME_value(names, i);
            if (gn->type != GEN_DNS) continue;
            ASN1_IA5STRING* s = gn->d.dNSName;
            info.san_dns.emplace_back(
                reinterpret_cast<const char*>(ASN1_STRING_get0_data(s)),
                ASN1_STRING_length(s));
        }
        sk_GENERAL_NAME_pop_free(names, GENERAL_NAME_free);
    }

    struct tm nb{}, na{};
    if (ASN1_TIME_TO_TM(X509_getm_notBefore(cert), nb)) {
        info.not_before = format_tm(nb);
        info.not_before_epoch = epoch_from_tm(nb);
    }
    if (ASN1_TIME_TO_TM(X509_getm_notAfter(cert), na)) {
        info.not_after = format_tm(na);
        info.not_after_epoch = epoch_from_tm(na);
    }
    X509_free(cert);
    return info;
}

bool is_ip_literal(const std::string& host) {
    std::error_code ec;
    asio::ip::make_address(host, ec);
    return !ec;
}

} // namespace

TlsClient::TlsClient(asio::io_context& io)
    : io_(io), ctx_(asio::ssl::context::tls_client) {
    // Verification is recorded, not enforced: vulnerability scanners must be
    // able to connect to self-signed / misconfigured endpoints.
    ctx_.set_default_verify_paths();
    ctx_.set_verify_mode(asio::ssl::verify_peer);
}

void TlsClient::run_round() {
    io_.restart();
    io_.run();
}

bool TlsClient::connect(const std::string& host, uint16_t port,
                        int timeout_ms) {
    close();
    peer_ = TlsPeerInfo{};

    TcpClient tcp(io_); // reuse the resolver + connect timeout logic
    if (!tcp.connect(host, port, timeout_ms)) return false;
    asio::ip::tcp::socket raw = tcp.detach(); // takes the connected socket
    if (!raw.is_open()) return false;

    stream_.emplace(std::move(raw), ctx_);
    peer_.handshake_ok = false;

    // SNI only for hostname targets; IP literals do not carry SNI.
    if (!is_ip_literal(host))
        SSL_set_tlsext_host_name(stream_->native_handle(), host.c_str());

    // Record OpenSSL preverification without aborting the handshake.
    stream_->set_verify_callback([&](bool preverified, asio::ssl::verify_context&) {
        return true;
    });

    asio::steady_timer timer(io_);
    timer.expires_after(std::chrono::milliseconds(timeout_ms));
    bool done = false;
    bool ok = false;

    stream_->async_handshake(asio::ssl::stream_base::client,
                             [&](std::error_code ec) {
                                 if (done) return;
                                 done = true;
                                 ok = !ec;
                                 timer.cancel();
                             });
    timer.async_wait([&](std::error_code) {
        if (done) return;
        done = true;
        std::error_code ignored;
        stream_->next_layer().close(ignored);
    });
    run_round();
    if (!ok) {
        stream_.reset();
        return false;
    }
    peer_ = extract_peer(stream_->native_handle());
    return true;
}

std::string TlsClient::recv_all(int total_wait_ms, int idle_gap_ms,
                                size_t max_bytes) {
    if (!is_open()) return {};

    std::string out;
    auto deadline = std::chrono::steady_clock::now() +
                    std::chrono::milliseconds(total_wait_ms);
    char buf[8192];

    for (;;) {
        if (out.size() >= max_bytes) break;
        auto now = std::chrono::steady_clock::now();
        if (now >= deadline) break;
        int wait = static_cast<int>(
            std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now)
                .count());
        wait = std::min(wait, idle_gap_ms);

        asio::steady_timer timer(io_);
        timer.expires_after(std::chrono::milliseconds(wait));
        bool done = false;
        size_t nread = 0;
        bool eof = false;
        bool err = false;

        stream_->async_read_some(
            asio::buffer(buf, sizeof(buf)),
            [&](std::error_code ec, size_t n) {
                if (done) return;
                done = true;
                if (ec == asio::error::eof ||
                    ec == asio::ssl::error::stream_truncated) {
                    eof = true;
                    std::error_code ignored;
                    stream_->next_layer().close(ignored);
                } else if (ec)
                    err = true;
                else
                    nread = n;
                timer.cancel();
            });
        timer.async_wait([&](std::error_code) {
            if (done) return;
            done = true;
            std::error_code ignored;
            stream_->next_layer().cancel(ignored);
        });
        run_round();

        if (err || eof) break;
        if (nread == 0) break;
        out.append(buf, nread);
    }
    return out;
}

bool TlsClient::send(std::string_view data) {
    if (!is_open() || data.empty()) return false;
    asio::steady_timer timer(io_);
    timer.expires_after(std::chrono::milliseconds(2000));
    bool done = false;
    bool ok = false;
    asio::async_write(*stream_, asio::buffer(data.data(), data.size()),
                      [&](std::error_code ec, size_t) {
                          if (done) return;
                          done = true;
                          ok = !ec;
                          timer.cancel();
                      });
    timer.async_wait([&](std::error_code) {
        if (done) return;
        done = true;
        std::error_code ignored;
        stream_->next_layer().close(ignored);
    });
    run_round();
    return ok;
}

std::string TlsClient::send_and_receive(std::string_view payload, int wait_ms,
                                        size_t max_bytes) {
    if (!send(payload)) return {};
    return recv_all(wait_ms, wait_ms, max_bytes);
}

void TlsClient::close() {
    if (stream_) {
        std::error_code ignored;
        stream_->next_layer().close(ignored);
        stream_.reset();
    }
}

bool TlsClient::is_open() const {
    return stream_ && stream_->next_layer().is_open();
}

} // namespace sln

#endif // SLEIPNIR_HAVE_TLS
