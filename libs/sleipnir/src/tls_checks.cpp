#include "sleipnir/tls_checks.hpp"

#ifdef SLEIPNIR_HAVE_TLS

#include <asio/ssl.hpp>

#include <openssl/x509.h>

#include <chrono>

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
    f.source = "tls";
    return f;
}

bool is_ip_literal(const std::string& host) {
    std::error_code ec;
    asio::ip::make_address(host, ec);
    return !ec;
}

// RFC 6125 name matching with the single leading "*." wildcard component.
bool name_matches(const std::string& pattern, const std::string& host) {
    if (pattern == host) return true;
    if (pattern.rfind("*.", 0) == 0) {
        size_t dot = host.find('.');
        return dot != std::string::npos &&
               pattern.substr(2) == host.substr(dot + 1);
    }
    return false;
}

// Attempts one handshake pinned to an exact legacy protocol version.
// Returns the negotiated protocol name on success, empty on refusal.
std::string try_pinned_version(asio::io_context& io,
                               asio::ssl::context::method method,
                               const std::string& host, uint16_t port,
                               int timeout_ms) {
    TcpClient tcp(io);
    if (!tcp.connect(host, port, timeout_ms)) return {};
    asio::ip::tcp::socket raw = tcp.detach();
    if (!raw.is_open()) return {};

    try {
        asio::ssl::context ctx(method);
        ctx.set_verify_mode(asio::ssl::verify_none);
        asio::ssl::stream<asio::ip::tcp::socket> stream(std::move(raw), ctx);

        asio::steady_timer timer(io);
        timer.expires_after(std::chrono::milliseconds(timeout_ms));
        bool done = false;
        bool ok = false;

        stream.async_handshake(asio::ssl::stream_base::client,
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
            stream.next_layer().close(ignored);
        });
        io.restart();
        io.run();

        if (!ok) return {};
        const char* proto = SSL_get_version(stream.native_handle());
        return proto ? proto : "unknown";
    } catch (const std::exception&) {
        return {}; // context for the pinned version unavailable in this build
    }
}

} // namespace

TlsInfo summarize_tls(const std::string& host, const TlsPeerInfo& peer) {
    TlsInfo info;
    info.protocol = peer.protocol;
    info.cipher = peer.cipher;
    info.subject = peer.subject;
    info.issuer = peer.issuer;
    info.not_before = peer.not_before;
    info.not_after = peer.not_after;

    info.self_signed =
        (!peer.subject.empty() && peer.subject == peer.issuer) ||
        peer.verify_error == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT ||
        peer.verify_error == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN;
    info.chain_trusted = peer.chain_trusted;
    info.hostname_match = true;

    // RFC 6125 name matching over SAN entries (CN is the fallback for
    // CN-only certificates). Skipped for IP targets: authoritative
    // IP-address matching needs the X509 object, and false positives here
    // would drown the signal.
    if (!is_ip_literal(host)) {
        const std::vector<std::string>& candidates =
            peer.san_dns.empty() && !peer.common_name.empty()
                ? std::vector<std::string>{peer.common_name}
                : peer.san_dns;
        if (!candidates.empty()) {
            info.hostname_match = false;
            for (const auto& c : candidates)
                if (name_matches(c, host)) {
                    info.hostname_match = true;
                    break;
                }
        }
    }
    return info;
}

std::vector<Finding> check_tls_certificate(const std::string& host,
                                           uint16_t port,
                                           const TlsPeerInfo& peer) {
    std::vector<Finding> out;
    long long now = std::chrono::duration_cast<std::chrono::seconds>(
                        std::chrono::system_clock::now().time_since_epoch())
                        .count();

    if (!peer.handshake_ok) {
        out.push_back(make_finding(
            host, port, "TLS handshake failed", Severity::Info,
            "The endpoint negotiates TLS only unreliably or not at all; the "
            "service may require a specific SNI name, client certificate or "
            "protocol version.",
            "no usable handshake"));
        return out;
    }

    if (peer.not_after_epoch == 0) {
        out.push_back(make_finding(
            host, port, "No certificate presented", Severity::High,
            "The endpoint completed a TLS handshake without providing a "
            "certificate. Anonymous TLS suites are obsolete and prevent any "
            "server authentication.",
            "peer certificate missing"));
        return out;
    }

    if (peer.not_after_epoch < now) {
        out.push_back(make_finding(
            host, port, "TLS certificate expired", Severity::Medium,
            "The served certificate is not valid anymore. Clients reject the "
            "connection or users learn to override warnings, which trains "
            "dangerous habits.",
            "not_after=" + peer.not_after));
    } else if (peer.not_after_epoch - now <= 14LL * 86400) {
        out.push_back(make_finding(
            host, port, "TLS certificate expires within 14 days",
            Severity::Low,
            "The certificate is about to expire; renewal should be scheduled "
            "before clients start seeing validation errors.",
            "not_after=" + peer.not_after));
    }

    TlsInfo summary = summarize_tls(host, peer);
    if (summary.self_signed) {
        out.push_back(make_finding(
            host, port, "Self-signed TLS certificate", Severity::Low,
            "The certificate is not issued by a trusted CA. Acceptable for "
            "internal lab use, but public endpoints should use a CA-signed "
            "certificate.",
            "subject=" + peer.subject));
    } else if (!summary.chain_trusted) {
        out.push_back(make_finding(
            host, port, "TLS certificate chain not trusted", Severity::Medium,
            "OpenSSL certificate validation failed. Most likely an incomplete "
            "chain (intermediate certificate missing) or an unknown CA.",
            "verify error: " + peer.verify_error_text));
    }

    if (!summary.hostname_match)
        out.push_back(make_finding(
            host, port, "TLS certificate hostname mismatch", Severity::Medium,
            "The certificate does not cover the scanned hostname. Clients "
            "will abort with a name-mismatch error.",
            "host=" + host + ", CN=" + peer.common_name));

    return out;
}

std::vector<Finding> check_tls_legacy_protocols(asio::io_context& io,
                                                const std::string& host,
                                                uint16_t port,
                                                int timeout_ms) {
    std::vector<Finding> out;

    struct Legacy {
        asio::ssl::context::method method;
        const char* proto;
        const char* cve;
        const char* risk;
        Severity sev;
    };
    static const Legacy versions[] = {
        {asio::ssl::context::tlsv1_client, "TLS 1.0",
         "CVE-2011-3389 (BEAST)",
         "allows downgrade and CBC attacks in principle", Severity::Medium},
        {asio::ssl::context::tlsv11_client, "TLS 1.1", "-",
         "deprecated by RFC 8996 (2021)", Severity::Medium},
        {asio::ssl::context::sslv3_client, "SSL 3.0",
         "CVE-2014-3566 (POODLE)",
         "padding oracle allows plaintext recovery", Severity::High},
    };

    for (const auto& v : versions) {
        std::string negotiated = try_pinned_version(io, v.method, host, port,
                                                    timeout_ms);
        if (negotiated.empty()) continue;
        std::string desc =
            std::string("The endpoint completed a handshake restricted to ") +
            v.proto + ". Legacy protocols should be disabled server-side (" +
            v.risk;
        if (std::string(v.cve) != "-") desc += std::string("; see ") + v.cve;
        desc += ").";
        out.push_back(make_finding(
            host, port, std::string("Server accepts ") + v.proto, v.sev, desc,
            "negotiated: " + negotiated));
    }
    return out;
}

} // namespace sln

#endif // SLEIPNIR_HAVE_TLS
