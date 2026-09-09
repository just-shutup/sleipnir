// TLS/SSL assessment: certificate validity and protocol hygiene.
// Findings follow the severity conventions of mainstream vulnerability
// scanners (expired/mismatched/untrusted certificate, legacy protocol
// versions still accepted by the endpoint).
#pragma once

#include "sleipnir/results.hpp"
#include "sleipnir/types.hpp"

#ifdef SLEIPNIR_HAVE_TLS

#include "sleipnir/tls_client.hpp"

#include <string>
#include <vector>

namespace sln {

// Projects handshake facts onto the report-facing TlsInfo (self-signed,
// chain trust, hostname match per RFC 6125).
TlsInfo summarize_tls(const std::string& host, const TlsPeerInfo& peer);

// Certificate checks based on the handshake facts already collected by
// TlsClient (expiry window: 14 days).
std::vector<Finding> check_tls_certificate(const std::string& host,
                                           uint16_t port,
                                           const TlsPeerInfo& peer);

// Actively probes legacy protocol versions (TLS 1.0/1.1, SSL 3.0) by
// attempting handshakes pinned to those versions. Expensive: call once per
// confirmed TLS endpoint.
std::vector<Finding> check_tls_legacy_protocols(asio::io_context& io,
                                                const std::string& host,
                                                uint16_t port, int timeout_ms);

} // namespace sln

#endif // SLEIPNIR_HAVE_TLS
