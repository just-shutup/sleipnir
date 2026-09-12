// Protocol-level server audits (0.9.5): SSH algorithm/weakness auditing
// with authentication-method enumeration, SMB negotiation/null-session
// auditing with share enumeration, and the factory-default credential
// dictionary (--brute-default-creds) for database and infrastructure
// services. The pure parsing/classification pieces are exposed for unit
// tests; the network stages take a connected TcpClient and never throw.
//
// SSH KEX note: the auth-method enumeration completes a real key exchange
// (curve25519-sha256 / diffie-hellman-group14-sha{1,256} + AES-CTR +
// HMAC) purely to send a single "none" USERAUTH_REQUEST — the same first
// step every SSH client performs. Host key signatures are not verified
// (a scanner never trusts the target anyway); no password is ever sent.
#pragma once

#include "sleipnir/auth.hpp"
#include "sleipnir/http_client.hpp"
#include "sleipnir/netio.hpp"
#include "sleipnir/results.hpp"
#include "sleipnir/types.hpp"

#include <asio.hpp>

#include <cstdint>
#include <string>
#include <vector>

namespace sln {

class ResultCollector;

// ---------------------------------------------------------------------------
// SSH
// ---------------------------------------------------------------------------

struct SshAlgorithms {
    std::string banner; // e.g. "SSH-2.0-OpenSSH_7.4"
    std::vector<std::string> kex;
    std::vector<std::string> host_keys;
    std::vector<std::string> ciphers_c2s;
    std::vector<std::string> ciphers_s2c;
    std::vector<std::string> macs_c2s;
    std::vector<std::string> macs_s2c;
    std::vector<std::string> compression;

    // Auth enumeration (a "none" USERAUTH_REQUEST after a real KEX).
    std::vector<std::string> auth_methods; // e.g. "publickey,password"
    bool auth_enumerated = false;          // method list was obtained
    bool auth_none_accepted = false;       // server granted "none" access!
};

// Parses the payload of an SSH_MSG_KEXINIT message (without the packet
// framing). Returns false on malformed input.
bool parse_ssh_kexinit(const std::string& payload, SshAlgorithms& out);

struct SshWeakAlgo {
    std::string name;
    Severity severity = Severity::Info;
    std::string issue; // human-readable reason
};

// Classifies the weak algorithms a server offers (DES/3DES/RC4 ciphers,
// SHA-1 key exchanges, weak MACs, legacy host key types).
std::vector<SshWeakAlgo> ssh_weak_algorithms(const SshAlgorithms& algs);

// Full SSH audit over a fresh connection: banner exchange, KEXINIT
// exchange (weak algorithm classification) and — when enumerate_auth is
// set — a complete key exchange followed by a "none" auth request to
// enumerate the accepted authentication methods.
SshAlgorithms ssh_audit(asio::io_context& io, const std::string& host,
                        uint16_t port, int timeout_ms, bool enumerate_auth,
                        ResultCollector& collector);

// Findings built from an audit result.
std::vector<Finding> ssh_audit_findings(const std::string& host, uint16_t port,
                                        const SshAlgorithms& algs);

// ---------------------------------------------------------------------------
// SMB / RPC
// ---------------------------------------------------------------------------

struct SmbInfo {
    bool smb1_enabled = false;      // answered an SMB1 NEGOTIATE
    bool smb2_responded = false;    // answered an SMB2 NEGOTIATE
    bool signing_enabled = false;   // server supports signing
    bool signing_required = false;  // server rejects unsigned traffic
    bool null_session_ok = false;   // anonymous session setup accepted
    bool guest_session_ok = false;  // "guest" account session accepted
    std::vector<std::string> shares; // RAP NetShareEnum via null session
};

// Parses an SMB1 Negotiate response (the SMB message, NBSS header
// stripped). Fills signing_* and smb1_enabled on success.
bool smb_parse_negotiate_response(const std::string& message, SmbInfo& info);

// Parses an SMB2 Negotiate response (protocol id \xfeSMB).
bool smb_parse_smb2_negotiate_response(const std::string& message,
                                        SmbInfo& info);

// RAP NetShareEnum level 1: parameters carry status/converter/count, the
// data section holds 19-byte entries (13-byte padded name, 2-byte type,
// 4-byte comment offset). Returns the share names.
std::vector<std::string> smb_parse_rap_shares(const std::string& params,
                                               const std::string& data);

// SMB audit over fresh connections: SMB1 + SMB2 negotiation (protocol
// versions, signing policy) and, when allow_session is set, null/guest
// session attempts plus share enumeration via RAP over IPC$.
SmbInfo smb_audit(asio::io_context& io, const std::string& host, uint16_t port,
                  int timeout_ms, bool allow_session,
                  ResultCollector& collector);

std::vector<Finding> smb_audit_findings(const std::string& host, uint16_t port,
                                        const SmbInfo& info);

// ---------------------------------------------------------------------------
// Default credentials (--brute-default-creds)
// ---------------------------------------------------------------------------

struct DefaultCred {
    std::string user;
    std::string password; // "" = empty password
};

// Built-in per-service dictionary of factory default accounts.
std::vector<DefaultCred> default_creds_for(const std::string& service);

// Protocol-level default-credential audit for ftp, mysql and redis
// (redis also fires when the banner shows "-NOAUTH"). Each attempt uses
// a fresh connection.
std::vector<Finding> default_creds_audit(asio::io_context& io,
                                         const std::string& service,
                                         const std::string& banner,
                                         const std::string& host,
                                         uint16_t port, int timeout_ms,
                                         ResultCollector& collector);

// HTTP Basic variant: runs over the caller's transport when a 401 with a
// Basic challenge was observed. Reports only logins that answer 2xx.
template <typename Stream>
std::vector<Finding> default_creds_http_basic(
    Stream& stream, const std::string& host, uint16_t port, int timeout_ms,
    const std::string& user_agent);

// MySQL mysql_native_password "20-byte scramble":
// SHA1(pass) XOR SHA1(nonce || SHA1(SHA1(pass))). Returns "" when the
// build has no OpenSSL (the MySQL probe is skipped there).
std::string mysql_scramble(const std::string& password,
                           const std::string& nonce);

// Builds a HandshakeResponse41 packet (with 4-byte MySQL framing) for
// mysql_native_password.
std::string mysql_handshake_response(const std::string& user,
                                     const std::string& scramble);

// ---------------------------------------------------------------------------
// Template implementation
// ---------------------------------------------------------------------------

template <typename Stream>
std::vector<Finding> default_creds_http_basic(
    Stream& stream, const std::string& host, uint16_t port, int timeout_ms,
    const std::string& user_agent) {
    std::vector<Finding> out;
    for (const auto& cred : default_creds_for("http-basic")) {
        HttpOptions opts;
        opts.headers.push_back(
            {"Authorization",
             "Basic " + base64_encode(cred.user + ":" + cred.password)});
        auto resp = http_request_ex(stream, "GET", host, port, "/", timeout_ms,
                                    user_agent, opts);
        if (!resp || resp->status < 200 || resp->status >= 300) continue;
        Finding f;
        f.host = host;
        f.port = port;
        f.title = "Default HTTP basic credentials accepted: " + cred.user +
                  ":" + (cred.password.empty() ? "<empty>" : cred.password);
        f.severity = Severity::Critical;
        f.description =
            "The endpoint accepts a factory default account (" + cred.user +
            "). Any attacker reading the product documentation gets the "
            "same access as a legitimate administrator. Change the "
            "credential and enforce strong passwords.";
        f.evidence = "GET / with Authorization: Basic " +
                     base64_encode(cred.user + ":" + cred.password) + " -> " +
                     std::to_string(resp->status);
        f.source = "proto-audit";
        f.verified = true;
        f.confidence = "confirmed";
        out.push_back(std::move(f));
        break; // one working credential proves the point
    }
    return out;
}

} // namespace sln
