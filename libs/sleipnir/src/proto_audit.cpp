// Protocol audits: SSH (KEXINIT parsing, weak algorithms, full key
// exchange for auth-method enumeration) and SMB (negotiation, signing
// policy, null/guest sessions, RAP share enumeration).

#include "sleipnir/proto_audit.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <random>

#ifndef SLEIPNIR_VERSION
#define SLEIPNIR_VERSION "dev"
#endif

#ifdef SLEIPNIR_HAVE_TLS
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#endif

namespace sln {

namespace {

// ---------------------------------------------------------------------------
// byte helpers
// ---------------------------------------------------------------------------

void put_u32be(std::string& s, uint32_t v) {
    s += static_cast<char>(v >> 24);
    s += static_cast<char>((v >> 16) & 0xff);
    s += static_cast<char>((v >> 8) & 0xff);
    s += static_cast<char>(v & 0xff);
}

void put_u16le(std::string& s, uint16_t v) {
    s += static_cast<char>(v & 0xff);
    s += static_cast<char>(v >> 8);
}

void put_u32le(std::string& s, uint32_t v) {
    s += static_cast<char>(v & 0xff);
    s += static_cast<char>((v >> 8) & 0xff);
    s += static_cast<char>((v >> 16) & 0xff);
    s += static_cast<char>((v >> 24) & 0xff);
}

bool get_u16le(const std::string& s, size_t& pos, uint16_t& out) {
    if (pos + 2 > s.size()) return false;
    out = static_cast<uint16_t>(static_cast<uint8_t>(s[pos])) |
          (static_cast<uint16_t>(static_cast<uint8_t>(s[pos + 1])) << 8);
    pos += 2;
    return true;
}

bool get_u32be(const std::string& s, size_t& pos, uint32_t& out) {
    if (pos + 4 > s.size()) return false;
    out = (static_cast<uint32_t>(static_cast<uint8_t>(s[pos])) << 24) |
          (static_cast<uint32_t>(static_cast<uint8_t>(s[pos + 1])) << 16) |
          (static_cast<uint32_t>(static_cast<uint8_t>(s[pos + 2])) << 8) |
          static_cast<uint32_t>(static_cast<uint8_t>(s[pos + 3]));
    pos += 4;
    return true;
}

// SSH "string": u32 length + bytes.
bool get_ssh_string(const std::string& s, size_t& pos, std::string& out) {
    uint32_t len;
    if (!get_u32be(s, pos, len)) return false;
    if (pos + len > s.size()) return false;
    out = s.substr(pos, len);
    pos += len;
    return true;
}

std::string ssh_string(const std::string& bytes) {
    std::string s;
    put_u32be(s, static_cast<uint32_t>(bytes.size()));
    s += bytes;
    return s;
}

std::vector<std::string> split_name_list(const std::string& names) {
    std::vector<std::string> out;
    std::string cur;
    for (char c : names) {
        if (c == ',') {
            out.push_back(std::move(cur));
            cur.clear();
        } else {
            cur += c;
        }
    }
    if (!cur.empty()) out.push_back(std::move(cur));
    return out;
}

bool list_has(const std::vector<std::string>& list, const std::string& name) {
    return std::find(list.begin(), list.end(), name) != list.end();
}

// First entry of `offered` that also appears in `supported`.
std::string pick_algorithm(const std::vector<std::string>& offered,
                           const std::vector<const char*>& supported) {
    for (const auto& o : offered)
        for (const char* s : supported)
            if (o == s) return o;
    return "";
}

uint32_t read_u32le(const std::string& s, size_t pos) {
    if (pos + 4 > s.size()) return 0;
    return static_cast<uint32_t>(static_cast<uint8_t>(s[pos])) |
           (static_cast<uint32_t>(static_cast<uint8_t>(s[pos + 1])) << 8) |
           (static_cast<uint32_t>(static_cast<uint8_t>(s[pos + 2])) << 16) |
           (static_cast<uint32_t>(static_cast<uint8_t>(s[pos + 3])) << 24);
}

uint32_t read_u32be(const std::string& s, size_t pos) {
    if (pos + 4 > s.size()) return 0;
    return (static_cast<uint32_t>(static_cast<uint8_t>(s[pos])) << 24) |
           (static_cast<uint32_t>(static_cast<uint8_t>(s[pos + 1])) << 16) |
           (static_cast<uint32_t>(static_cast<uint8_t>(s[pos + 2])) << 8) |
           static_cast<uint32_t>(static_cast<uint8_t>(s[pos + 3]));
}

} // namespace

// ---------------------------------------------------------------------------
// SSH: KEXINIT parsing and weak-algorithm classification (pure, portable)
// ---------------------------------------------------------------------------

bool parse_ssh_kexinit(const std::string& payload, SshAlgorithms& out) {
    // byte SSH_MSG_KEXINIT(20) + byte[16] cookie + 10 name-lists + flags
    if (payload.size() < 17) return false;
    if (static_cast<uint8_t>(payload[0]) != 20) return false;
    size_t pos = 17;
    std::string lists[10];
    for (auto& l : lists)
        if (!get_ssh_string(payload, pos, l)) return false;
    out.kex = split_name_list(lists[0]);
    out.host_keys = split_name_list(lists[1]);
    out.ciphers_c2s = split_name_list(lists[2]);
    out.ciphers_s2c = split_name_list(lists[3]);
    out.macs_c2s = split_name_list(lists[4]);
    out.macs_s2c = split_name_list(lists[5]);
    out.compression = split_name_list(lists[6]);
    return true;
}

std::vector<SshWeakAlgo> ssh_weak_algorithms(const SshAlgorithms& algs) {
    std::vector<SshWeakAlgo> out;

    for (const auto& k : algs.kex) {
        if (k == "diffie-hellman-group1-sha1") {
            out.push_back({k, Severity::High,
                           "1024-bit MODP group with SHA-1: precomputation "
                           "attacks (LogJam class) can recover the session"});
        } else if (k == "diffie-hellman-group14-sha1" ||
                   k == "diffie-hellman-group-exchange-sha1") {
            out.push_back({k, Severity::Low,
                           "SHA-1 based key exchange (deprecated; prefer a "
                           "SHA-256 or Curve25519 KEX)"});
        }
    }

    auto weak_cipher = [](const std::string& c) -> SshWeakAlgo {
        if (c.find("arcfour") != std::string::npos)
            return {c, Severity::High,
                    "RC4 stream cipher: biased keystream allows plaintext "
                    "recovery (removed from SSH implementations)"};
        if (c == "3des-cbc" || c == "3des-ctr" || c == "3des")
            return {c, Severity::High,
                    "3DES: 112-bit effective strength and small block size "
                    "(Sweet32 birthday attacks)"};
        if (c.find("-des-") != std::string::npos || c == "des-cbc" ||
            c == "des")
            return {c, Severity::High, "single-DES cipher: trivially breakable"};
        if (c == "none")
            return {c, Severity::Critical, "unencrypted transport offered"};
        if (c.size() > 4 && c.compare(c.size() - 4, 4, "-cbc") == 0)
            return {c, Severity::Low,
                    "CBC mode in SSH is vulnerable to plaintext injection "
                    "(SSH CBC bias attacks)"};
        return {};
    };
    for (const auto& list : {algs.ciphers_c2s, algs.ciphers_s2c})
        for (const auto& c : list) {
            auto w = weak_cipher(c);
            if (!w.name.empty()) out.push_back(std::move(w));
        }

    auto weak_mac = [](const std::string& m) -> SshWeakAlgo {
        if (m.find("md5") != std::string::npos)
            return {m, Severity::Medium,
                    "MD5-based MAC: collision-prone hash, deprecated"};
        if (m.find("sha1-96") != std::string::npos)
            return {m, Severity::Medium,
                    "truncated SHA-1 MAC (96 bits): weakened integrity"};
        if (m == "hmac-sha1")
            return {m, Severity::Low,
                    "SHA-1 based MAC (prefer hmac-sha2-256 or stronger)"};
        if (m == "none")
            return {m, Severity::Critical, "unauthenticated transport offered"};
        return {};
    };
    for (const auto& list : {algs.macs_c2s, algs.macs_s2c})
        for (const auto& m : list) {
            auto w = weak_mac(m);
            if (!w.name.empty()) out.push_back(std::move(w));
        }

    for (const auto& hk : algs.host_keys) {
        if (hk == "ssh-dss")
            out.push_back({hk, Severity::High,
                           "DSA host keys are limited to 1024 bits and were "
                           "removed from OpenSSH as insecure"});
        else if (hk == "ssh-rsa")
            out.push_back({hk, Severity::Low,
                           "RSA host key with SHA-1 signatures (deprecated; "
                           "prefer rsa-sha2-*, ecdsa or ed25519)"});
    }
    return out;
}

std::vector<Finding> ssh_audit_findings(const std::string& host, uint16_t port,
                                        const SshAlgorithms& algs) {
    std::vector<Finding> out;
    for (const auto& w : ssh_weak_algorithms(algs)) {
        Finding f;
        f.host = host;
        f.port = port;
        f.title = "SSH weak algorithm offered: " + w.name;
        f.severity = w.severity;
        f.description =
            "The server offers '" + w.name + "' during key exchange: " +
            w.issue + ". Remove the algorithm from the server configuration.";
        f.evidence = "banner '" + algs.banner + "' KEXINIT lists " + w.name;
        f.source = "proto-audit";
        f.verified = true;
        f.confidence = "confirmed";
        out.push_back(std::move(f));
    }

    if (algs.auth_none_accepted) {
        Finding f;
        f.host = host;
        f.port = port;
        f.title = "SSH accepts unauthenticated sessions (method 'none')";
        f.severity = Severity::Critical;
        f.description =
            "A USERAUTH_REQUEST with method 'none' succeeded: the server "
            "grants an SSH session without any credentials. Every "
            "authorized-user restriction is bypassed — fix the "
            "authentication configuration immediately.";
        f.evidence = "USERAUTH_REQUEST user=audit method=none -> SUCCESS";
        f.source = "proto-audit";
        f.verified = true;
        f.confidence = "confirmed";
        out.push_back(std::move(f));
    } else if (algs.auth_enumerated) {
        std::string methods;
        for (const auto& m : algs.auth_methods) {
            if (!methods.empty()) methods += ",";
            methods += m;
        }
        {
            Finding f;
            f.host = host;
            f.port = port;
            f.title = "SSH authentication methods: " + methods;
            f.severity = Severity::Info;
            f.description =
                "The server enumerated its accepted authentication methods "
                "in response to a 'none' request. 'publickey' only is the "
                "recommended posture; 'password' keeps the door open to "
                "brute-force and credential stuffing.";
            f.evidence = "USERAUTH_REQUEST method=none -> FAILURE, methods=" +
                         methods;
            f.source = "proto-audit";
            f.verified = true;
            f.confidence = "confirmed";
            out.push_back(std::move(f));
        }
        if (list_has(algs.auth_methods, "password")) {
            Finding f;
            f.host = host;
            f.port = port;
            f.title = "SSH password authentication enabled";
            f.severity = Severity::Low;
            f.description =
                "The server accepts password authentication (method list: " +
                methods +
                "). Password logins invite brute-force attacks; prefer "
                "public-key-only authentication (PasswordAuthentication no).";
            f.evidence = "methods=" + methods;
            f.source = "proto-audit";
            f.verified = true;
            f.confidence = "confirmed";
            out.push_back(std::move(f));
        }
    }
    return out;
}

// ---------------------------------------------------------------------------
// SSH transport: packet framing + crypto (OpenSSL builds only)
// ---------------------------------------------------------------------------

#ifdef SLEIPNIR_HAVE_TLS

namespace {

// Digest helper.
std::string digest(const EVP_MD* md, const std::string& data) {
    unsigned char out[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    EVP_Digest(data.data(), data.size(), out, &len, md, nullptr);
    return std::string(reinterpret_cast<char*>(out), len);
}

std::string hmac_digest(const EVP_MD* md, const std::string& key,
                        const std::string& data) {
    unsigned char mac[EVP_MAX_MD_SIZE];
    unsigned int maclen = 0;
    HMAC(md, key.data(), static_cast<int>(key.size()),
         reinterpret_cast<const unsigned char*>(data.data()), data.size(), mac,
         &maclen);
    return std::string(reinterpret_cast<char*>(mac), maclen);
}

std::string seq_string(uint32_t seq) {
    std::string s;
    put_u32be(s, seq);
    return s;
}

void ctr_process(EVP_CIPHER_CTX* ctx, std::string& data) {
    if (data.empty()) return;
    std::string out(data.size(), '\0');
    int outlen = 0;
    EVP_CipherUpdate(ctx, reinterpret_cast<unsigned char*>(out.data()), &outlen,
                     reinterpret_cast<const unsigned char*>(data.data()),
                     static_cast<int>(data.size()));
    data = out.substr(0, static_cast<size_t>(outlen));
}

// mpint encoding: minimal big-endian; a leading 0x00 is prepended when
// the high bit of the first byte is set (positive numbers only here).
std::string to_mpint(const std::string& big_endian) {
    size_t start = 0;
    while (start < big_endian.size() && big_endian[start] == '\0') ++start;
    std::string v = big_endian.substr(start);
    if (v.empty()) return std::string("\0", 1);
    if (static_cast<uint8_t>(v[0]) & 0x80) v.insert(v.begin(), '\0');
    return v;
}

std::string bn_bytes(const BIGNUM* bn) {
    int len = BN_num_bytes(bn);
    std::string out(static_cast<size_t>(len), '\0');
    BN_bn2bin(bn, reinterpret_cast<unsigned char*>(out.data()));
    return out;
}

// RFC 3526 group 14 (2048-bit MODP), generator 2.
const char* kDhGroup14Hex =
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF";

BIGNUM* dh_prime() {
    BIGNUM* p = nullptr;
    BN_hex2bn(&p, kDhGroup14Hex);
    return p;
}

bool x25519_keypair(std::string& pub, std::string& priv) {
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
    if (!pctx) return false;
    EVP_PKEY* pkey = nullptr;
    bool ok = EVP_PKEY_keygen_init(pctx) > 0 &&
              EVP_PKEY_keygen(pctx, &pkey) > 0;
    EVP_PKEY_CTX_free(pctx);
    if (!ok || !pkey) {
        EVP_PKEY_free(pkey);
        return false;
    }
    unsigned char p[32], s[32];
    size_t plen = sizeof(p), slen = sizeof(s);
    ok = EVP_PKEY_get_raw_public_key(pkey, p, &plen) > 0 &&
         EVP_PKEY_get_raw_private_key(pkey, s, &slen) > 0;
    EVP_PKEY_free(pkey);
    if (!ok) return false;
    pub.assign(reinterpret_cast<char*>(p), plen);
    priv.assign(reinterpret_cast<char*>(s), slen);
    return true;
}

bool x25519_shared(const std::string& priv, const std::string& peer_pub,
                   std::string& out) {
    if (peer_pub.size() != 32 || priv.size() != 32) return false;
    EVP_PKEY* ours = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_X25519, nullptr,
        reinterpret_cast<const unsigned char*>(priv.data()), priv.size());
    EVP_PKEY* peer = EVP_PKEY_new_raw_public_key(
        EVP_PKEY_X25519, nullptr,
        reinterpret_cast<const unsigned char*>(peer_pub.data()),
        peer_pub.size());
    if (!ours || !peer) {
        EVP_PKEY_free(ours);
        EVP_PKEY_free(peer);
        return false;
    }
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(ours, nullptr);
    unsigned char secret[32];
    size_t secret_len = sizeof(secret);
    bool ok = ctx && EVP_PKEY_derive_init(ctx) > 0 &&
              EVP_PKEY_derive_set_peer(ctx, peer) > 0 &&
              EVP_PKEY_derive(ctx, secret, &secret_len) > 0 &&
              secret_len == 32;
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(ours);
    EVP_PKEY_free(peer);
    if (ok) out.assign(reinterpret_cast<char*>(secret), 32);
    return ok;
}

// e = 2^x mod p (SSH-string-wrapped mpint); the private exponent returns
// as raw big-endian bytes.
bool dh_group14_keypair(std::string& e_wire, std::string& priv_out) {
    BIGNUM* p = dh_prime();
    BIGNUM* g = BN_new();
    BN_set_word(g, 2);
    unsigned char randbuf[40];
    RAND_bytes(randbuf, sizeof(randbuf));
    BIGNUM* x = BN_bin2bn(randbuf, sizeof(randbuf), nullptr);
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* e = BN_new();
    BN_mod_exp(e, g, x, p, ctx);
    e_wire = ssh_string(to_mpint(bn_bytes(e)));
    priv_out = bn_bytes(x);
    BN_free(e);
    BN_free(x);
    BN_free(g);
    BN_free(p);
    BN_CTX_free(ctx);
    return true;
}

bool dh_group14_shared(const std::string& priv_bytes, const std::string& f_bytes,
                       std::string& out) {
    BIGNUM* p = dh_prime();
    BIGNUM* x = BN_bin2bn(
        reinterpret_cast<const unsigned char*>(priv_bytes.data()),
        static_cast<int>(priv_bytes.size()), nullptr);
    BIGNUM* f = BN_bin2bn(
        reinterpret_cast<const unsigned char*>(f_bytes.data()),
        static_cast<int>(f_bytes.size()), nullptr);
    if (!x || !f) {
        BN_free(p);
        BN_free(x);
        BN_free(f);
        return false;
    }
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* k = BN_new();
    BN_mod_exp(k, f, x, p, ctx);
    out = to_mpint(bn_bytes(k));
    BN_free(k);
    BN_CTX_free(ctx);
    BN_free(f);
    BN_free(x);
    BN_free(p);
    return true;
}

// Buffered SSH packet reader/writer over a TcpClient, with optional
// AES-CTR + HMAC transport encryption after NEWKEYS.
class SshConn {
public:
    SshConn(TcpClient& client, int timeout_ms)
        : client_(client), timeout_ms_(timeout_ms) {}

    bool read_exact(size_t n, std::string& out) {
        auto deadline = std::chrono::steady_clock::now() +
                        std::chrono::milliseconds(timeout_ms_);
        while (buf_.size() < n) {
            if (!client_.is_open()) return false;
            int remain = static_cast<int>(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    deadline - std::chrono::steady_clock::now())
                    .count());
            if (remain <= 0) return false;
            std::string chunk =
                client_.recv_all(std::min(remain, 3000), 100, 262144);
            if (!chunk.empty()) {
                buf_ += chunk;
                continue;
            }
            if (!client_.is_open()) return false;
        }
        out = buf_.substr(0, n);
        buf_.erase(0, n);
        return true;
    }

    // One banner line terminated by \n (trailing \r stripped).
    bool read_banner_line(std::string& line) {
        auto deadline = std::chrono::steady_clock::now() +
                        std::chrono::milliseconds(timeout_ms_);
        for (;;) {
            size_t nl = buf_.find('\n');
            if (nl != std::string::npos) {
                line = buf_.substr(0, nl);
                if (!line.empty() && line.back() == '\r') line.pop_back();
                buf_.erase(0, nl + 1);
                return true;
            }
            if (!client_.is_open()) return false;
            int remain = static_cast<int>(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    deadline - std::chrono::steady_clock::now())
                    .count());
            if (remain <= 0) return false;
            std::string chunk =
                client_.recv_all(std::min(remain, 3000), 100, 8192);
            if (!chunk.empty()) {
                buf_ += chunk;
                if (buf_.size() > 8192) return false;
                continue;
            }
            if (!client_.is_open()) return false;
        }
    }

    // Plain (unencrypted) packet send.
    bool send_packet(const std::string& payload) {
        size_t pad = 8 - ((5 + payload.size()) % 8);
        if (pad < 4) pad += 8;
        std::string pkt;
        put_u32be(pkt, static_cast<uint32_t>(1 + payload.size() + pad));
        pkt += static_cast<char>(pad);
        pkt += payload;
        pkt.append(pad, '\0');
        if (!client_.send(pkt)) return false;
        ++seq_c2s_;
        return true;
    }

    // Encrypted packet send (no-op fallback to plain when tx not enabled).
    bool send_packet_enc(const std::string& payload) {
        if (!tx_cipher_) return send_packet(payload);
        size_t pad = 8 - ((5 + payload.size()) % 8);
        if (pad < 4) pad += 8;
        std::string pkt;
        put_u32be(pkt, static_cast<uint32_t>(1 + payload.size() + pad));
        pkt += static_cast<char>(pad);
        pkt += payload;
        pkt.append(pad, '\0');
        std::string mac =
            hmac_digest(tx_mac_, tx_mac_key_, seq_string(seq_c2s_) + pkt);
        ctr_process(tx_cipher_, pkt);
        if (!client_.send(pkt + mac)) return false;
        ++seq_c2s_;
        return true;
    }

    // Packet receive: plain before NEWKEYS, length-hidden CTR + MAC after.
    bool recv_packet(std::string& payload) {
        std::string head;
        if (!read_exact(4, head)) return false;
        if (crypto_rx_) {
            ctr_process(rx_cipher_, head); // decrypt the length field
            uint32_t len = read_u32be(head, 0);
            if (len < 2 || len > 65536) return false;
            std::string rest;
            if (!read_exact(len, rest)) return false;
            ctr_process(rx_cipher_, rest);
            std::string plain = head + rest;
            size_t maclen = rx_mac_ ? static_cast<size_t>(EVP_MD_size(rx_mac_))
                                    : 0;
            std::string mac;
            if (!read_exact(maclen, mac)) return false;
            ++seq_s2c_;
            if (mac != hmac_digest(rx_mac_, rx_mac_key_,
                                   seq_string(seq_s2c_ - 1) + plain))
                return false; // desync or wrong key derivation
            return unwrap(plain, payload);
        }
        uint32_t len = read_u32be(head, 0);
        if (len < 2 || len > 65536) return false;
        std::string rest;
        if (!read_exact(len, rest)) return false;
        ++seq_s2c_;
        return unwrap(head + rest, payload);
    }

    void enable_tx(const EVP_CIPHER* cipher, const std::string& key,
                   const std::string& iv, const EVP_MD* mac,
                   const std::string& mac_key) {
        tx_cipher_ = EVP_CIPHER_CTX_new();
        EVP_CipherInit_ex(tx_cipher_, cipher, nullptr,
                          reinterpret_cast<const unsigned char*>(key.data()),
                          reinterpret_cast<const unsigned char*>(iv.data()), 1);
        tx_mac_ = mac;
        tx_mac_key_ = mac_key;
    }

    void enable_rx(const EVP_CIPHER* cipher, const std::string& key,
                   const std::string& iv, const EVP_MD* mac,
                   const std::string& mac_key) {
        rx_cipher_ = EVP_CIPHER_CTX_new();
        EVP_CipherInit_ex(rx_cipher_, cipher, nullptr,
                          reinterpret_cast<const unsigned char*>(key.data()),
                          reinterpret_cast<const unsigned char*>(iv.data()), 0);
        rx_mac_ = mac;
        rx_mac_key_ = mac_key;
        crypto_rx_ = true;
    }

private:
    static bool unwrap(const std::string& pkt, std::string& payload) {
        uint32_t len = read_u32be(pkt, 0);
        if (len < 2 || 4 + len != pkt.size()) return false;
        uint8_t padlen = static_cast<uint8_t>(pkt[4]);
        if (1 + padlen > len) return false;
        payload = pkt.substr(5, len - 1 - padlen);
        return true;
    }

    TcpClient& client_;
    std::string buf_;
    int timeout_ms_;
    uint32_t seq_c2s_ = 0;
    uint32_t seq_s2c_ = 0;
    EVP_CIPHER_CTX* tx_cipher_ = nullptr;
    EVP_CIPHER_CTX* rx_cipher_ = nullptr;
    const EVP_MD* tx_mac_ = nullptr;
    const EVP_MD* rx_mac_ = nullptr;
    std::string tx_mac_key_, rx_mac_key_;
    bool crypto_rx_ = false;
};

std::string build_our_kexinit() {
    std::string p;
    p += static_cast<char>(20); // SSH_MSG_KEXINIT
    static std::mt19937_64 rng{std::random_device{}()};
    for (int i = 0; i < 16; ++i) p += static_cast<char>(rng() & 0xff);
    auto nl = [&p](const char* s) {
        put_u32be(p, static_cast<uint32_t>(std::strlen(s)));
        p += s;
    };
    nl("curve25519-sha256,curve25519-sha256@libssh.org,"
       "diffie-hellman-group14-sha256,diffie-hellman-group14-sha1");
    nl("ssh-ed25519,ecdsa-sha2-nistp256,rsa-sha2-512,rsa-sha2-256,ssh-rsa");
    nl("aes128-ctr,aes192-ctr,aes256-ctr");
    nl("aes128-ctr,aes192-ctr,aes256-ctr");
    nl("hmac-sha2-256,hmac-sha2-512,hmac-sha1");
    nl("hmac-sha2-256,hmac-sha2-512,hmac-sha1");
    nl("none");
    nl("none");
    nl("");
    nl("");
    p += static_cast<char>(0); // first_kex_packet_follows
    put_u32be(p, 0);           // reserved
    return p;
}

const EVP_MD* kex_hash(const std::string& kex) {
    if (kex.find("sha256") != std::string::npos) return EVP_sha256();
    return EVP_sha1();
}

const EVP_CIPHER* ctr_cipher(const std::string& name) {
    if (name == "aes128-ctr") return EVP_aes_128_ctr();
    if (name == "aes192-ctr") return EVP_aes_192_ctr();
    if (name == "aes256-ctr") return EVP_aes_256_ctr();
    return nullptr;
}

const EVP_MD* mac_md(const std::string& name) {
    if (name == "hmac-sha2-256") return EVP_sha256();
    if (name == "hmac-sha2-512") return EVP_sha512();
    if (name == "hmac-sha1") return EVP_sha1();
    return nullptr;
}

// RFC 4253 key derivation: K1 = HASH(K || H || X || session_id),
// K2 = HASH(K || H || K1), ...
std::string derive_key(const EVP_MD* md, const std::string& k_wire,
                       const std::string& h, char x,
                       const std::string& session_id, size_t need) {
    std::string out = digest(md, k_wire + h + x + session_id);
    std::string last = out;
    while (out.size() < need) {
        last = digest(md, k_wire + h + last);
        out += last;
    }
    out.resize(need);
    return out;
}

// Complete KEX + "none" auth request; fills algs.auth_*.
bool ssh_enumerate_auth(SshConn& conn, const std::string& our_banner,
                        const std::string& our_kexinit,
                        const std::string& server_kexinit, SshAlgorithms& algs) {
    static const std::vector<const char*> kex_ok = {
        "curve25519-sha256", "curve25519-sha256@libssh.org",
        "diffie-hellman-group14-sha256", "diffie-hellman-group14-sha1"};
    static const std::vector<const char*> cipher_ok = {"aes128-ctr",
                                                       "aes192-ctr",
                                                       "aes256-ctr"};
    static const std::vector<const char*> mac_ok = {
        "hmac-sha2-256", "hmac-sha2-512", "hmac-sha1"};

    std::string kex = pick_algorithm(algs.kex, kex_ok);
    std::string cipher_c2s = pick_algorithm(algs.ciphers_c2s, cipher_ok);
    std::string cipher_s2c = pick_algorithm(algs.ciphers_s2c, cipher_ok);
    std::string mac_c2s = pick_algorithm(algs.macs_c2s, mac_ok);
    std::string mac_s2c = pick_algorithm(algs.macs_s2c, mac_ok);
    if (kex.empty() || cipher_c2s.empty() || cipher_s2c.empty() ||
        mac_c2s.empty() || mac_s2c.empty())
        return false;

    const EVP_MD* md = kex_hash(kex);
    const EVP_CIPHER* ciph_c2s = ctr_cipher(cipher_c2s);
    const EVP_CIPHER* ciph_s2c = ctr_cipher(cipher_s2c);
    const EVP_MD* md_c2s = mac_md(mac_c2s);
    const EVP_MD* md_s2c = mac_md(mac_s2c);
    if (!md || !ciph_c2s || !ciph_s2c || !md_c2s || !md_s2c) return false;

    // Our DH share.
    bool use_x25519 = kex.rfind("curve25519", 0) == 0;
    std::string e_wire, priv;
    if (use_x25519) {
        std::string pub;
        if (!x25519_keypair(pub, priv)) return false;
        e_wire = ssh_string(pub);
    } else {
        if (!dh_group14_keypair(e_wire, priv)) return false;
    }

    // KEXDH_INIT (30) / ECDH_INIT.
    std::string init(1, static_cast<char>(30));
    init += e_wire;
    if (!conn.send_packet(init)) return false;

    // KEXDH_REPLY (31): K_S, f, signature (we never verify the signature —
    // the scanner does not trust the target's host key to begin with).
    std::string reply;
    bool got_reply = false;
    for (int i = 0; i < 6 && !got_reply; ++i) {
        if (!conn.recv_packet(reply)) return false;
        if (reply.empty()) return false;
        uint8_t msg = static_cast<uint8_t>(reply[0]);
        if (msg == 31) got_reply = true;
        else if (msg == 1) return false; // SSH_MSG_DISCONNECT
        // DEBUG/IGNORE/UNIMPL/stray guess packets are skipped
    }
    if (!got_reply) return false;
    size_t pos = 1;
    std::string ks, f_bytes, sig;
    if (!get_ssh_string(reply, pos, ks) ||
        !get_ssh_string(reply, pos, f_bytes) ||
        !get_ssh_string(reply, pos, sig))
        return false;

    // Shared secret K.
    std::string k_mpint;
    if (use_x25519) {
        std::string shared;
        if (!x25519_shared(priv, f_bytes, shared)) return false;
        k_mpint = to_mpint(shared);
    } else {
        if (!dh_group14_shared(priv, f_bytes, k_mpint)) return false;
    }

    // Exchange hash H = HASH(V_C || V_S || I_C || I_S || K_S || e || f || K).
    std::string h_buf;
    h_buf += ssh_string(our_banner);
    h_buf += ssh_string(algs.banner);
    h_buf += ssh_string(our_kexinit);
    h_buf += ssh_string(server_kexinit);
    h_buf += ssh_string(ks);
    h_buf += e_wire;
    h_buf += ssh_string(f_bytes);
    h_buf += ssh_string(k_mpint);
    std::string h = digest(md, h_buf);
    std::string session_id = h;
    std::string k_wire = ssh_string(k_mpint);

    std::string iv_c2s = derive_key(md, k_wire, h, 'A', session_id, 16);
    std::string iv_s2c = derive_key(md, k_wire, h, 'B', session_id, 16);
    std::string key_c2s =
        derive_key(md, k_wire, h, 'C', session_id,
                   static_cast<size_t>(EVP_CIPHER_key_length(ciph_c2s)));
    std::string key_s2c =
        derive_key(md, k_wire, h, 'D', session_id,
                   static_cast<size_t>(EVP_CIPHER_key_length(ciph_s2c)));
    std::string mackey_c2s =
        derive_key(md, k_wire, h, 'E', session_id,
                   static_cast<size_t>(EVP_MD_size(md_c2s)));
    std::string mackey_s2c =
        derive_key(md, k_wire, h, 'F', session_id,
                   static_cast<size_t>(EVP_MD_size(md_s2c)));

    // NEWKEYS: ours plain (last cleartext packet), then encrypt; the
    // server's NEWKEYS is still plain, everything after is not.
    if (!conn.send_packet(std::string(1, static_cast<char>(21)))) return false;
    conn.enable_tx(ciph_c2s, key_c2s, iv_c2s, md_c2s, mackey_c2s);
    std::string nk;
    bool got_newkeys = false;
    for (int i = 0; i < 4 && !got_newkeys; ++i) {
        if (!conn.recv_packet(nk)) return false;
        if (!nk.empty()) {
            uint8_t msg = static_cast<uint8_t>(nk[0]);
            if (msg == 21) got_newkeys = true;
            else if (msg == 1) return false;
        }
    }
    if (!got_newkeys) return false;
    conn.enable_rx(ciph_s2c, key_s2c, iv_s2c, md_s2c, mackey_s2c);

    // SERVICE_REQUEST (5) "ssh-userauth".
    std::string sreq(1, static_cast<char>(5));
    sreq += ssh_string("ssh-userauth");
    if (!conn.send_packet_enc(sreq)) return false;
    std::string sresp;
    bool accepted = false;
    for (int i = 0; i < 6 && !accepted; ++i) {
        if (!conn.recv_packet(sresp)) return false;
        if (sresp.empty()) return false;
        uint8_t msg = static_cast<uint8_t>(sresp[0]);
        if (msg == 6) accepted = true; // SERVICE_ACCEPT
        else if (msg == 1) return false;
    }
    if (!accepted) return false;

    // USERAUTH_REQUEST (50): user "audit", service "ssh-connection",
    // method "none" — the same first packet any SSH client sends.
    std::string areq(1, static_cast<char>(50));
    areq += ssh_string("audit");
    areq += ssh_string("ssh-connection");
    areq += ssh_string("none");
    if (!conn.send_packet_enc(areq)) return false;

    std::string aresp;
    for (int i = 0; i < 8; ++i) {
        if (!conn.recv_packet(aresp)) return false;
        if (aresp.empty()) return false;
        uint8_t msg = static_cast<uint8_t>(aresp[0]);
        if (msg == 52) { // USERAUTH_SUCCESS — no auth required at all
            algs.auth_none_accepted = true;
            algs.auth_enumerated = true;
            return true;
        }
        if (msg == 51) { // USERAUTH_FAILURE: method list
            size_t p2 = 1;
            std::string methods;
            if (get_ssh_string(aresp, p2, methods)) {
                algs.auth_methods = split_name_list(methods);
                algs.auth_enumerated = true;
                return true;
            }
            return false;
        }
        if (msg == 1) return false; // SSH_MSG_DISCONNECT
        // banners (53), EXT_INFO (7) etc. are skipped
    }
    return false;
}

} // namespace

#endif // SLEIPNIR_HAVE_TLS

SshAlgorithms ssh_audit(asio::io_context& io, const std::string& host,
                        uint16_t port, int timeout_ms, bool enumerate_auth,
                        ResultCollector& collector) {
    (void)collector;
    SshAlgorithms algs;
    TcpClient client(io);
    if (!client.connect(host, port, timeout_ms)) return algs;
    SshConn conn(client, timeout_ms);

    // Banner exchange (a few pre-banner lines are tolerated).
    std::string banner;
    bool have_banner = false;
    for (int i = 0; i < 4 && !have_banner; ++i) {
        if (!conn.read_banner_line(banner)) return algs;
        if (banner.rfind("SSH-", 0) == 0) have_banner = true;
    }
    if (!have_banner) return algs;
    algs.banner = banner;

    const std::string our_banner =
        "SSH-2.0-Sleipnir_" SLEIPNIR_VERSION;
    client.send(our_banner + "\r\n");

    std::string our_kexinit = build_our_kexinit();
    if (!conn.send_packet(our_kexinit)) return algs;

    // Server KEXINIT (the algorithm lists are sent in the clear).
    std::string server_kexinit;
    bool got = false;
    for (int i = 0; i < 4 && !got; ++i) {
        if (!conn.recv_packet(server_kexinit)) return algs;
        if (!server_kexinit.empty() &&
            static_cast<uint8_t>(server_kexinit[0]) == 20)
            got = true;
    }
    if (!got) return algs;
    if (!parse_ssh_kexinit(server_kexinit, algs)) return algs;

#ifdef SLEIPNIR_HAVE_TLS
    if (enumerate_auth)
        ssh_enumerate_auth(conn, our_banner, our_kexinit, server_kexinit,
                           algs);
#else
    (void)enumerate_auth;
#endif
    return algs;
}

// ---------------------------------------------------------------------------
// SMB
// ---------------------------------------------------------------------------

namespace {

std::string smb1_header(uint8_t command, uint16_t tid, uint16_t uid) {
    std::string h;
    h += static_cast<char>(0xFF);
    h += "SMB";
    h += static_cast<char>(command);
    put_u32le(h, 0);                    // status
    h += static_cast<char>(0x18);       // flags
    put_u16le(h, 0x4801);               // flags2: long names + ext sec + NT status
    put_u16le(h, 0);                    // pid high
    h.append(8, '\0');                  // signature
    put_u16le(h, 0);                    // reserved
    put_u16le(h, tid);
    put_u16le(h, 0x1234);               // pid
    put_u16le(h, uid);
    put_u16le(h, 0x0001);               // mid
    return h;
}

std::string smb1_negotiate_request() {
    std::string dialects;
    for (const char* d : {"PC NETWORK PROGRAM 1.0", "LANMAN1.0",
                          "Windows for Workgroups", "LM1.2X002", "LANMAN2.1",
                          "NT LM 0.12"}) {
        dialects += static_cast<char>(0x02);
        dialects += d;
        dialects += '\0';
    }
    std::string msg = smb1_header(0x72, 0, 0);
    msg += static_cast<char>(0); // word count
    put_u16le(msg, static_cast<uint16_t>(dialects.size()));
    msg += dialects;
    return msg;
}

// NTLMSSP type 1 (NEGOTIATE): anonymous, OEM strings.
std::string ntlmssp_negotiate() {
    const uint32_t flags = 0x0000020E; // OEM | ANONYMOUS | REQUEST_TARGET | NTLM
    std::string body = "NTLMSSP\0";
    put_u32le(body, 1); // type
    put_u32le(body, flags);
    // supplied domain (empty), supplied workstation (empty)
    put_u16le(body, 0);
    put_u16le(body, 0);
    put_u32le(body, 40);
    put_u16le(body, 0);
    put_u16le(body, 0);
    put_u32le(body, 40);
    return body;
}

// NTLMSSP type 3 (AUTHENTICATE): anonymous (LM response = the 1-byte
// marker 0x01) with an optional account name (guest attempts).
std::string ntlmssp_authenticate(const std::string& user) {
    const uint32_t flags = 0x0000020E;
    std::string body = "NTLMSSP\0";
    put_u32le(body, 3); // type

    // String fields in order: LM response, NT response, domain, user,
    // workstation, session key — each Len2 MaxLen2 Offset4. The payload
    // starts at byte 64 (8 + 4 + 6*8 + 4).
    auto field = [&body](size_t len, size_t offset) {
        put_u16le(body, static_cast<uint16_t>(len));
        put_u16le(body, static_cast<uint16_t>(len));
        put_u32le(body, static_cast<uint32_t>(offset));
    };
    field(1, 64);             // LM response: the anonymous marker
    field(0, 65);             // NT response
    field(0, 65);             // domain
    field(user.size(), 65);   // user name
    field(0, 65);             // workstation
    field(0, 65);             // session key
    put_u32le(body, flags);   // negotiate flags
    body += static_cast<char>(0x01); // the anonymous LM response
    body += user;
    return body;
}

std::string smb1_session_setup(const std::string& security_blob,
                               uint16_t uid) {
    std::string msg = smb1_header(0x73, 0, uid);
    msg += static_cast<char>(13); // word count
    put_u16le(msg, 0x00FF);       // AndX: none
    put_u16le(msg, 0);            // AndXOffset
    put_u32le(msg, 4356);         // max buffer
    put_u16le(msg, 2);            // max mpx
    put_u16le(msg, 1);            // vc number
    put_u32le(msg, 0);            // session key
    put_u16le(msg, static_cast<uint16_t>(security_blob.size()));
    put_u32le(msg, 0);            // reserved
    put_u32le(msg, 0x0000004D);   // capabilities
    std::string tail = security_blob;
    tail += "Unix\0";
    tail += "Sleipnir\0";
    put_u16le(msg, static_cast<uint16_t>(tail.size()));
    msg += tail;
    return msg;
}

std::string smb1_tree_connect_ipc(uint16_t uid, const std::string& host) {
    std::string msg = smb1_header(0x75, 0, uid);
    msg += static_cast<char>(4); // word count
    put_u16le(msg, 0x00FF);      // AndX: none
    put_u16le(msg, 0);           // AndXOffset
    put_u16le(msg, 0);           // flags
    put_u16le(msg, 1);           // password length (1 null byte)
    std::string path = "\\\\" + host + "\\IPC$";
    path += '\0';
    std::string tail(1, '\0');
    tail += path;
    tail += "IPC\0";
    put_u16le(msg, static_cast<uint16_t>(tail.size()));
    msg += tail;
    return msg;
}

std::string smb1_rap_netshareenum(uint16_t tid, uint16_t uid) {
    std::string params;
    put_u16le(params, 0);     // RAP API number: NetShareEnum
    params += "WrLeh\0";
    params += "B13BWz\0";
    put_u16le(params, 1);     // level
    put_u16le(params, 4096);  // client receive buffer

    std::string msg = smb1_header(0x25, tid, uid);
    msg += static_cast<char>(14); // word count
    const size_t header_len = 32 + 1 + 14 * 2 + 2;
    std::string name = "\\PIPE\\LANMAN\0";
    const size_t pad = (header_len + name.size()) % 2;
    const size_t param_offset = header_len + name.size() + pad;

    put_u16le(msg, static_cast<uint16_t>(params.size())); // total param
    put_u16le(msg, 0);                                    // total data
    put_u16le(msg, 6);                                    // max param
    put_u16le(msg, 4096);                                 // max data
    put_u16le(msg, 0);                                    // max setup
    put_u16le(msg, 0);                                    // reserved
    put_u16le(msg, 0);                                    // flags
    put_u32le(msg, 0);                                    // timeout
    put_u16le(msg, 0);                                    // reserved2
    put_u16le(msg, static_cast<uint16_t>(params.size())); // param count
    put_u16le(msg, static_cast<uint16_t>(param_offset));  // param offset
    put_u16le(msg, 0);                                    // data count
    put_u16le(msg, 0);                                    // data offset
    put_u16le(msg, 0);                                    // setup count
    put_u16le(msg, static_cast<uint16_t>(params.size())); // byte count
    msg += name;
    msg.append(pad, '\0');
    msg += params;
    return msg;
}

std::string smb2_negotiate_request() {
    std::string msg;
    msg += static_cast<char>(0xFE);
    msg += "SMB";
    put_u16le(msg, 36);   // structure size
    put_u16le(msg, 5);    // dialect count
    put_u16le(msg, 0);    // security mode
    put_u16le(msg, 0);    // reserved
    put_u32le(msg, 0);    // capabilities
    msg.append(16, '\0'); // client guid
    put_u32le(msg, 0);    // negotiate context offset
    put_u16le(msg, 0);    // negotiate context count
    put_u16le(msg, 0);    // reserved2
    put_u16le(msg, 0x0202);
    put_u16le(msg, 0x0210);
    put_u16le(msg, 0x0300);
    put_u16le(msg, 0x0302);
    put_u16le(msg, 0x0311);
    return msg;
}

// NBSS session-message wrapper (port 139 direct IPX... rather NBT).
std::string nbss_wrap(const std::string& smb) {
    std::string s;
    s += static_cast<char>(0x00);
    s += static_cast<char>((smb.size() >> 16) & 0xff);
    s += static_cast<char>((smb.size() >> 8) & 0xff);
    s += static_cast<char>(smb.size() & 0xff);
    s += smb;
    return s;
}

bool nbss_unwrap(const std::string& raw, std::string& out) {
    if (raw.size() < 4) return false;
    uint32_t len = (static_cast<uint32_t>(static_cast<uint8_t>(raw[1]))
                    << 16) |
                   (static_cast<uint32_t>(static_cast<uint8_t>(raw[2]))
                    << 8) |
                   static_cast<uint32_t>(static_cast<uint8_t>(raw[3]));
    if (raw.size() < 4 + len) return false;
    out = raw.substr(4, len);
    return true;
}

uint32_t smb1_status(const std::string& msg) { return read_u32le(msg, 5); }

uint16_t smb1_uid(const std::string& msg) {
    size_t pos = 28;
    uint16_t v = 0;
    get_u16le(msg, pos, v);
    return v;
}

uint16_t smb1_tid(const std::string& msg) {
    size_t pos = 24;
    uint16_t v = 0;
    get_u16le(msg, pos, v);
    return v;
}

} // namespace

bool smb_parse_negotiate_response(const std::string& message, SmbInfo& info) {
    if (message.size() < 36) return false;
    if (static_cast<uint8_t>(message[0]) != 0xFF || message[1] != 'S' ||
        message[2] != 'M' || message[3] != 'B' ||
        static_cast<uint8_t>(message[4]) != 0x72)
        return false;
    uint8_t wc = static_cast<uint8_t>(message[32]);
    if (wc != 17) return false;
    // words start after wc; word 0 = dialect index, word 1 = security mode
    uint8_t secmode = static_cast<uint8_t>(message[35]);
    info.smb1_enabled = true;
    info.signing_enabled = (secmode & 0x04) != 0;
    info.signing_required = (secmode & 0x08) != 0;
    return true;
}

bool smb_parse_smb2_negotiate_response(const std::string& message,
                                        SmbInfo& info) {
    if (message.size() < 10) return false;
    if (static_cast<uint8_t>(message[0]) != 0xFE || message[1] != 'S' ||
        message[2] != 'M' || message[3] != 'B')
        return false;
    uint16_t secmode = static_cast<uint16_t>(
        static_cast<uint8_t>(message[6]) |
        (static_cast<uint16_t>(static_cast<uint8_t>(message[7])) << 8));
    info.smb2_responded = true;
    info.signing_enabled = (secmode & 0x01) != 0;
    info.signing_required = (secmode & 0x02) != 0;
    return true;
}

std::vector<std::string> smb_parse_rap_shares(const std::string& params,
                                               const std::string& data) {
    std::vector<std::string> shares;
    size_t pos = 0;
    uint16_t status = 0, entries = 0;
    if (!get_u16le(params, pos, status)) return shares;
    pos += 2; // converter
    if (!get_u16le(params, pos, entries)) return shares;
    if (status != 0) return shares;
    size_t off = 0;
    for (uint16_t i = 0; i < entries; ++i) {
        if (off + 19 > data.size()) break;
        std::string name = data.substr(off, 13);
        size_t nul = name.find('\0');
        if (nul != std::string::npos) name.resize(nul);
        uint16_t type =
            static_cast<uint16_t>(static_cast<uint8_t>(data[off + 13]) |
                                  (static_cast<uint16_t>(
                                       static_cast<uint8_t>(data[off + 14]))
                                   << 8));
        // IPC shares (type 3) are structural; everything else is listed.
        if (!name.empty() && (type & 0x0F) != 3) shares.push_back(name);
        off += 19;
    }
    return shares;
}

SmbInfo smb_audit(asio::io_context& io, const std::string& host, uint16_t port,
                  int timeout_ms, bool allow_session,
                  ResultCollector& collector) {
    SmbInfo info;
    const bool nbss = (port == 139);

    auto send_recv = [&](TcpClient& c, const std::string& msg,
                         std::string& out) -> bool {
        if (!c.send(nbss ? nbss_wrap(msg) : msg)) return false;
        std::string raw = c.recv_all(timeout_ms, 400, 65536);
        if (raw.empty()) return false;
        if (nbss) return nbss_unwrap(raw, out);
        out = raw;
        return true;
    };

    // 1. SMB1 NEGOTIATE: SMBv1 enabled? signing policy?
    {
        TcpClient c(io);
        if (c.connect(host, port, timeout_ms)) {
            std::string resp;
            if (send_recv(c, smb1_negotiate_request(), resp))
                smb_parse_negotiate_response(resp, info);
        }
    }

    // 2. SMB2 NEGOTIATE: dialect + signing policy (independent listener
    // state; servers with SMB1 disabled only answer this one).
    {
        TcpClient c(io);
        if (c.connect(host, port, timeout_ms)) {
            std::string resp;
            if (send_recv(c, smb2_negotiate_request(), resp)) {
                SmbInfo two;
                if (smb_parse_smb2_negotiate_response(resp, two)) {
                    info.smb2_responded = true;
                    if (!info.smb1_enabled) {
                        info.signing_enabled = two.signing_enabled;
                        info.signing_required = two.signing_required;
                    }
                }
            }
        }
    }

    // 3. Null/guest session + RAP share enumeration (SMB1 only — the
    // anonymous RAP path is exactly the classic null-session attack).
    if (allow_session && info.smb1_enabled) {
        TcpClient c(io);
        if (c.connect(host, port, timeout_ms)) {
            // Null first, guest second — both start with the same NTLMSSP
            // NEGOTIATE; only the AUTHENTICATE leg differs (anonymous
            // without vs. with an account name).
            std::string resp;
            uint16_t uid = 0;
            bool session_ok = false;
            bool guest = false;
            for (int attempt = 0; attempt < 2 && !session_ok; ++attempt) {
                guest = (attempt == 1);
                if (!send_recv(c, smb1_session_setup(ntlmssp_negotiate(), uid),
                               resp))
                    break;
                uint32_t status = smb1_status(resp);
                if (status == 0) {
                    // Session granted on the anonymous NEGOTIATE alone —
                    // a null session, whatever attempt we are on.
                    session_ok = true;
                    guest = false;
                } else if (status == 0xC0000016) { // MORE_PROCESSING_REQUIRED
                    uid = smb1_uid(resp);
                    std::string auth = ntlmssp_authenticate(guest ? "Guest"
                                                                  : "");
                    std::string resp2;
                    if (send_recv(c, smb1_session_setup(auth, uid), resp2)) {
                        if (smb1_status(resp2) == 0)
                            session_ok = true;
                        else
                            resp = resp2; // keep the freshest header
                    }
                }
                // any rejection falls through to the next attempt
            }
            if (session_ok) {
                uid = smb1_uid(resp);
                if (guest)
                    info.guest_session_ok = true;
                else
                    info.null_session_ok = true;
                collector.log("  [smb] " + host + ":" +
                              std::to_string(port) + " " +
                              (guest ? "guest" : "null") +
                              " session established");
            }

            // Share enumeration via RAP over IPC$.
            if (session_ok) {
                std::string tc;
                if (send_recv(c, smb1_tree_connect_ipc(uid, host), tc) &&
                    smb1_status(tc) == 0) {
                    uint16_t tid = smb1_tid(tc);
                    std::string rap;
                    if (send_recv(c, smb1_rap_netshareenum(tid, uid), rap) &&
                        rap.size() > 64 &&
                        static_cast<uint8_t>(rap[4]) == 0x25) {
                        // TRANSACTION response: word count at 32.
                        uint8_t wc = static_cast<uint8_t>(rap[32]);
                        if (wc >= 10) {
                            size_t w = 33;
                            uint16_t total_param = 0, total_data = 0,
                                     param_count = 0, param_offset = 0,
                                     data_count = 0, data_offset = 0;
                            get_u16le(rap, w, total_param);
                            get_u16le(rap, w, total_data);
                            w += 2; // reserved
                            get_u16le(rap, w, param_count);
                            get_u16le(rap, w, param_offset);
                            get_u16le(rap, w, data_count);
                            get_u16le(rap, w, data_offset);
                            (void)total_param;
                            (void)total_data;
                            if (param_offset + param_count <= rap.size() &&
                                data_offset + data_count <= rap.size()) {
                                std::string params =
                                    rap.substr(param_offset, param_count);
                                std::string data =
                                    rap.substr(data_offset, data_count);
                                info.shares =
                                    smb_parse_rap_shares(params, data);
                            }
                        }
                    }
                }
            }
        }
    }
    return info;
}

std::vector<Finding> smb_audit_findings(const std::string& host, uint16_t port,
                                        const SmbInfo& info) {
    std::vector<Finding> out;
    auto add = [&](const std::string& title, Severity sev,
                   const std::string& description, const std::string& evidence) {
        Finding f;
        f.host = host;
        f.port = port;
        f.title = title;
        f.severity = sev;
        f.description = description;
        f.evidence = evidence;
        f.source = "proto-audit";
        f.verified = true;
        f.confidence = "confirmed";
        out.push_back(std::move(f));
    };

    if (info.smb1_enabled)
        add("SMBv1 protocol enabled", Severity::High,
            "The server negotiated the SMBv1 dialect. SMBv1 is a legacy "
            "protocol with no modern integrity or confidentiality features "
            "and a long exploit history (EternalBlue/WannaCry RCE worms). "
            "Disable SMBv1 in the server configuration.",
            "SMB1 NEGOTIATE answered with dialect NT LM 0.12");

    if (info.smb1_enabled || info.smb2_responded) {
        if (!info.signing_enabled)
            add("SMB signing disabled", Severity::Medium,
                "The server does not request SMB message signing. "
                "Unauthenticated relay attacks (NTLM relay to SMB) can "
                "execute remote operations on behalf of any "
                "authenticated user whose traffic can be intercepted.",
                "SMB negotiate response: signing not enabled");
        else if (!info.signing_required)
            add("SMB signing enabled but not required", Severity::Low,
                "The server supports SMB signing but accepts unsigned "
                "messages. An attacker positioned on the network can "
                "downgrade sessions to unsigned mode; require signing on "
                "both SMB server and client sides.",
                "SMB negotiate response: signing enabled, not required");
    }

    if (info.null_session_ok)
        add("SMB null session allowed", Severity::High,
            "The server accepted an anonymous (null) session setup. Null "
            "sessions are the classic foothold for information disclosure "
            "on Windows domains: user and share enumeration, and on "
            "misconfigured hosts remote registry access. Restrict "
            "anonymous access (restrictanonymous / server services "
            "configuration).",
            "anonymous NTLMSSP session setup -> STATUS_SUCCESS");

    if (info.guest_session_ok)
        add("SMB guest session allowed", Severity::Medium,
            "The server accepted a session with the built-in guest "
            "account. Guest access defeats authentication on any share "
            "that maps unknown users to guest. Disable the guest account.",
            "NTLMSSP session setup as 'Guest' -> STATUS_SUCCESS");

    if (!info.shares.empty()) {
        std::string list;
        for (const auto& s : info.shares) {
            if (!list.empty()) list += ", ";
            list += s;
        }
        add("SMB shares enumerated without credentials", Severity::Low,
            "The share list was retrieved through an unauthenticated "
            "session (RAP NetShareEnum). The names and types of shares "
            "give an attacker the map of interesting data. Restrict "
            "anonymous enumeration.",
            "shares: " + list);
    }
    return out;
}

} // namespace sln
