// Factory-default credential dictionary and the protocol-level login
// attempts behind --brute-default-creds (FTP, MySQL, Redis; the HTTP
// Basic variant lives in the header as a transport template).
//
// Opt-in by design: login attempts can trip account lockouts and show up
// in authentication logs, so the scanner never sends them unless asked —
// and never in --safe mode.

#include "sleipnir/proto_audit.hpp"

#include <algorithm>
#include <cstring>

#ifdef SLEIPNIR_HAVE_TLS
#include <openssl/evp.h>
#include <openssl/sha.h>
#endif

namespace sln {

namespace {

#ifdef SLEIPNIR_HAVE_TLS
std::string sha1(const std::string& data) {
    unsigned char out[SHA_DIGEST_LENGTH];
    unsigned int len = 0;
    EVP_Digest(data.data(), data.size(), out, &len, EVP_sha1(), nullptr);
    return std::string(reinterpret_cast<char*>(out), len);
}
#endif

// MySQL packet framing: 3-byte length + sequence number.
std::string mysql_packet(const std::string& payload, uint8_t seq) {
    std::string s;
    s += static_cast<char>(payload.size() & 0xff);
    s += static_cast<char>((payload.size() >> 8) & 0xff);
    s += static_cast<char>((payload.size() >> 16) & 0xff);
    s += static_cast<char>(seq);
    s += payload;
    return s;
}

struct MySqlGreeting {
    std::string version;
    std::string nonce; // 20 bytes
};

// Parses a MySQL handshake greeting packet (with the 4-byte framing).
bool mysql_parse_greeting(const std::string& raw, MySqlGreeting& out) {
    if (raw.size() < 5 + 32) return false;
    const std::string p = raw.substr(4); // strip framing
    size_t pos = 0;
    uint8_t proto = static_cast<uint8_t>(p[pos++]);
    if (proto != 10) return false; // v4.1+ only
    size_t nul = p.find('\0', pos);
    if (nul == std::string::npos) return false;
    out.version = p.substr(pos, nul - pos);
    pos = nul + 1;
    pos += 4; // thread id
    if (pos + 8 + 1 + 2 + 1 + 2 + 2 + 1 + 10 + 12 > p.size()) return false;
    std::string nonce1 = p.substr(pos, 8);
    pos += 8 + 1;                        // salt part 1 + filler
    pos += 2 + 1 + 2 + 2 + 1 + 10;       // caps lo, charset, status, caps hi, auth len, reserved
    std::string nonce2 = p.substr(pos, 12);
    out.nonce = nonce1 + nonce2;
    return out.nonce.size() == 20;
}

bool ftp_try_login(asio::io_context& io, const std::string& host,
                   uint16_t port, const DefaultCred& cred, int timeout_ms) {
    TcpClient c(io);
    if (!c.connect(host, port, timeout_ms)) return false;
    std::string greeting = c.recv_all(timeout_ms, 400, 4096);
    if (greeting.compare(0, 3, "220") != 0) return false;
    c.send("USER " + cred.user + "\r\n");
    std::string r = c.recv_all(timeout_ms, 400, 4096);
    if (r.compare(0, 3, "230") == 0) return true;  // user alone suffices
    if (r.compare(0, 3, "331") != 0) return false; // need password
    c.send("PASS " + cred.password + "\r\n");
    std::string r2 = c.recv_all(timeout_ms, 400, 4096);
    return r2.compare(0, 3, "230") == 0;
}

#ifdef SLEIPNIR_HAVE_TLS
bool mysql_try_login(asio::io_context& io, const std::string& host,
                     uint16_t port, const DefaultCred& cred, int timeout_ms) {
    TcpClient c(io);
    if (!c.connect(host, port, timeout_ms)) return false;
    std::string greeting = c.recv_all(timeout_ms, 400, 8192);
    MySqlGreeting g;
    if (!mysql_parse_greeting(greeting, g)) return false;
    std::string scramble = mysql_scramble(cred.password, g.nonce);
    if (scramble.empty()) return false;
    if (!c.send(mysql_handshake_response(cred.user, scramble))) return false;
    std::string reply = c.recv_all(timeout_ms, 400, 8192);
    if (reply.size() < 5) return false;
    return static_cast<uint8_t>(reply[4]) == 0x00; // OK packet
}
#endif

// Returns the working password when AUTH succeeds on a password-protected
// Redis ("" when the instance answers PONG without auth — that case is
// reported by the redis_unauth plugin, not here).
bool redis_default_password(asio::io_context& io, const std::string& host,
                            uint16_t port, int timeout_ms,
                            std::string& used_password) {
    TcpClient c(io);
    if (!c.connect(host, port, timeout_ms)) return false;
    c.send("PING\r\n");
    std::string r = c.recv_all(timeout_ms, 400, 4096);
    if (r.find("+PONG") == 0) return false;      // no auth at all
    if (r.find("-NOAUTH") == std::string::npos) return false;
    for (const auto& cred : default_creds_for("redis")) {
        c.send("AUTH " + cred.password + "\r\n");
        std::string ar = c.recv_all(timeout_ms, 400, 4096);
        if (ar.find("+OK") == 0) {
            used_password = cred.password;
            return true;
        }
    }
    return false;
}

Finding cred_finding(const std::string& host, uint16_t port,
                     const std::string& service_name, const DefaultCred& cred,
                     const std::string& evidence) {
    Finding f;
    f.host = host;
    f.port = port;
    f.title = "Default " + service_name + " credentials accepted: " + cred.user +
              ":" + (cred.password.empty() ? "<empty>" : cred.password);
    f.severity = Severity::Critical;
    f.description =
        "The " + service_name +
        " service accepts a factory default account (" + cred.user + "). "
        "Anyone reading the product documentation gets the same access as "
        "a legitimate administrator. Change the credential, disable the "
        "account, and enforce strong passwords.";
    f.evidence = evidence;
    f.source = "proto-audit";
    f.verified = true;
    f.confidence = "confirmed";
    return f;
}

} // namespace

std::vector<DefaultCred> default_creds_for(const std::string& service) {
    if (service == "ftp")
        return {{"admin", "admin"},   {"admin", "password"},
                {"admin", "123456"},  {"root", "root"},
                {"ftp", "ftp"},       {"test", "test"},
                {"user", "user"}};
    if (service == "mysql")
        return {{"root", ""},        {"root", "root"},
                {"root", "mysql"},   {"root", "password"},
                {"mysql", "mysql"},  {"admin", "admin"}};
    if (service == "redis")
        return {{"default", "redis"},    {"default", "foobared"},
                {"default", "changeme"}, {"default", "password"},
                {"default", "admin"},    {"default", "root"},
                {"default", "123456"}};
    if (service == "http-basic")
        return {{"admin", "admin"},    {"admin", "password"},
                {"admin", "123456"},   {"admin", "admin123"},
                {"root", "root"},      {"tomcat", "tomcat"},
                {"tomcat", "s3cret"},  {"manager", "manager"},
                {"guest", "guest"},    {"test", "test"}};
    return {};
}

std::string mysql_scramble(const std::string& password,
                           const std::string& nonce) {
#ifdef SLEIPNIR_HAVE_TLS
    if (nonce.size() != 20) return "";
    // SHA1(pass) XOR SHA1(nonce + SHA1(SHA1(pass)))
    std::string h1 = sha1(password);
    std::string h2 = sha1(sha1(h1));
    std::string h3 = sha1(nonce + h2);
    std::string out(20, '\0');
    for (size_t i = 0; i < 20; ++i)
        out[i] = static_cast<char>(static_cast<uint8_t>(h1[i]) ^
                                   static_cast<uint8_t>(h3[i]));
    return out;
#else
    (void)password;
    (void)nonce;
    return "";
#endif
}

std::string mysql_handshake_response(const std::string& user,
                                     const std::string& scramble) {
    // HandshakeResponse41, mysql_native_password.
    const uint32_t caps = 0x00000001   // CLIENT_LONG_PASSWORD
                          | 0x00000200 // CLIENT_PROTOCOL_41
                          | 0x00008000 // CLIENT_SECURE_CONNECTION
                          | 0x00080000; // CLIENT_PLUGIN_AUTH
    std::string p;
    p += static_cast<char>(caps & 0xff);
    p += static_cast<char>((caps >> 8) & 0xff);
    p += static_cast<char>((caps >> 16) & 0xff);
    p += static_cast<char>((caps >> 24) & 0xff);
    p += static_cast<char>(0); // max packet 16MB
    p += static_cast<char>(0);
    p += static_cast<char>(1);
    p += static_cast<char>(0);
    p += static_cast<char>(33); // charset utf8
    p.append(23, '\0');
    p += user;
    p += '\0';
    p += static_cast<char>(20); // auth response length
    p += scramble;
    p += "mysql_native_password";
    p += '\0';
    return mysql_packet(p, 1);
}

std::vector<Finding> default_creds_audit(asio::io_context& io,
                                         const std::string& service,
                                         const std::string& banner,
                                         const std::string& host,
                                         uint16_t port, int timeout_ms,
                                         ResultCollector& collector) {
    (void)collector;
    (void)banner;
    std::vector<Finding> out;

    if (service == "ftp") {
        for (const auto& cred : default_creds_for("ftp")) {
            if (ftp_try_login(io, host, port, cred, timeout_ms)) {
                out.push_back(cred_finding(host, port, "FTP", cred,
                                           "USER " + cred.user + " / PASS " +
                                               (cred.password.empty()
                                                    ? "<empty>"
                                                    : cred.password) +
                                               " -> 230"));
                break;
            }
        }
        return out;
    }

    if (service == "mysql") {
#ifdef SLEIPNIR_HAVE_TLS
        for (const auto& cred : default_creds_for("mysql")) {
            if (mysql_try_login(io, host, port, cred, timeout_ms)) {
                out.push_back(cred_finding(
                    host, port, "MySQL", cred,
                    "mysql_native_password handshake as " + cred.user +
                        " -> OK packet"));
                break;
            }
        }
#endif
        return out;
    }

    if (service == "redis") {
        std::string password;
        if (redis_default_password(io, host, port, timeout_ms, password)) {
            DefaultCred cred{"default", password};
            out.push_back(cred_finding(host, port, "Redis", cred,
                                       "AUTH " + password + " -> +OK"));
        }
        return out;
    }
    return out;
}

} // namespace sln
