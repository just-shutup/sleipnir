// SYN ("half-open", stealth) port discovery over Linux raw sockets. The
// scanner sends crafted TCP SYNs with a raw sender socket and watches a
// packet socket for the replies: SYN|ACK -> open, RST -> closed, silence
// until the deadline -> filtered. No connection is ever completed, so most
// services do not log the probe. Requires root or CAP_NET_RAW; when raw
// sockets are unavailable the caller falls back to the connect scan.
#pragma once

#include "sleipnir/results.hpp"
#include "sleipnir/types.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace sln {

// TCP flag bits as they appear in a packet (offset 13 of the TCP header).
constexpr uint8_t kTcpFin = 0x01;
constexpr uint8_t kTcpSyn = 0x02;
constexpr uint8_t kTcpRst = 0x04;
constexpr uint8_t kTcpPsh = 0x08;
constexpr uint8_t kTcpAck = 0x10;

// Reply classification: SYN|ACK means the port is open, RST means closed,
// anything else is treated as filtered (unexpected shapes still deserve a
// state and the packet was clearly answered by a live host).
PortStatus syn_status_from_flags(uint8_t tcp_flags);

// RFC 1071 ones-complement checksum over an even number of bytes (the
// caller pads odd-length inputs).
uint16_t ones_complement_checksum(const uint8_t* data, size_t len);

struct SynOutcome {
    std::string host;
    uint16_t port;
    PortStatus status;
    int ttl = 0;           // IP TTL of the SYN-ACK reply (0 = unknown)
    uint16_t window = 0;   // TCP window of the SYN-ACK reply (0 = unknown)
};

// Passive/light OS classification (p0f-style) from the initial TTL and the
// TCP window of a SYN-ACK. Initial TTL stacks: 64 = Linux, 128 = Windows,
// 255 = Cisco/BSD; the received TTL minus the initial one estimates the hop
// count. The window refines the family guess. Cheap by construction: both
// values ride along with every SYN-ACK the scanner already processes.
struct OsGuess {
    std::string family;   // "linux" | "windows" | "cisco/bsd" | "" (unknown)
    std::string detail;   // human-readable summary for logs and reports
    int initial_ttl = 0;  // estimated initial TTL (64/128/255)
    int distance = 0;     // estimated hop count
};

// Pure classifier: ttl <= 0 returns an empty (unknown) guess.
OsGuess os_guess_from_synack(int ttl, uint16_t window);

// IPv4 SYN discovery for every (host, port). Hostnames are resolved to IPv4
// first; if any target has no IPv4 address (IPv6-only) raw-socket scanning
// is impossible for the batch, so nullopt is returned for the caller to
// fall back. send_delay_ms paces packets (per-packet pause) — the paranoid
// timing profiles pass a value here.
std::optional<std::vector<SynOutcome>> syn_discover(
    const std::vector<std::string>& hosts, const std::vector<uint16_t>& ports,
    int timeout_ms, int send_delay_ms, ResultCollector& collector);

} // namespace sln
