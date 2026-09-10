// UDP service discovery with per-port probe payloads (nmap-style): a
// datagram is sent to the port and the reply — or its absence — is
// interpreted. Requires no privileges: connecting the UDP socket makes the
// kernel deliver ICMP port-unreachable errors as ECONNREFUSED, which maps
// to "closed"; silence means "open|filtered"; a reply is "open" and gets
// classified by its shape.
#pragma once

#include "sleipnir/results.hpp"
#include "sleipnir/types.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace sln {

struct UdpProbe {
    uint16_t port;
    const char* service;   // classification when a reply comes back
    const char* payload_hex;
};

// Probe registered for the port (nullptr when none — a bare empty datagram
// is sent instead, still enough to distinguish closed from filtered).
const UdpProbe* udp_probe_for(uint16_t port);

// Service name for a reply received on the port, or "" when the reply does
// not match the expected shape (falls back to the probe's default service).
std::string udp_classify(uint16_t port, const std::string& reply);

// Probes every (host, port) pair and returns one row per endpoint, with
// Open (reply), Closed (refused) or Filtered (timeout) statuses. SNMP
// 'public' and DNS version.bind answers raise findings through the
// collector. hosts may contain IPv4 and IPv6 literals/hostnames.
std::vector<PortResult> udp_discover(const std::vector<std::string>& hosts,
                                     const std::vector<uint16_t>& ports,
                                     int timeout_ms, int threads,
                                     ResultCollector& collector);

} // namespace sln
