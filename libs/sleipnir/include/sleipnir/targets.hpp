// Target & port spec parsing and expansion.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace sln {

// Expand "127.0.0.1,10.0.0.0/30,2001:db8::/126,example.com" into a flat
// list of hosts. IPv4 and IPv6 CIDR ranges are expanded locally, literals
// pass through (brackets are stripped), hostnames are DNS-resolved (A/AAAA).
// Returns the list plus a human-readable error for unresolvable entries.
// Throws std::runtime_error on a malformed spec.
std::vector<std::string> expand_targets(const std::vector<std::string>& specs,
                                        size_t max_hosts = 65536);

// Expand port spec "80,443,1000-2000,top100" into unique sorted port list.
// Throws std::runtime_error on malformed input or out-of-range ports.
std::vector<uint16_t> expand_ports(const std::string& spec);

} // namespace sln
