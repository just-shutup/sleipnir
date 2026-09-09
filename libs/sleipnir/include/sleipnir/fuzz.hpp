// Mutation-based robustness fuzzer for network services: sends malformed or
// oversized payloads to an open port and reports services that reset
// connections or stop responding entirely (possible crash / buffer
// overflow). Intended for use against your own test stands only.
#pragma once

#include "sleipnir/results.hpp"
#include "sleipnir/types.hpp"

#include <asio.hpp>

#include <string>
#include <vector>

namespace sln {

// Cooperative stop flag for fuzz sessions (set by the engine on Ctrl+C).
void fuzz_request_stop();

// Clear the fuzz stop flag before a new session.
void fuzz_reset_stop();

class TcpClient;

// Deterministic payload set: oversized 'A' runs, format-string abuse,
// protocol delimiter floods, path traversal and random binary blobs.
std::vector<std::string> build_fuzz_payloads(int max_len);

// Runs the fuzz session against host:port. `alive_before` must reflect that
// the service was reachable moments ago.
void run_fuzz(asio::io_context& io, const std::string& host, uint16_t port,
              const ScanConfig& cfg, ResultCollector& out);

} // namespace sln
