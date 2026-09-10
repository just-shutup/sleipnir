// Blocking-style TCP client with per-operation deadlines, built on async
// Asio operations. Every operation runs on a worker-local single-threaded
// io_context: an async operation and a steady_timer race each other, so no
// thread ever blocks on I/O beyond the configured timeout. This keeps the
// code portable (no raw native socket APIs) and free of C++20 coroutines.
#pragma once

#include <asio.hpp>

#include <cstdint>
#include <optional>
#include <string>

namespace sln {

class TcpClient {
public:
    explicit TcpClient(asio::io_context& io);

    // Resolve + TCP connect. Returns false on refusal, unreachable host or
    // timeout (the latter is indistinguishable from "filtered").
    bool connect(const std::string& host, uint16_t port, int timeout_ms);

    // Read whatever the peer sends: returns early on EOF, on an idle gap of
    // idle_gap_ms with at least some bytes collected, or at total_wait_ms.
    std::string recv_all(int total_wait_ms, int idle_gap_ms = 350,
                         size_t max_bytes = 65536);

    bool send(std::string_view data);

    // Send a payload, then collect the answer. Used by HTTP probes and by
    // the Lua scripting API.
    std::string send_and_receive(std::string_view payload, int wait_ms,
                                 size_t max_bytes = 1 << 20);

    void close();

    bool is_open() const { return socket_.is_open(); }

    // Relinquish the connected socket; the TcpClient is left closed and
    // reusable. Used by TlsClient to reuse the resolver/connect logic.
    asio::ip::tcp::socket detach();

private:
    // Run the worker io_context until both racing handlers complete.
    void run_round();

    asio::io_context& io_;
    asio::ip::tcp::socket socket_;
};

// Outcome of a UDP recv: a datagram, a refusal (ICMP port unreachable
// delivered to the connected socket — means the port is closed), or an
// empty timeout (port behaves as open|filtered).
struct UdpRecv {
    std::string data;
    bool refused = false;
};

// Same blocking-style pattern as TcpClient, over UDP. connect() sets the
// default destination (so ICMP errors surface on recv); works with IPv4 and
// IPv6 endpoints alike.
class UdpClient {
public:
    explicit UdpClient(asio::io_context& io);

    // Resolve + "connect" the UDP socket. Returns false on resolution
    // failure or timeout.
    bool connect(const std::string& host, uint16_t port, int timeout_ms);

    bool send(std::string_view data);

    // Waits up to wait_ms for one datagram.
    UdpRecv recv(int wait_ms, size_t max_bytes = 65536);

    void close();

private:
    void run_round();

    asio::io_context& io_;
    asio::ip::udp::socket socket_;
};

} // namespace sln
