#include "sleipnir/netio.hpp"

#include <chrono>

namespace sln {

TcpClient::TcpClient(asio::io_context& io) : io_(io), socket_(io) {}

void TcpClient::run_round() {
    io_.restart();
    io_.run();
}

bool TcpClient::connect(const std::string& host, uint16_t port, int timeout_ms) {
    close();

    asio::ip::tcp::endpoint endpoint;
    try {
        endpoint = {asio::ip::make_address(host), port};
    } catch (const std::exception&) {
        // not a raw IP -> resolve
        asio::ip::tcp::resolver resolver(io_);
        std::optional<asio::ip::tcp::resolver::results_type> resolved;
        asio::steady_timer resolve_timer(io_);
        resolve_timer.expires_after(std::chrono::milliseconds(timeout_ms));
        bool resolve_done = false;
        resolver.async_resolve(host, std::to_string(port),
                               [&](std::error_code ec, auto results) {
                                   if (resolve_done) return;
                                   resolve_done = true;
                                   if (!ec) resolved = std::move(results);
                                   resolve_timer.cancel();
                               });
        resolve_timer.async_wait([&](std::error_code) {
            if (resolve_done) return;
            resolve_done = true;
            resolver.cancel();
        });
        run_round();
        if (!resolved || resolved->empty()) return false;
        endpoint = resolved->begin()->endpoint();
    }

    asio::steady_timer timer(io_);
    timer.expires_after(std::chrono::milliseconds(timeout_ms));
    bool done = false;
    bool ok = false;

    socket_.async_connect(endpoint, [&](std::error_code ec) {
        if (done) return;
        done = true;
        ok = !ec;
        timer.cancel();
    });
    timer.async_wait([&](std::error_code) {
        if (done) return;
        done = true;
        std::error_code ignored;
        socket_.close(ignored);
    });
    run_round();
    return ok;
}

std::string TcpClient::recv_all(int total_wait_ms, int idle_gap_ms,
                                size_t max_bytes) {
    if (!socket_.is_open()) return {};

    std::string out;
    auto deadline = std::chrono::steady_clock::now() +
                    std::chrono::milliseconds(total_wait_ms);
    char buf[8192];

    for (;;) {
        if (out.size() >= max_bytes) break;
        auto now = std::chrono::steady_clock::now();
        if (now >= deadline) break;
        int wait = static_cast<int>(
            std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now)
                .count());
        wait = std::min(wait, idle_gap_ms);

        asio::steady_timer timer(io_);
        timer.expires_after(std::chrono::milliseconds(wait));
        bool done = false;
        size_t nread = 0;
        bool eof = false;
        bool err = false;

        socket_.async_read_some(
            asio::buffer(buf, sizeof(buf)),
            [&](std::error_code ec, size_t n) {
                if (done) return;
                done = true;
                if (ec == asio::error::eof) {
                    eof = true;
                    // Peer closed: mark the socket closed so the probe loop
                    // reconnects instead of writing into a dead connection.
                    std::error_code ignored;
                    socket_.close(ignored);
                } else if (ec)
                    err = true;
                else
                    nread = n;
                timer.cancel();
            });
        timer.async_wait([&](std::error_code) {
            if (done) return;
            done = true; // idle gap hit: enough banner collected
            // cancel the pending read, otherwise io_.run() never returns
            std::error_code ignored;
            socket_.cancel(ignored);
        });
        run_round();

        if (err || eof) break;
        if (nread == 0) break; // gap timer fired first
        out.append(buf, nread);
    }
    return out;
}

bool TcpClient::send(std::string_view data) {
    if (!socket_.is_open() || data.empty()) return false;
    asio::steady_timer timer(io_);
    timer.expires_after(std::chrono::milliseconds(2000));
    bool done = false;
    bool ok = false;
    asio::async_write(socket_, asio::buffer(data.data(), data.size()),
                      [&](std::error_code ec, size_t) {
                          if (done) return;
                          done = true;
                          ok = !ec;
                          timer.cancel();
                      });
    timer.async_wait([&](std::error_code) {
        if (done) return;
        done = true;
        std::error_code ignored;
        socket_.close(ignored);
    });
    run_round();
    return ok;
}

std::string TcpClient::send_and_receive(std::string_view payload, int wait_ms,
                                        size_t max_bytes) {
    if (!send(payload)) return {};
    return recv_all(wait_ms, wait_ms, max_bytes);
}

void TcpClient::close() {
    if (socket_.is_open()) {
        std::error_code ignored;
        socket_.close(ignored);
    }
}

asio::ip::tcp::socket TcpClient::detach() {
    asio::ip::tcp::socket s = std::move(socket_);
    socket_ = asio::ip::tcp::socket(io_);
    return s;
}

} // namespace sln
