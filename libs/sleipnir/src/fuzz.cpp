#include "sleipnir/fuzz.hpp"
#include "sleipnir/netio.hpp"

#include <atomic>
#include <chrono>
#include <random>
#include <thread>

namespace sln {

namespace {
std::atomic<bool> g_fuzz_stop{false};
} // namespace

void fuzz_request_stop() { g_fuzz_stop = true; }

void fuzz_reset_stop() { g_fuzz_stop = false; }

std::vector<std::string> build_fuzz_payloads(int max_len) {
    std::vector<std::string> out;

    for (int len : {128, 256, 512, 1024, 4096})
        if (len <= max_len) out.emplace_back(len, 'A');
    if (max_len >= 65536) out.emplace_back(65536, 'A');
    if (max_len >= 1048576) out.emplace_back(1048576, 'A');

    // format string abuse: %s/%n pairs
    if (max_len >= 4096) {
        std::string fmt;
        for (int i = 0; i < 256 && fmt.size() < 4096u; ++i) fmt += "%s%s%n";
        out.push_back(fmt);
    }

    // protocol delimiter flood (line-oriented services)
    if (max_len >= 2048) out.emplace_back(2048, '\n');

    // path traversal abuse for anything that parses paths
    if (max_len >= 4096) {
        std::string traversal;
        for (int i = 0; i < 128; ++i) traversal += "../../../";
        out.push_back(traversal);
    }

    // NUL padding + trailing 'A's
    if (max_len >= 1024) {
        std::string nuls(512, '\0');
        nuls += std::string(512, 'A');
        out.push_back(nuls);
    }

    // random binary blobs (deterministic seed for reproducibility)
    std::mt19937 rng(20260909u);
    for (int len : {256, 1024, 4096}) {
        if (len > max_len) continue;
        std::string blob(len, '\0');
        for (char& c : blob)
            c = static_cast<char>(rng() & 0xFF);
        out.push_back(std::move(blob));
    }
    return out;
}

namespace {

// True when the service accepts a fresh TCP connection again.
bool still_alive(asio::io_context& io, const std::string& host, uint16_t port,
                 int timeout_ms) {
    TcpClient probe(io);
    return probe.connect(host, port, timeout_ms);
}

Finding make_finding(const std::string& host, uint16_t port,
                     const std::string& title, Severity sev,
                     const std::string& description,
                     const std::string& evidence) {
    Finding f;
    f.host = host;
    f.port = port;
    f.title = title;
    f.severity = sev;
    f.description = description;
    f.evidence = evidence;
    f.source = "fuzz";
    return f;
}

std::string preview(const std::string& payload) {
    std::string p = payload.substr(0, 32);
    for (char& c : p)
        if (static_cast<unsigned char>(c) < 0x20 || c == '%')
            c = '.';
    return p + (payload.size() > 32 ? "..." : "");
}

} // namespace

void run_fuzz(asio::io_context& io, const std::string& host, uint16_t port,
              const ScanConfig& cfg, ResultCollector& out) {
    auto payloads = build_fuzz_payloads(cfg.fuzz_max_len);
    out.log("[fuzz] " + host + ":" + std::to_string(port) + ": " +
            std::to_string(payloads.size()) + " payloads");

    for (size_t i = 0; i < payloads.size(); ++i) {
        if (g_fuzz_stop) break;
        const std::string& payload = payloads[i];

        TcpClient client(io);
        if (!client.connect(host, port, cfg.timeout_ms)) {
            // the service was alive moments ago; now it refuses connections
            out.add_finding(make_finding(
                host, port, "Service stopped accepting connections",
                Severity::Critical,
                "After " + std::to_string(i + 1) +
                    " fuzz payload(s) the port no longer accepts TCP "
                    "connections. The service process likely crashed.",
                "payload #" + std::to_string(i + 1) + " (" +
                    std::to_string(payload.size()) + " bytes)"));
            return;
        }

        client.send(payload);
        client.recv_all(400, 200, 4096); // short observation window

        if (cfg.fuzz_delay_ms > 0)
            std::this_thread::sleep_for(
                std::chrono::milliseconds(cfg.fuzz_delay_ms));
        if (!still_alive(io, host, port, cfg.timeout_ms)) {
            out.add_finding(make_finding(
                host, port, "Service unavailable after fuzz payload",
                Severity::Critical,
                "The service stopped responding after a fuzz payload. "
                "Possible crash, hang or resource exhaustion (buffer "
                "overflow / DoS).",
                "payload #" + std::to_string(i + 1) + " (" +
                    std::to_string(payload.size()) + " bytes): " +
                    preview(payload)));
            return;
        }
    }
}

} // namespace sln
