// ScanEngine: pulls (host, port) jobs from a queue into a worker pool.
// Each worker owns a single-threaded io_context and runs the full pipeline:
// connect -> fingerprint (probes) -> built-in checks -> Lua plugin hooks
// -> CVE matching -> (optional) fuzzing.
#pragma once

#include "sleipnir/checks.hpp"
#include "sleipnir/cve_db.hpp"
#include "sleipnir/jobqueue.hpp"
#include "sleipnir/plugins.hpp"
#include "sleipnir/probes.hpp"
#include "sleipnir/results.hpp"
#include "sleipnir/types.hpp"

#include <memory>
#include <set>
#include <string>

namespace sln {

class TcpClient;

class ScanEngine {
public:
    struct Deps {
        ProbeDb probes;
        CveDb cves;
        PluginHost plugins;
    };

    // Throws std::runtime_error when data files cannot be loaded.
    ScanEngine(const ScanConfig& cfg);
    ~ScanEngine(); // out-of-line: PluginHost::Plugin is incomplete here

    // Blocks until the whole scan is finished (or stopped via Ctrl+C).
    // Returns per-host/port results; findings are accessible via collector().
    std::vector<PortResult> run(const std::vector<std::string>& hosts,
                                const std::vector<uint16_t>& ports);

    ResultCollector& collector() { return collector_; }

    // Request graceful stop (called from a signal handler).
    static void request_stop();

    // Clear the stop flags before a new scan (interactive sessions reuse
    // the process after a Ctrl+C-stopped scan).
    static void reset_stop();

private:
    struct Job {
        std::string host;
        uint16_t port;
    };

    void worker_loop();
    // Returns the failed-connect duration in ms, or 0 when the port is open
    // (the adaptive pacer distinguishes filtered timeouts from fast RSTs).
    int process_job(const Job& job, TcpClient& client, asio::io_context& io);

    ScanConfig cfg_;
    ProbeDb probes_;
    CveDb cves_;
    PluginHost plugins_;
    ResultCollector collector_;
    JobQueue<Job> queue_;
    std::set<uint16_t> tls_ports_;
    std::atomic<uint64_t> active_workers_{0};
    std::atomic<int> adaptive_delay_ms_{0}; // runtime backoff, ms
    int base_delay_ms_ = 0;                 // timing profile delay
    int adaptive_ceiling_ = 500;

    static inline std::atomic<bool> stop_requested_{false};
};

} // namespace sln
