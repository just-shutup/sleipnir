// Thread-safe collector for scan results and findings, plus stats.
#pragma once

#include "sleipnir/types.hpp"

#include <atomic>
#include <mutex>
#include <string>
#include <vector>

namespace sln {

struct ScanStats {
    size_t hosts = 0;
    size_t jobs_total = 0;
    std::atomic<uint64_t> jobs_done{0};
    std::atomic<uint64_t> open_ports{0};
    std::atomic<uint64_t> findings{0};

    uint64_t jobs_done_snapshot() const { return jobs_done.load(); }
};

class ResultCollector {
public:
    void add_port(PortResult r);
    void add_finding(Finding f);

    // Copy snapshots (safe to read after workers joined; also callable live).
    std::vector<PortResult> ports() const;
    std::vector<Finding> findings() const;

    ScanStats& stats() { return stats_; }
    const ScanStats& stats() const { return stats_; }

    // Progress output is shared by all workers; serializes console lines.
    void log(const std::string& line);
    // Verbose-only logging.
    void debug(const std::string& line);
    void set_verbose(bool v) { verbose_ = v; }

private:
    mutable std::mutex mutex_;
    std::vector<PortResult> ports_;
    std::vector<Finding> findings_;
    std::mutex log_mutex_;
    bool verbose_ = false;
    ScanStats stats_;
};

} // namespace sln
