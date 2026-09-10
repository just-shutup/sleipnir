#include "sleipnir/results.hpp"

#include <algorithm>
#include <iostream>

namespace sln {

const char* severity_name(Severity s) {
    switch (s) {
    case Severity::Info: return "info";
    case Severity::Low: return "low";
    case Severity::Medium: return "medium";
    case Severity::High: return "high";
    case Severity::Critical: return "critical";
    }
    return "info";
}

int severity_rank(Severity s) { return static_cast<int>(s); }

const char* status_name(PortStatus s) {
    switch (s) {
    case PortStatus::Open: return "open";
    case PortStatus::Closed: return "closed";
    case PortStatus::Filtered: return "filtered";
    }
    return "open";
}

Severity severity_from_string(const std::string& s) {
    if (s == "low") return Severity::Low;
    if (s == "medium") return Severity::Medium;
    if (s == "high") return Severity::High;
    if (s == "critical") return Severity::Critical;
    return Severity::Info;
}

void ResultCollector::add_port(PortResult r) {
    PortStatus s = r.status;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        ports_.push_back(std::move(r));
    }
    count_port(s);
}

void ResultCollector::count_port(PortStatus s) {
    stats_.jobs_done.fetch_add(1);
    switch (s) {
    case PortStatus::Open: stats_.open_ports.fetch_add(1); break;
    case PortStatus::Closed: stats_.closed_ports.fetch_add(1); break;
    case PortStatus::Filtered: stats_.filtered_ports.fetch_add(1); break;
    }
}

void ResultCollector::add_finding(Finding f) {
    std::lock_guard<std::mutex> lock(mutex_);
    findings_.push_back(std::move(f));
    stats_.findings.fetch_add(1);
}

std::vector<PortResult> ResultCollector::ports() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return ports_;
}

std::vector<Finding> ResultCollector::findings() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return findings_;
}

void ResultCollector::log(const std::string& line) {
    std::lock_guard<std::mutex> lock(log_mutex_);
    std::cout << line << std::endl;
}

void ResultCollector::debug(const std::string& line) {
    if (!verbose_) return;
    log("[debug] " + line);
}

TimingProfile timing_profile(int t) {
    if (t < 0 || t > 5) t = 3;
    switch (t) {
    case 0: return {400, 10000, 8, 2000};   // paranoid: IDS evasion pacing
    case 1: return {200, 7500, 16, 1500};   // sneaky
    case 2: return {100, 5000, 32, 1000};   // polite
    case 3: return {0, 2500, 64, 500};      // normal (defaults)
    case 4: return {0, 1500, 128, 300};     // aggressive
    default: return {0, 750, 256, 100};     // insane: fast networks only
    }
}

} // namespace sln
