#include "sleipnir/results.hpp"

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

Severity severity_from_string(const std::string& s) {
    if (s == "low") return Severity::Low;
    if (s == "medium") return Severity::Medium;
    if (s == "high") return Severity::High;
    if (s == "critical") return Severity::Critical;
    return Severity::Info;
}

void ResultCollector::add_port(PortResult r) {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        ports_.push_back(std::move(r));
    }
    stats_.jobs_done.fetch_add(1);
    if (r.status == PortStatus::Open) stats_.open_ports.fetch_add(1);
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

} // namespace sln
