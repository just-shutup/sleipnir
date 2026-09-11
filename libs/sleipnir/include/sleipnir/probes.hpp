// Service fingerprinting: a JSON probe table (payload + regex rules, similar
// in spirit to nmap's service probes) plus the runtime that applies the
// probes to an open TCP connection.
#pragma once

#include "sleipnir/netio.hpp"
#include "sleipnir/types.hpp"

#include <functional>
#include <optional>
#include <regex>
#include <string>
#include <vector>

namespace sln {

struct ProbeRule {
    std::string service;
    std::regex re;
    std::string product;      // literal product name (empty -> use group)
    int product_group = 0;    // 1-based capture group for product name
    int version_group = 0;    // 1-based capture group for version
};

struct Probe {
    std::string name;
    std::optional<std::string> payload; // nullopt -> NULL probe (just read)
    int wait_ms = 1500;                 // how long to wait for a response
    std::vector<ProbeRule> rules;
};

class ProbeDb {
public:
    // Throws std::runtime_error if missing/malformed.
    static ProbeDb load(const std::string& path);

    // Run probes against an already-connected client until one rule matches.
    // reconnect() is called when a previous probe (e.g. HTTP with
    // "Connection: close") consumed the connection. Returns nullopt when
    // nothing matched (service stays "unknown").
    std::optional<ServiceInfo> identify(
        TcpClient& client, const std::string& host_ip,
        const std::function<bool()>& reconnect, int timeout_ms) const;

    const std::vector<Probe>& probes() const { return probes_; }

    // Knowledge base version from the top-level "db_version" key
    // ("" when absent).
    const std::string& db_version() const { return db_version_; }

private:
    std::vector<Probe> probes_;
    std::string db_version_;
};

} // namespace sln
