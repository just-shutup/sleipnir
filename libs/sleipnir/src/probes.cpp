#include "sleipnir/probes.hpp"

#include <nlohmann/json.hpp>

#include <fstream>
#include <stdexcept>

namespace sln {

namespace {

using json = nlohmann::json;

ServiceInfo apply_rule(const ProbeRule& rule, const std::string& response) {
    std::smatch m;
    if (!std::regex_search(response, m, rule.re)) return {};
    ServiceInfo info;
    info.service = rule.service;
    if (!rule.product.empty()) {
        info.product = rule.product;
    } else if (rule.product_group > 0 &&
               static_cast<size_t>(rule.product_group) < m.size()) {
        info.product = m[rule.product_group].str();
    }
    if (rule.version_group > 0 &&
        static_cast<size_t>(rule.version_group) < m.size()) {
        info.version = m[rule.version_group].str();
    }
    return info;
}

} // namespace

ProbeDb ProbeDb::load(const std::string& path) {
    std::ifstream in(path);
    if (!in) throw std::runtime_error("cannot open probe table: " + path);
    json root;
    try {
        in >> root;
    } catch (const std::exception& e) {
        throw std::runtime_error("probe table " + path + " is not valid JSON: " +
                                 e.what());
    }

    ProbeDb db;
    db.db_version_ = root.value("db_version", "");
    for (const auto& j : root.at("probes")) {
        Probe p;
        p.name = j.at("name").get<std::string>();
        if (j.contains("payload") && !j["payload"].is_null())
            p.payload = j["payload"].get<std::string>();
        p.wait_ms = j.value("wait_ms", 1500);
        for (const auto& r : j.at("matches")) {
            ProbeRule rule;
            rule.service = r.at("service").get<std::string>();
            rule.product = r.value("product", "");
            rule.product_group = r.value("product_group", 0);
            rule.version_group = r.value("version_group", 0);
            rule.re.assign(r.at("regex").get<std::string>(),
                           std::regex::optimize);
            p.rules.push_back(std::move(rule));
        }
        db.probes_.push_back(std::move(p));
    }
    if (db.probes_.empty())
        throw std::runtime_error("probe table " + path + " has no probes");
    return db;
}

std::optional<ServiceInfo> ProbeDb::identify(
    TcpClient& client, const std::string& host_ip,
    const std::function<bool()>& reconnect, int timeout_ms) const {
    for (const auto& probe : probes_) {
        if (!client.is_open() && reconnect && !reconnect()) break;

        std::string response;
        if (probe.payload) {
            // substitute {host} so HTTP Host headers are correct
            std::string payload = *probe.payload;
            size_t pos;
            while ((pos = payload.find("{host}")) != std::string::npos)
                payload.replace(pos, 6, host_ip);
            response = client.send_and_receive(payload, probe.wait_ms);
        } else {
            response = client.recv_all(std::min(probe.wait_ms, timeout_ms));
        }
        if (response.empty()) continue; // try the next probe on the same conn

        for (const auto& rule : probe.rules) {
            ServiceInfo info = apply_rule(rule, response);
            if (!info.service.empty()) {
                info.banner = response.substr(0, 1024);
                return info;
            }
        }
    }
    return std::nullopt;
}

} // namespace sln
