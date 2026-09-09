#include "sleipnir/cve_db.hpp"
#include "sleipnir/version.hpp"

#include <nlohmann/json.hpp>

#include <cctype>
#include <fstream>
#include <stdexcept>

namespace sln {

namespace {

using json = nlohmann::json;

std::string lower(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

// Eval one "<=x.y.z"-style token against the scanned version.
bool eval_token(const std::string& version, const std::string& op,
                const std::string& rhs) {
    int cmp = version_compare(version, rhs);
    if (op == "<") return cmp < 0;
    if (op == "<=") return cmp <= 0;
    if (op == ">") return cmp > 0;
    if (op == ">=") return cmp >= 0;
    if (op == "==") return cmp == 0;
    if (op == "!=") return cmp != 0;
    return false;
}

// Constraints are conjunctions of tokens: "<1.0 <1.0.2" or single "==2.3.4".
bool eval_constraint(const std::string& version, const std::string& constraint) {
    size_t pos = 0;
    while (pos < constraint.size()) {
        size_t next = constraint.find_first_of(" \t", pos);
        std::string token = constraint.substr(
            pos, next == std::string::npos ? std::string::npos : next - pos);
        pos = (next == std::string::npos) ? constraint.size() : next + 1;
        if (token.empty()) continue;

        std::string op, rhs;
        size_t i = 0;
        while (i < token.size() &&
               (token[i] == '<' || token[i] == '>' || token[i] == '=' ||
                token[i] == '!')) {
            op += token[i];
            ++i;
        }
        rhs = token.substr(i);
        if (op.empty()) op = "==";
        if (rhs.empty()) return false;
        if (!eval_token(version, op, rhs)) return false;
    }
    return true;
}

Severity severity_from_cvss(double cvss) {
    if (cvss >= 9.0) return Severity::Critical;
    if (cvss >= 7.0) return Severity::High;
    if (cvss >= 4.0) return Severity::Medium;
    if (cvss > 0.0) return Severity::Low;
    return Severity::Info;
}

VulnEntry parse_vuln(const json& j) {
    VulnEntry e;
    e.cve = j.at("cve").get<std::string>();
    e.constraint = j.at("affected").get<std::string>();
    e.summary = j.value("summary", "");
    e.cvss = j.value("cvss", 0.0);
    e.severity = j.contains("severity")
                     ? severity_from_string(j["severity"].get<std::string>())
                     : severity_from_cvss(e.cvss);
    return e;
}

} // namespace

CveDb CveDb::load(const std::string& path) {
    std::ifstream in(path);
    if (!in)
        throw std::runtime_error("cannot open CVE database: " + path);
    json root;
    try {
        in >> root;
    } catch (const std::exception& e) {
        throw std::runtime_error("CVE database " + path + " is not valid JSON: " +
                                 e.what());
    }

    CveDb db;
    for (const auto& [key, value] : root.items()) {
        ProductEntry p;
        p.product = value.value("product", key);
        p.aliases.push_back(lower(key));
        if (value.contains("aliases"))
            for (const auto& a : value["aliases"]) p.aliases.push_back(lower(a.get<std::string>()));
        if (value.contains("vulns"))
            for (const auto& v : value["vulns"]) p.vulns.push_back(parse_vuln(v));
        if (!p.vulns.empty()) db.products_.push_back(std::move(p));
    }
    if (db.products_.empty())
        throw std::runtime_error("CVE database " + path + " has no entries");
    return db;
}

std::vector<Finding> CveDb::match(const std::string& host, uint16_t port,
                                  const std::string& product,
                                  const std::string& version) const {
    std::vector<Finding> out;
    if (product.empty()) return out;

    const std::string needle = lower(product);
    for (const auto& p : products_) {
        bool alias_hit = false;
        for (const auto& a : p.aliases)
            if (needle.find(a) != std::string::npos) {
                alias_hit = true;
                break;
            }
        if (!alias_hit) continue;

        for (const auto& v : p.vulns) {
            if (!eval_constraint(version, v.constraint)) continue;
            Finding f;
            f.host = host;
            f.port = port;
            f.title = p.product + " " +
                      (version.empty() ? "(unknown version)" : version) + ": " +
                      v.cve;
            f.severity = v.severity;
            f.description = v.summary.empty() ? v.cve : v.summary;
            f.evidence = "product=" + p.product + " version=" +
                         (version.empty() ? "unknown" : version) +
                         " matches " + v.constraint;
            f.cve = v.cve;
            f.source = "cve-db";
            out.push_back(std::move(f));
        }
    }
    return out;
}

} // namespace sln
