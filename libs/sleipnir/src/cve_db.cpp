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

std::string strip(std::string s) {
    size_t b = s.find_first_not_of(" \t");
    if (b == std::string::npos) return "";
    size_t e = s.find_last_not_of(" \t");
    return s.substr(b, e - b + 1);
}

// Parses a "check" block: either {"probes": [{method, path, body,
// content_type, headers: ["Name: value"], markers: [...], not_markers:
// [...]}]}, or {"script": "file.lua", "safe": false} referencing a Lua
// check script (plugins/checks/). A malformed check degrades to nullopt
// (finding stays potential) instead of rejecting the whole database.
std::shared_ptr<const VulnCheck> parse_check(const json& j) {
    auto check = std::make_shared<VulnCheck>();
    check->script = j.value("script", "");
    check->safe = j.value("safe", true);

    if (j.contains("probes") && j["probes"].is_array()) {
        for (const auto& pj : j["probes"]) {
            VulnCheckProbe p;
            p.path = pj.value("path", "");
            if (p.path.empty()) return nullptr;
            if (pj.contains("markers") && pj["markers"].is_array())
                for (const auto& m : pj["markers"])
                    p.markers.push_back(m.get<std::string>());
            if (p.markers.empty()) return nullptr;
            p.method = pj.value("method", ""); // empty -> inferred by the executor
            p.body = pj.value("body", "");
            p.content_type = pj.value("content_type", "");
            if (pj.contains("headers") && pj["headers"].is_array())
                for (const auto& h : pj["headers"]) {
                    std::string hs = h.get<std::string>();
                    size_t colon = hs.find(':');
                    if (colon == std::string::npos) return nullptr;
                    p.headers.push_back({strip(hs.substr(0, colon)),
                                         strip(hs.substr(colon + 1))});
                }
            if (pj.contains("not_markers") && pj["not_markers"].is_array())
                for (const auto& m : pj["not_markers"])
                    p.not_markers.push_back(m.get<std::string>());
            check->probes.push_back(std::move(p));
        }
    }
    if (!check->script.empty()) return check; // script path: probes optional
    return check->probes.empty() ? nullptr : check;
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
    if (j.contains("check")) e.check = parse_check(j["check"]);
    return e;
}

}

// True when the raw banner names a Linux distribution that backports
// security fixes while keeping the upstream version string — the classic
// false-positive amplifier for version-based CVE matching.
std::string distro_backport_marker(const std::string& banner) {
    std::string low = lower(banner);
    if (low.find("debian") != std::string::npos) return "Debian Backport likely";
    if (low.find("ubuntu") != std::string::npos) return "Ubuntu Backport likely";
    if (low.find("raspbian") != std::string::npos) return "Raspbian Backport likely";
    if (low.find("centos") != std::string::npos ||
        low.find("rhel") != std::string::npos ||
        low.find("red hat") != std::string::npos)
        return "RHEL/CentOS Backport likely";
    return "";
}

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
    db.db_version_ = root.value("_db_version", "");
    for (const auto& [key, value] : root.items()) {
        // metadata keys (_db_version, ...) are not product entries
        if (!value.is_object()) continue;
        ProductEntry p;
        p.product = value.value("product", key);
        p.aliases.push_back(lower(key));
        if (value.contains("aliases"))
            for (const auto& a : value["aliases"]) p.aliases.push_back(lower(a.get<std::string>()));
        p.os = lower(value.value("os", ""));
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
                                  const std::string& version,
                                  const std::string& banner,
                                  const std::string& os_family) const {
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

        // OS gate: when the SYN-scan fingerprint says "windows" and the
        // product only exists on Linux (vsftpd, ...), the banner was a lie
        // or the guess is wrong — either way the CVE does not apply.
        if (!p.os.empty() && !os_family.empty() && p.os != os_family) continue;

        // Distro backport marker from the raw banner ("Apache/2.4.10
        // (Debian)"): distro packages keep the upstream version while
        // carrying the fix, so version matches stay potential suspicions.
        const std::string backport = distro_backport_marker(banner);

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
            if (!backport.empty()) {
                f.evidence += " [" + backport + "]";
                f.description +=
                    " The banner names a distribution (" + backport +
                    "): such packages usually carry the fix while keeping "
                    "the upstream version string — verify against the "
                    "package changelog before acting on this finding.";
            }
            f.cve = v.cve;
            f.source = "cve-db";
            f.check = v.check;
            // Version match only: a potential suspicion until the record's
            // active check (if any) proves it. Backported distros lower the
            // confidence since the upstream version usually ships the fix.
            f.verified = false;
            f.confidence = backport.empty() ? "potential" : "low";
            out.push_back(std::move(f));
        }
    }
    return out;
}

} // namespace sln
