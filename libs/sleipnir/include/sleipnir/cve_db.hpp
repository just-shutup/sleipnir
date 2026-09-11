// Local CVE database: maps product + version to known vulnerabilities.
// The DB is plain JSON data (data/cve_map.json) and can be extended without
// recompiling the scanner.
#pragma once

#include "sleipnir/types.hpp"

#include <memory>
#include <string>
#include <vector>

namespace sln {

struct VulnEntry {
    std::string cve;
    std::string constraint;   // "<9.8p1", "==2.3.4", ">=1.0 <1.0.2"
    double cvss = 0.0;
    Severity severity = Severity::Info;
    std::string summary;
    // Active verification probes from the record's "check" block (nullopt =
    // version-matching only, findings stay "potential").
    std::shared_ptr<const VulnCheck> check;
};

struct ProductEntry {
    std::string product;                 // canonical, e.g. "OpenSSH"
    std::vector<std::string> aliases;    // banner spellings, lowercase
    std::vector<VulnEntry> vulns;
};

class CveDb {
public:
    // Throws std::runtime_error if the file is missing or malformed.
    static CveDb load(const std::string& path);

    // Match product/version against the DB; product lookup is
    // case-insensitive and alias-aware ("openssh_8.4p1" still hits OpenSSH).
    std::vector<Finding> match(const std::string& host, uint16_t port,
                               const std::string& product,
                               const std::string& version) const;

    size_t product_count() const { return products_.size(); }

    // Knowledge base version from the "_db_version" top-level key
    // ("" when the file does not carry one). Monotonic strings like
    // "YYYY.MM" so lexicographic comparison orders releases.
    const std::string& db_version() const { return db_version_; }

private:
    std::vector<ProductEntry> products_;
    std::string db_version_;
};

} // namespace sln
