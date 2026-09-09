// Version string parsing and ordering, used by the CVE matcher.
//
// Handles real-world banners like "8.4p1", "2.4.49 (Unix)", "1.21.0" by
// splitting on dots and comparing numeric components; an alphanumeric
// suffix (e.g. "p2") is treated as an extra sub-version, so 9.8 < 9.8p1.
#pragma once

#include <string>
#include <string_view>
#include <vector>

namespace sln {

struct Version {
    std::vector<int> parts;

    int compare(const Version& other) const;
    bool valid() const { return !parts.empty(); }
};

// Extracts the leading dotted version from a string ("OpenSSH_8.4p1" is
// handled by the caller; here "8.4p1" -> parts {8,4,1}).
Version parse_version(std::string_view s);

// Compare two raw version strings; returns <0 / 0 / >0.
// Unparseable input compares as "unknown" (always greater than any version).
int version_compare(std::string_view a, std::string_view b);

} // namespace sln
