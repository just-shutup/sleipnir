#include "sleipnir/version.hpp"

#include <cctype>

namespace sln {

Version parse_version(std::string_view s) {
    Version v;
    size_t i = 0;
    while (i < s.size()) {
        // numeric component
        int num = 0;
        bool digits = false;
        while (i < s.size() && std::isdigit(static_cast<unsigned char>(s[i]))) {
            num = num * 10 + (s[i] - '0');
            ++i;
            digits = true;
        }
        if (digits) v.parts.push_back(num);
        // skip one separator ('.') or consume alphanumeric suffix ("p2", "a")
        if (i < s.size() && s[i] == '.') {
            ++i;
            continue;
        }
        // suffix like "p2": letters followed by optional digits
        bool letters = false;
        while (i < s.size() &&
               std::isalpha(static_cast<unsigned char>(s[i]))) {
            ++i;
            letters = true;
        }
        if (letters) continue; // next loop will read the digits if present
        if (i < s.size() && !std::isdigit(static_cast<unsigned char>(s[i])) &&
            s[i] != '.')
            break; // anything non-version-like ends parsing
        if (i < s.size() && s[i] != '.' && s[i] != '\0') ++i;
    }
    return v;
}

static int cmp_parts(const std::vector<int>& a, const std::vector<int>& b) {
    size_t n = std::max(a.size(), b.size());
    for (size_t i = 0; i < n; ++i) {
        int x = i < a.size() ? a[i] : 0;
        int y = i < b.size() ? b[i] : 0;
        if (x != y) return x < y ? -1 : 1;
    }
    return 0;
}

int Version::compare(const Version& other) const {
    return cmp_parts(parts, other.parts);
}

int version_compare(std::string_view a, std::string_view b) {
    Version va = parse_version(a);
    Version vb = parse_version(b);
    if (!va.valid() && !vb.valid()) return 0;
    if (!va.valid()) return 1;  // unknown > known: never flag CVEs
    if (!vb.valid()) return -1;
    return va.compare(vb);
}

} // namespace sln
