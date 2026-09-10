#include "sleipnir/targets.hpp"

#include <asio.hpp>

#include <charconv>
#include <regex>
#include <set>
#include <stdexcept>

namespace sln {

namespace {

uint32_t ip_to_u32(const std::string& ip) {
    asio::ip::address_v4 addr = asio::ip::make_address_v4(ip);
    return addr.to_uint();
}

std::string u32_to_ip(uint32_t v) {
    return asio::ip::address_v4(v).to_string();
}

std::string resolve_host(const std::string& host) {
    asio::io_context io;
    asio::ip::tcp::resolver resolver(io);
    asio::ip::tcp::resolver::results_type results;
    std::string err;
    try {
        results = resolver.resolve(host, "");
        if (results.begin() != results.end()) {
            // prefer IPv4 when the name has both A and AAAA records;
            // IPv6-only hosts resolve to their v6 address and scan over v6
            for (const auto& entry : results) {
                if (entry.endpoint().address().is_v4())
                    return entry.endpoint().address().to_string();
            }
            return results.begin()->endpoint().address().to_string();
        }
    } catch (const std::exception& e) {
        err = e.what();
    }
    throw std::runtime_error("cannot resolve host '" + host + "'" +
                             (err.empty() ? "" : ": " + err));
}

// Expands an IPv6 CIDR "2001:db8::/64" (prefix 0..128). Prefixes below /64
// are rejected outright: even a /63 is 2^65 hosts, far beyond any sane scan.
void expand_v6_cidr(std::set<std::string>& out, const std::string& addr,
                    int prefix, const std::string& raw, size_t max_hosts) {
    if (prefix < 0 || prefix > 128)
        throw std::runtime_error("bad IPv6 prefix in '" + raw + "'");
    int host_bits = 128 - prefix;
    if (host_bits >= 64)
        throw std::runtime_error(
            "IPv6 prefix /" + std::to_string(prefix) + " in '" + raw +
            "' spans more than 2^64 hosts; use a /64 or larger prefix");
    uint64_t count = 1ull << host_bits;
    if (out.size() + count > max_hosts)
        throw std::runtime_error("target expansion exceeds " +
                                 std::to_string(max_hosts) + " hosts");

    auto base = asio::ip::make_address_v6(addr).to_bytes();
    for (int bit = 0; bit < host_bits; ++bit)
        base[15 - bit / 8] &= static_cast<unsigned char>(~(1 << (bit % 8)));

    for (uint64_t i = 0; i < count; ++i) {
        auto b = base;
        for (int bit = 0; bit < host_bits; ++bit)
            if ((i >> bit) & 1)
                b[15 - bit / 8] |= static_cast<unsigned char>(1 << (bit % 8));
        out.insert(asio::ip::address_v6(b).to_string());
    }
}

} // namespace

std::vector<std::string> expand_targets(const std::vector<std::string>& specs,
                                        size_t max_hosts) {
    std::set<std::string> out;
    static const std::regex cidr_re(
        R"(^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/(\d{1,2})$)");

    for (const auto& raw : specs) {
        std::string spec = raw;
        // strip optional scheme and path
        size_t scheme = spec.find("://");
        if (scheme != std::string::npos) spec = spec.substr(scheme + 3);

        std::smatch m;
        if (std::regex_match(spec, m, cidr_re)) {
            for (int i = 1; i <= 4; ++i)
                if (std::stoi(m[i].str()) > 255)
                    throw std::runtime_error("bad IPv4 in '" + raw + "'");
            int prefix = std::stoi(m[5].str());
            if (prefix > 32)
                throw std::runtime_error("bad prefix in '" + raw + "'");
            uint32_t base = ip_to_u32(spec.substr(0, spec.find('/')));
            uint32_t host_bits = 32 - prefix;
            uint64_t count = (host_bits >= 32) ? 0ull : (1ull << host_bits);
            if (count == 0) count = 1ull << 32;
            uint32_t mask = (prefix == 0) ? 0u : (~0u << host_bits);
            uint32_t network = base & mask;
            if (out.size() + count > max_hosts)
                throw std::runtime_error("target expansion exceeds " +
                                         std::to_string(max_hosts) + " hosts");
            for (uint64_t i = 0; i < count; ++i)
                out.insert(u32_to_ip(network + static_cast<uint32_t>(i)));
            continue;
        }

        // Bare IPv6 CIDR ("2001:db8::/64", "::1/128"): a '/' followed by an
        // all-digits tail after an address that parses as IPv6. Anything
        // else after the slash (URL path) is dropped below.
        size_t slash = spec.find('/');
        if (slash != std::string::npos) {
            std::string head = spec.substr(0, slash);
            std::string tail = spec.substr(slash + 1);
            bool tail_digits = !tail.empty() &&
                tail.find_first_not_of("0123456789") == std::string::npos;
            bool head_is_v6 = false;
            try {
                asio::ip::make_address_v6(head);
                head_is_v6 = true;
            } catch (const std::exception&) {
            }
            if (head_is_v6 && tail_digits) {
                expand_v6_cidr(out, head, std::stoi(tail), raw, max_hosts);
                continue;
            }
            spec = head;
        }

        // [2001:db8::1] -> 2001:db8::1
        if (spec.size() >= 2 && spec.front() == '[' && spec.back() == ']')
            spec = spec.substr(1, spec.size() - 2);

        if (spec.empty())
            throw std::runtime_error("empty target in '" + raw + "'");

        bool literal = false;
        try {
            asio::ip::make_address(spec); // IPv4 or IPv6 literal
            literal = true;
        } catch (const std::exception&) {
        }

        if (literal) {
            out.insert(spec);
        } else {
            // Validate resolvability early (fail fast), but keep the hostname:
            // TLS SNI, HTTP Host headers and readable reports all need the
            // original name, not the resolved address.
            resolve_host(spec);
            out.insert(spec);
        }
    }
    return {out.begin(), out.end()};
}

std::vector<uint16_t> expand_ports(const std::string& spec) {
    static const std::vector<uint16_t> top100 = {
        7, 20, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113,
        119, 135, 139, 143, 144, 161, 179, 199, 389, 427, 443, 444, 465, 500,
        513, 514, 515, 543, 544, 548, 554, 587, 631, 646, 636, 873, 990, 993,
        995, 1080, 1099, 1158, 1194, 1234, 1433, 1434, 1521, 1723, 1883, 2049,
        2100, 2121, 2181, 2375, 2376, 3000, 3128, 3260, 3268, 3306, 3389, 3690,
        4444, 4505, 4506, 4848, 5000, 5060, 5222, 5353, 5432, 5555, 5601, 5666,
        5800, 5900, 5984, 6000, 6379, 6443, 6666, 6667, 7001, 7077, 8000, 8008,
        8009, 8080, 8081, 8443, 8500, 8732, 8888, 9000, 9090, 9200, 9300, 9999,
        10000, 11211, 15672, 27017, 27018, 28017, 50000, 50030, 50070, 61616};

    std::set<uint16_t> ports;
    size_t pos = 0;
    while (pos < spec.size()) {
        size_t comma = spec.find(',', pos);
        std::string tok = spec.substr(pos, comma - pos);
        if (comma == std::string::npos) tok = spec.substr(pos);
        pos = (comma == std::string::npos) ? spec.size() : comma + 1;
        if (tok.empty()) continue;

        if (tok == "top100") {
            ports.insert(top100.begin(), top100.end());
            continue;
        }
        size_t dash = tok.find('-');
        if (dash != std::string::npos) {
            int lo = std::stoi(tok.substr(0, dash));
            int hi = std::stoi(tok.substr(dash + 1));
            if (lo < 1 || hi > 65535 || lo > hi)
                throw std::runtime_error("bad port range '" + tok + "'");
            for (int p = lo; p <= hi; ++p) ports.insert(static_cast<uint16_t>(p));
        } else {
            int p = std::stoi(tok);
            if (p < 1 || p > 65535)
                throw std::runtime_error("port out of range '" + tok + "'");
            ports.insert(static_cast<uint16_t>(p));
        }
    }
    if (ports.empty())
        throw std::runtime_error("empty port spec '" + spec + "'");
    return {ports.begin(), ports.end()};
}

} // namespace sln
