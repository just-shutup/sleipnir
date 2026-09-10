#include "sleipnir/udp_scan.hpp"
#include "sleipnir/netio.hpp"

#include <asio.hpp>

#include <atomic>
#include <mutex>
#include <thread>

namespace sln {

namespace {

// Built-in probe table: payload hex per well-known UDP service. Payloads
// are protocol-legal minimal requests (a DNS query for CHAOS version.bind,
// an NTP client packet, an SNMP GET for sysDescr.0, ...).
const UdpProbe kProbes[] = {
    // DNS: A TXT query for version.bind in the CHAOS class
    {53, "domain",
     "0000010000010000000000000776657273696f6e0462696e640000100003"},
    // TFTP: RRQ "README" netascii
    {69, "tftp", "0001524541444d45006f6374657400"},
    // NTP: client (mode 3) packet, v3 — 48 bytes: 0x1b + 47 zeros
    {123, "ntp",
     "1b00000000000000000000000000000000000000000000000000000000000000"
     "00000000000000000000000000000000"},
    // NetBIOS Name Service: node status request for '*'
    {137, "netbios-ns",
     "00000010000100000000000020434b4141414141414141414141414141414141"
     "414141414141414141414141410000210001"},
    // SNMPv1 GET sysDescr.0, community "public"
    {161, "snmp",
     "302602010004067075626c6963a01902010002010002010030"
     "0e300c06082b060102010101000500"},
    // SNMPv1 GET sysDescr.0, community "public" (same shape on 162)
    {162, "snmp",
     "302602010004067075626c6963a01902010002010002010030"
     "0e300c06082b060102010101000500"},
    // ISAKMP: IKE SA init header (aggressive daemons answer with a notify)
    {500, "isakmp",
     "736c6569706e6972000000000000000001100200000000000000001c"},
    // syslog: a harmless priority-prefixed line (answer would be exotic)
    {514, "syslog", "3c31333e736c6569706e6972207564702070726f62650a"},
    // L2TP: SCCRQ would be protocol-legal; keep a short message header
    {1701, "l2tp", "c802000100000000"},
    // IPsec NAT-T: non-ESP marker + IKE header
    {4500, "isakmp",
     "00000000736c6569706e6972000000000000000001100200000000000000001c"},
    // SSDP: M-SEARCH for all devices
    {1900, "ssdp",
     "4d2d534541524348202a20485454502f312e310d0a484f53543a203233392e3235"
     "352e3235352e3235303a313930300d0a4d414e3a2022737364703a646973636f76"
     "6572220d0a4d583a20310d0a53543a20737364703a616c6c0d0a0d0a"},
    // mDNS: PTR query for _services._dns-sd._udp.local
    {5353, "mdns",
     "000000000001000000000000095f7365727669636573075f646e732d7364045f75"
     "6470046c6f63616c00000c0001"},
    // memcached: UDP-framed "version\r\n" (8-byte request header)
    {11211, "memcached",
     "000000000001000076657273696f6e0d0a"},
};

std::vector<uint8_t> hex_to_bytes(const std::string& hex) {
    std::vector<uint8_t> out;
    out.reserve(hex.size() / 2);
    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    int hi = -1;
    for (char c : hex) {
        if (c == ' ') continue;
        int v = nibble(c);
        if (v < 0) break;
        if (hi < 0) {
            hi = v;
        } else {
            out.push_back(static_cast<uint8_t>((hi << 4) | v));
            hi = -1;
        }
    }
    return out;
}

std::string printable(const std::string& s) {
    std::string out;
    for (unsigned char c : s)
        out += (c >= 0x20 && c < 0x7f) ? static_cast<char>(c) : '.';
    if (out.size() > 120) out.resize(120);
    return out;
}

} // namespace

const UdpProbe* udp_probe_for(uint16_t port) {
    for (const auto& p : kProbes)
        if (p.port == port) return &p;
    return nullptr;
}

std::string udp_classify(uint16_t port, const std::string& r) {
    if (r.empty()) return {};
    auto byte_at = [&r](size_t i) -> unsigned {
        return static_cast<unsigned char>(r[i]);
    };
    switch (port) {
    case 53:
    case 5353: {
        // DNS header: answer flag set in the flags word (offset 2)
        if (r.size() >= 4 && (byte_at(2) & 0x80))
            return port == 5353 ? "mdns" : "domain";
        break;
    }
    case 123:
        // NTP reply: LI/VN/Mode byte with a non-zero mode
        if (r.size() >= 48 && (byte_at(0) & 0x07) == 4) return "ntp";
        break;
    case 161:
    case 162:
        // SNMP: BER SEQUENCE tag
        if (byte_at(0) == 0x30) return "snmp";
        break;
    case 69:
        // TFTP: opcode 1..5 in the first datagram bytes
        if (r.size() >= 2) {
            unsigned op = (byte_at(0) << 8) | byte_at(1);
            if (op >= 1 && op <= 5) return "tftp";
        }
        break;
    case 137:
        return "netbios-ns";
    case 1900:
        if (r.rfind("HTTP/1.", 0) == 0) return "ssdp";
        break;
    case 11211:
        if (r.find("VERSION") != std::string::npos ||
            r.find("STAT ") != std::string::npos)
            return "memcached";
        break;
    case 500:
    case 4500:
        return "isakmp";
    case 514:
        return "syslog";
    case 1701:
        return "l2tp";
    default:
        break;
    }
    return {};
}

std::vector<PortResult> udp_discover(const std::vector<std::string>& hosts,
                                     const std::vector<uint16_t>& ports,
                                     int timeout_ms, int threads,
                                     ResultCollector& collector) {
    struct Job {
        size_t host;
        uint16_t port;
    };
    std::vector<Job> jobs;
    for (size_t h = 0; h < hosts.size(); ++h)
        for (uint16_t p : ports) jobs.push_back({h, p});

    std::vector<PortResult> rows(jobs.size());
    std::atomic<size_t> next{0};
    int nworkers = std::max(1, std::min<int>(threads, 256));

    auto worker = [&] {
        asio::io_context io;
        UdpClient client(io);
        for (;;) {
            size_t i = next.fetch_add(1);
            if (i >= jobs.size()) break;
            const auto& job = jobs[i];
            const std::string& host = hosts[job.host];
            const UdpProbe* probe = udp_probe_for(job.port);

            PortResult row;
            row.host = host;
            row.port = job.port;

            if (!client.connect(host, job.port, timeout_ms)) {
                // unresolvable / unreachable host: report filtered, not closed
                row.status = PortStatus::Filtered;
                row.service = "unknown";
            } else {
                if (probe) {
                    std::string payload;
                    for (uint8_t b : hex_to_bytes(probe->payload_hex))
                        payload.push_back(static_cast<char>(b));
                    client.send(payload);
                }
                UdpRecv r = client.recv(timeout_ms);
                if (!r.data.empty()) {
                    row.status = PortStatus::Open;
                    std::string svc = udp_classify(job.port, r.data);
                    row.service = !svc.empty()
                                      ? svc
                                      : (probe ? probe->service : "udp");
                    row.banner = printable(r.data);
                    if (job.port == 161 && row.service == "snmp") {
                        Finding f;
                        f.host = host;
                        f.port = job.port;
                        f.title = "SNMP responds to the default 'public' community";
                        f.severity = Severity::Medium;
                        f.description =
                            "The device answered an SNMPv1 GET for sysDescr.0 "
                            "with the community string 'public'. Anyone on the "
                            "network can enumerate system details, interfaces "
                            "and routing tables; often a stepping stone to "
                            "configuration writes via SNMP SET.";
                        f.evidence = printable(r.data);
                        f.source = "builtin";
                        collector.add_finding(std::move(f));
                    } else if (job.port == 53 && row.service == "domain" &&
                               r.data.size() > 20) {
                        Finding f;
                        f.host = host;
                        f.port = job.port;
                        f.title = "DNS server discloses its version via CHAOS version.bind";
                        f.severity = Severity::Info;
                        f.description =
                            "A TXT query for version.bind in the CHAOS class "
                            "was answered. Exposing the resolver version lets "
                            "attackers pick matching exploits; disable the "
                            "version.bind record.";
                        f.evidence = printable(r.data);
                        f.source = "builtin";
                        collector.add_finding(std::move(f));
                    }
                } else if (r.refused) {
                    row.status = PortStatus::Closed;
                    row.service = "unknown";
                } else {
                    row.status = PortStatus::Filtered; // open|filtered
                    row.service = "unknown";
                }
            }
            rows[i] = std::move(row);
            collector.debug("[udp] " + host + ":" + std::to_string(job.port) +
                            " " + status_name(rows[i].status));
        }
    };

    std::vector<std::thread> pool;
    for (int i = 0; i < nworkers; ++i) pool.emplace_back(worker);
    for (auto& t : pool) t.join();

    size_t open = 0, closed = 0, filtered = 0;
    for (const auto& r : rows) {
        if (r.status == PortStatus::Open) ++open;
        else if (r.status == PortStatus::Closed) ++closed;
        else ++filtered;
    }
    collector.log("  [udp] probed " + std::to_string(jobs.size()) +
                  " endpoint(s): " + std::to_string(open) + " answer(s), " +
                  std::to_string(closed) + " refused, " +
                  std::to_string(filtered) + " silent (open|filtered)");
    return rows;
}

} // namespace sln
