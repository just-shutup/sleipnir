#include "sleipnir/syn_scan.hpp"

#include <asio.hpp>

#ifdef __linux__
#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#include <algorithm>
#include <chrono>
#include <cstring>
#include <thread>

namespace sln {

namespace {

// Source ports used by our probes; the reply's destination port identifies
// the slot. The range deliberately avoids the usual kernel ephemeral range
// start (32768..) overlap zone below 40000.
constexpr uint16_t kSportBase = 40000;
constexpr uint32_t kSeqBase = 0x53313031u; // "S101" — deterministic marker

} // namespace

PortStatus syn_status_from_flags(uint8_t f) {
    if (f & kTcpSyn) return (f & kTcpAck) ? PortStatus::Open : PortStatus::Filtered;
    if (f & kTcpRst) return PortStatus::Closed;
    return PortStatus::Filtered;
}

uint16_t ones_complement_checksum(const uint8_t* data, size_t len) {
    uint32_t sum = 0;
    size_t i = 0;
    for (; i + 1 < len; i += 2)
        sum += (static_cast<uint32_t>(data[i]) << 8) | data[i + 1];
    if (i < len) sum += static_cast<uint32_t>(data[i]) << 8;
    while (sum >> 16) sum = (sum & 0xffffu) + (sum >> 16);
    return static_cast<uint16_t>(~sum);
}

#ifdef __linux__

namespace {

uint16_t ip_checksum(const uint8_t* hdr, size_t len) {
    return ones_complement_checksum(hdr, len);
}

// TCP checksum with the RFC 793 pseudo-header.
uint16_t tcp_checksum(uint32_t src, uint32_t dst, const uint8_t* tcp,
                      size_t len) {
    uint8_t buf[64]; // pseudo header (12) + TCP header (20) + padding
    size_t n = 0;
    auto push16 = [&buf, &n](uint32_t v) {
        buf[n++] = static_cast<uint8_t>(v >> 8);
        buf[n++] = static_cast<uint8_t>(v);
    };
    push16(src >> 16);
    push16(src & 0xffff);
    push16(dst >> 16);
    push16(dst & 0xffff);
    buf[n++] = 0;
    buf[n++] = 6; // IPPROTO_TCP
    push16(static_cast<uint32_t>(len));
    std::memcpy(buf + n, tcp, len);
    n += len;
    if (n % 2) buf[n++] = 0;
    return ones_complement_checksum(buf, n);
}

#pragma pack(push, 1)
struct TcpHeader {
    uint16_t sport, dport;
    uint32_t seq, ack;
    uint8_t offset_res;
    uint8_t flags;
    uint16_t window, checksum, urgent;
};
#pragma pack(pop)

static_assert(sizeof(TcpHeader) == 20);

} // namespace

std::optional<std::vector<SynOutcome>> syn_discover(
    const std::vector<std::string>& hosts, const std::vector<uint16_t>& ports,
    int timeout_ms, int send_delay_ms, ResultCollector& collector) {
    // Raw sockets need root or CAP_NET_RAW; anything else falls back.
    int recv_fd = ::socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (recv_fd < 0) return std::nullopt;
    int send_fd = ::socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (send_fd < 0) {
        ::close(recv_fd);
        return std::nullopt;
    }
    int one = 1;
    ::setsockopt(send_fd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
    int rcvbuf = 1 << 20;
    ::setsockopt(recv_fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

    // Resolve every host to an IPv4 address (nullopt -> caller falls back).
    std::vector<asio::ip::address_v4> dst_addrs;
    dst_addrs.reserve(hosts.size());
    for (const auto& host : hosts) {
        asio::ip::address addr;
        try {
            addr = asio::ip::make_address(host);
        } catch (const std::exception&) {
            asio::io_context io;
            asio::ip::tcp::resolver resolver(io);
            try {
                auto results = resolver.resolve(host, "");
                bool found = false;
                for (const auto& entry : results) {
                    if (entry.endpoint().address().is_v4()) {
                        addr = entry.endpoint().address();
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    ::close(recv_fd);
                    ::close(send_fd);
                    return std::nullopt; // IPv6-only target: connect fallback
                }
            } catch (const std::exception&) {
                ::close(recv_fd);
                ::close(send_fd);
                return std::nullopt;
            }
        }
        dst_addrs.push_back(addr.to_v4());
    }

    // Our source address per destination (UDP connect route lookup).
    std::vector<uint32_t> src_addrs(hosts.size(), 0);
    for (size_t h = 0; h < hosts.size(); ++h) {
        int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) break;
        sockaddr_in to{};
        to.sin_family = AF_INET;
        to.sin_port = 0;
        auto dstb = dst_addrs[h].to_bytes();
        std::memcpy(&to.sin_addr, dstb.data(), 4);
        if (::connect(fd, reinterpret_cast<sockaddr*>(&to), sizeof(to)) == 0) {
            sockaddr_in self{};
            socklen_t sl = sizeof(self);
            if (::getsockname(fd, reinterpret_cast<sockaddr*>(&self), &sl) == 0)
                src_addrs[h] = self.sin_addr.s_addr;
        }
        ::close(fd);
    }

    struct Job {
        size_t host;
        uint16_t port;
    };
    std::vector<Job> jobs;
    for (size_t h = 0; h < hosts.size(); ++h)
        for (uint16_t p : ports)
            if (src_addrs[h]) jobs.push_back({h, p});

    std::vector<SynOutcome> outcomes;
    outcomes.reserve(jobs.size());

    const size_t capacity = 65535 - kSportBase + 1;
    std::vector<uint8_t> pkt(20 + sizeof(TcpHeader));
    uint8_t* tcpbytes = pkt.data() + 20;

    for (size_t wave_start = 0; wave_start < jobs.size();
         wave_start += capacity) {
        const size_t wave_n = std::min(capacity, jobs.size() - wave_start);
        std::vector<char> seen(wave_n, 0);
        std::vector<PortStatus> st(wave_n, PortStatus::Filtered);
        std::vector<uint32_t> seqs(wave_n);

        for (size_t i = 0; i < wave_n; ++i) {
            const auto& job = jobs[wave_start + i];
            uint16_t sport = static_cast<uint16_t>(kSportBase + i);
            uint32_t seq = kSeqBase + static_cast<uint32_t>(i);
            seqs[i] = seq;

            auto dstb = dst_addrs[job.host].to_bytes();
            uint32_t srcn = src_addrs[job.host]; // network order already
            uint32_t dstn;
            std::memcpy(&dstn, dstb.data(), 4);

            // IPv4 header
            pkt[0] = 0x45; // v4, IHL 5
            pkt[1] = 0;    // TOS
            pkt[2] = (20 + 20) >> 8;
            pkt[3] = (20 + 20) & 0xff;
            pkt[4] = 0; pkt[5] = 0;      // id
            pkt[6] = 0x40; pkt[7] = 0;   // DF
            pkt[8] = 64;                  // TTL
            pkt[9] = 6;                   // proto TCP
            pkt[10] = pkt[11] = 0;        // checksum placeholder
            std::memcpy(&pkt[12], &srcn, 4);
            std::memcpy(&pkt[16], &dstn, 4);
            uint16_t ipck = ip_checksum(pkt.data(), 20);
            pkt[10] = ipck >> 8;
            pkt[11] = ipck & 0xff;

            // TCP header
            TcpHeader th{};
            th.sport = htons(sport);
            th.dport = htons(job.port);
            th.seq = htonl(seq);
            th.ack = 0;
            th.offset_res = 0x50;
            th.flags = kTcpSyn;
            th.window = htons(1024);
            th.checksum = 0;
            th.urgent = 0;
            std::memcpy(tcpbytes, &th, sizeof(th));
            uint16_t ck = tcp_checksum(srcn, dstn, tcpbytes, sizeof(th));
            tcpbytes[16] = ck >> 8;
            tcpbytes[17] = ck & 0xff;

            sockaddr_in sa{};
            sa.sin_family = AF_INET;
            sa.sin_port = htons(job.port);
            std::memcpy(&sa.sin_addr, &dstn, 4);
            ::sendto(send_fd, pkt.data(), pkt.size(), 0,
                     reinterpret_cast<sockaddr*>(&sa), sizeof(sa));
            if (send_delay_ms > 0)
                std::this_thread::sleep_for(
                    std::chrono::milliseconds(send_delay_ms));
        }

        // Collect replies until the deadline.
        auto deadline = std::chrono::steady_clock::now() +
                        std::chrono::milliseconds(timeout_ms);
        uint8_t buf[2048];
        for (;;) {
            int remain = static_cast<int>(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    deadline - std::chrono::steady_clock::now())
                    .count());
            if (remain <= 0) break;
            pollfd pfd{recv_fd, POLLIN, 0};
            int pr = ::poll(&pfd, 1, remain);
            if (pr <= 0) break;
            ssize_t n = ::recv(recv_fd, buf, sizeof(buf), 0);
            if (n < 24) continue;
            unsigned ihl = (buf[0] & 0x0f) * 4;
            if (buf[9] != 6 || n < ihl + 20) continue;
            const uint8_t* tcp = buf + ihl;
            uint16_t sport, dport;
            std::memcpy(&sport, tcp, 2);
            std::memcpy(&dport, tcp + 2, 2);
            sport = ntohs(sport);
            dport = ntohs(dport);
            if (dport < kSportBase) continue;
            size_t slot = dport - kSportBase;
            if (slot >= wave_n) continue;
            const auto& job = jobs[wave_start + slot];

            uint32_t srcn;
            std::memcpy(&srcn, buf + 12, 4);
            if (srcn != src_addrs[job.host]) continue;

            uint32_t ack;
            std::memcpy(&ack, tcp + 8, 4);
            ack = ntohl(ack);
            uint32_t expect = seqs[slot] + 1;
            uint8_t flags = tcp[13];
            if (flags & kTcpSyn) {
                if (ack != expect) continue; // not a reply to our SYN
            } else if (flags & kTcpRst) {
                if (ack != expect && ack != 0) continue;
            } else {
                continue;
            }
            seen[slot] = 1;
            st[slot] = syn_status_from_flags(flags);
        }

        for (size_t i = 0; i < wave_n; ++i) {
            const auto& job = jobs[wave_start + i];
            outcomes.push_back(
                {hosts[job.host], job.port,
                 seen[i] ? st[i] : PortStatus::Filtered});
            collector.debug("[syn] " + hosts[job.host] + ":" +
                            std::to_string(job.port) + " " +
                            status_name(outcomes.back().status));
        }
    }

    ::close(send_fd);
    ::close(recv_fd);
    return outcomes;
}

#else // !__linux__

std::optional<std::vector<SynOutcome>> syn_discover(
    const std::vector<std::string>&, const std::vector<uint16_t>&, int, int,
    ResultCollector&) {
    return std::nullopt; // raw-socket SYN scanning is Linux-only
}

#endif // __linux__

} // namespace sln
