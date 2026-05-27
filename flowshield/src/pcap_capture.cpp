/**
 * FlowShield - libpcap Integration Implementation (C++23)
 *
 * The functional body is gated on HAVE_PCAP. When the macro is undefined,
 * the file still compiles but all methods are no-ops returning empty/false
 * results — matching the C version's stub behaviour.
 */

#include "pcap_capture.hpp"

#ifdef HAVE_PCAP
#include <pcap.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/ethernet.h>
#endif

#include <chrono>
#include <cstring>
#include <format>
#include <utility>

namespace flowshield {

namespace {

constexpr std::uint32_t ether_header_len = 14;

}  // namespace

// ----- Packet parsing (independent of HAVE_PCAP) -----

void pcap_capture::on_packet(const std::uint8_t* packet, std::uint32_t len) {
    if (len < ether_header_len + 20) return;  // Min: Ethernet + IP header

    packets_received_.fetch_add(1, std::memory_order_relaxed);
    bytes_received_.fetch_add(len, std::memory_order_relaxed);

    const std::uint8_t* ip_data = packet + ether_header_len;
    const std::uint32_t ip_len  = len - ether_header_len;

    const std::uint8_t version = (ip_data[0] >> 4) & 0x0F;
    if (version != 4) return;

    const std::uint32_t ihl = (ip_data[0] & 0x0F) * 4u;
    if (ihl < 20 || ip_len < ihl) return;

    const std::uint8_t protocol = ip_data[9];
    std::uint32_t src_ip_n = 0;
    std::uint32_t dst_ip_n = 0;
    std::memcpy(&src_ip_n, ip_data + 12, 4);
    std::memcpy(&dst_ip_n, ip_data + 16, 4);

#ifdef HAVE_PCAP
    const std::uint32_t src_ip = ::ntohl(src_ip_n);
    const std::uint32_t dst_ip = ::ntohl(dst_ip_n);
#else
    // Portable byte swap when libpcap isn't available.
    auto bswap32 = [](std::uint32_t v) noexcept {
        return ((v & 0x000000FFu) << 24) |
               ((v & 0x0000FF00u) << 8)  |
               ((v & 0x00FF0000u) >> 8)  |
               ((v & 0xFF000000u) >> 24);
    };
    const std::uint32_t src_ip = bswap32(src_ip_n);
    const std::uint32_t dst_ip = bswap32(dst_ip_n);
#endif

    std::uint16_t src_port  = 0;
    std::uint16_t dst_port  = 0;
    std::uint8_t  tcp_flags_byte = 0;

    const std::uint8_t* transport     = ip_data + ihl;
    const std::uint32_t transport_len = ip_len - ihl;

    auto read_be16 = [](const std::uint8_t* p) noexcept -> std::uint16_t {
        return static_cast<std::uint16_t>((p[0] << 8) | p[1]);
    };

    constexpr std::uint8_t proto_tcp  = 6;
    constexpr std::uint8_t proto_udp  = 17;
    constexpr std::uint8_t proto_icmp = 1;

    if (protocol == proto_tcp && transport_len >= 20) {
        src_port       = read_be16(transport);
        dst_port       = read_be16(transport + 2);
        tcp_flags_byte = transport[13];
    } else if (protocol == proto_udp && transport_len >= 8) {
        src_port = read_be16(transport);
        dst_port = read_be16(transport + 2);
    } else if (protocol == proto_icmp) {
        // ICMP — no ports
    }

    engine_->process_packet(src_ip, dst_ip, src_port, dst_port,
                            protocol, len, tcp_flags_byte);

    packets_processed_.fetch_add(1, std::memory_order_relaxed);
}

#ifdef HAVE_PCAP

namespace {

void pcap_trampoline(u_char* user, const struct pcap_pkthdr* header, const u_char* packet) {
    auto* self = reinterpret_cast<pcap_capture*>(user);
    if (!self) return;
    self->on_packet(reinterpret_cast<const std::uint8_t*>(packet), header->caplen);
}

}  // namespace

// ----- Constructors (live + offline) -----

pcap_capture::pcap_capture(engine&          eng,
                           std::string_view interface,
                           std::string_view filter,
                           int              snaplen)
    : engine_(&eng)
{
    char errbuf[PCAP_ERRBUF_SIZE]{};
    std::string iface_s(interface);
    auto* h = ::pcap_open_live(iface_s.c_str(),
                               snaplen > 0 ? snaplen : 96,
                               1,
                               100,
                               errbuf);
    if (!h) {
        error_ = std::format("pcap_open_live failed: {}", errbuf);
        return;
    }
    handle_ = h;

    if (!filter.empty()) {
        auto* prog = new bpf_program{};
        std::string filt_s(filter);
        if (::pcap_compile(h, prog, filt_s.c_str(), 1, PCAP_NETMASK_UNKNOWN) == 0) {
            if (::pcap_setfilter(h, prog) == 0) {
                filter_          = prog;
                filter_compiled_ = true;
            } else {
                ::pcap_freecode(prog);
                delete prog;
            }
        } else {
            delete prog;
        }
    }
}

pcap_capture::pcap_capture(engine& eng, std::string_view pcap_file)
    : engine_(&eng)
{
    char errbuf[PCAP_ERRBUF_SIZE]{};
    std::string path(pcap_file);
    auto* h = ::pcap_open_offline(path.c_str(), errbuf);
    if (!h) {
        error_ = std::format("pcap_open_offline failed: {}", errbuf);
        return;
    }
    handle_ = h;
}

#else  // !HAVE_PCAP

pcap_capture::pcap_capture(engine&          eng,
                           std::string_view /*interface*/,
                           std::string_view /*filter*/,
                           int              /*snaplen*/)
    : engine_(&eng) {
    error_ = "libpcap not enabled at build time (rebuild with -DHAVE_PCAP -lpcap)";
}

pcap_capture::pcap_capture(engine& eng, std::string_view /*pcap_file*/)
    : engine_(&eng) {
    error_ = "libpcap not enabled at build time (rebuild with -DHAVE_PCAP -lpcap)";
}

#endif

pcap_capture::~pcap_capture() {
    stop();
#ifdef HAVE_PCAP
    if (filter_compiled_ && filter_) {
        auto* prog = reinterpret_cast<bpf_program*>(filter_);
        ::pcap_freecode(prog);
        delete prog;
    }
    if (handle_) {
        ::pcap_close(reinterpret_cast<pcap_t*>(handle_));
    }
#endif
}

bool pcap_capture::valid() const noexcept {
    return handle_ != nullptr;
}

// ----- Control -----

void pcap_capture::capture_loop_() {
#ifdef HAVE_PCAP
    running_.store(true, std::memory_order_release);
    start_time_ns_ = time_now_ns();
    ::pcap_loop(reinterpret_cast<pcap_t*>(handle_), 0, pcap_trampoline,
                reinterpret_cast<u_char*>(this));
    running_.store(false, std::memory_order_release);
#endif
}

bool pcap_capture::start() {
#ifdef HAVE_PCAP
    if (!handle_) return false;
    if (running_.load(std::memory_order_acquire)) return false;
    should_stop_.store(false, std::memory_order_release);
    thread_ = std::jthread([this] { capture_loop_(); });
    return true;
#else
    return false;
#endif
}

void pcap_capture::stop() {
    if (!running_.load(std::memory_order_acquire)) {
        // Even if not running, still join any thread that was started.
        if (thread_.joinable()) thread_.join();
        return;
    }
    should_stop_.store(true, std::memory_order_release);
#ifdef HAVE_PCAP
    if (handle_) {
        ::pcap_breakloop(reinterpret_cast<pcap_t*>(handle_));
    }
#endif
    if (thread_.joinable()) thread_.join();
}

std::size_t pcap_capture::process(std::size_t max_packets) {
#ifdef HAVE_PCAP
    if (!handle_) return 0;
    start_time_ns_ = time_now_ns();
    const int count = (max_packets > 0) ? static_cast<int>(max_packets) : -1;
    const int result = ::pcap_dispatch(reinterpret_cast<pcap_t*>(handle_),
                                       count, pcap_trampoline,
                                       reinterpret_cast<u_char*>(this));
    return (result >= 0) ? static_cast<std::size_t>(result) : 0;
#else
    (void)max_packets;
    return 0;
#endif
}

// ----- Statistics -----

capture_stats pcap_capture::get_stats() const {
    capture_stats s{};
    s.packets_received  = packets_received_.load(std::memory_order_relaxed);
    s.packets_processed = packets_processed_.load(std::memory_order_relaxed);
    s.bytes_received    = bytes_received_.load(std::memory_order_relaxed);

#ifdef HAVE_PCAP
    if (handle_) {
        struct pcap_stat ps{};
        if (::pcap_stats(reinterpret_cast<pcap_t*>(const_cast<void*>(handle_)), &ps) == 0) {
            s.packets_dropped = ps.ps_drop;
        }
    }
#endif

    const auto elapsed_ns = time_now_ns() - start_time_ns_;
    if (elapsed_ns > 0) {
        const double elapsed_sec = static_cast<double>(elapsed_ns) / 1e9;
        s.capture_rate_pps    = static_cast<double>(s.packets_received)  / elapsed_sec;
        s.processing_rate_pps = static_cast<double>(s.packets_processed) / elapsed_sec;
    }
    return s;
}

std::string pcap_capture::get_error() const {
    if (!error_.empty()) return error_;
#ifdef HAVE_PCAP
    if (handle_) return ::pcap_geterr(reinterpret_cast<pcap_t*>(const_cast<void*>(handle_)));
#endif
    return {};
}

// ----- Utility -----

std::vector<std::string> pcap_capture::list_interfaces(std::size_t max_names) {
    std::vector<std::string> out;
#ifdef HAVE_PCAP
    pcap_if_t* alldevs = nullptr;
    char errbuf[PCAP_ERRBUF_SIZE]{};
    if (::pcap_findalldevs(&alldevs, errbuf) == -1) return out;
    for (auto* d = alldevs; d && out.size() < max_names; d = d->next) {
        if (d->name) out.emplace_back(d->name);
    }
    ::pcap_freealldevs(alldevs);
#else
    (void)max_names;
#endif
    return out;
}

}  // namespace flowshield
