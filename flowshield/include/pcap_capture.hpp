/**
 * FlowShield - libpcap Integration (C++23)
 *
 * Real network traffic capture and analysis.
 * Requires libpcap-dev: apt-get install libpcap-dev
 *
 * Build with -DHAVE_PCAP and link against -lpcap to enable actual capture.
 * Without HAVE_PCAP, all operations are no-ops (compiles fine, runtime
 * methods return falsy values).
 */

#pragma once

#include "flowshield.hpp"

#include <atomic>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace flowshield {

struct capture_stats {
    std::uint64_t packets_received{};
    std::uint64_t packets_processed{};
    std::uint64_t packets_dropped{};
    std::uint64_t bytes_received{};
    double        capture_rate_pps{};
    double        processing_rate_pps{};
};

class pcap_capture {
public:
    // Live capture on a network interface.
    //   snaplen <= 0 → default 96 bytes (enough for IP + TCP/UDP headers).
    pcap_capture(engine&          eng,
                 std::string_view interface,
                 std::string_view filter,
                 int              snaplen);

    // Offline replay from a pcap/pcapng file.
    pcap_capture(engine& eng, std::string_view pcap_file);

    pcap_capture(const pcap_capture&)            = delete;
    pcap_capture& operator=(const pcap_capture&) = delete;
    pcap_capture(pcap_capture&&)                 = delete;
    pcap_capture& operator=(pcap_capture&&)      = delete;
    ~pcap_capture();

    // ----- Control -----

    // Start capture loop on a background jthread.
    bool start();
    // Stop, join the thread.
    void stop();

    [[nodiscard]] bool is_running() const noexcept { return running_.load(std::memory_order_acquire); }

    // Drive capture loop synchronously on the calling thread.
    // max_packets == 0 → unlimited.
    std::size_t process(std::size_t max_packets);

    // True if pcap was actually opened successfully.
    [[nodiscard]] bool valid() const noexcept;

    // ----- Statistics -----

    [[nodiscard]] capture_stats get_stats() const;
    [[nodiscard]] std::string   get_error() const;

    // ----- Utility -----

    [[nodiscard]] static std::vector<std::string> list_interfaces(std::size_t max_names);

    // Internal: invoked by the pcap callback. Exposed here for the C-style
    // libpcap callback shim defined in the .cpp.
    void on_packet(const std::uint8_t* packet, std::uint32_t len);

private:
    void capture_loop_();   // body of the background thread

    engine* engine_;

    // Opaque pcap_t* handle (defined in .cpp guarded by HAVE_PCAP). We hold
    // it via void* in the header so callers don't need <pcap.h>.
    void* handle_{nullptr};
    // bpf_program is stored heap-allocated when filter is set; pointer is
    // void* in the header for the same reason.
    void* filter_{nullptr};
    bool  filter_compiled_{false};

    std::jthread thread_;
    std::atomic<bool> running_{false};
    std::atomic<bool> should_stop_{false};

    std::atomic<std::uint64_t> packets_received_{0};
    std::atomic<std::uint64_t> packets_processed_{0};
    std::atomic<std::uint64_t> bytes_received_{0};
    std::uint64_t              start_time_ns_{0};

    std::string error_;
};

}  // namespace flowshield
