// FlowShield AI - Machine Learning Inference (C++23 migration of ai_inference.c)

#include "ai_inference.hpp"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstring>
#include <format>
#include <iostream>
#include <mutex>

// Bring in the canonical entropy_analysis definition. Forward-declared in the
// header so this is the only translation unit that needs the full layout.
#include "anomaly_detector.hpp"

#ifdef HAVE_HAILO
extern "C" {
#include <hailo/hailort.h>
}
#endif

namespace flowshield {

namespace {

constexpr std::size_t MAX_BASELINE_SAMPLES = 1000;

// Wall-clock millis using steady_clock; matches gettimeofday()-based timing
// granularity used by the original C code.
[[nodiscard]] double get_time_ms() noexcept {
    using clock = std::chrono::steady_clock;
    const auto t = clock::now().time_since_epoch();
    return std::chrono::duration<double, std::milli>(t).count();
}

[[gnu::always_inline]] inline float relu(float x) noexcept {
    return x > 0 ? x : 0.0f;
}

[[gnu::always_inline]] inline float sigmoid(float x) noexcept {
    return 1.0f / (1.0f + std::exp(-x));
}

void softmax(float* x, std::size_t n) noexcept {
    float max_val = x[0];
    for (std::size_t i = 1; i < n; ++i) {
        if (x[i] > max_val) max_val = x[i];
    }
    float sum = 0.0f;
    for (std::size_t i = 0; i < n; ++i) {
        x[i] = std::exp(x[i] - max_val);
        sum += x[i];
    }
    for (std::size_t i = 0; i < n; ++i) {
        x[i] /= sum;
    }
}

[[nodiscard]] float mse(const float* a, const float* b, std::size_t n) noexcept {
    float sum = 0.0f;
    for (std::size_t i = 0; i < n; ++i) {
        const float diff = a[i] - b[i];
        sum += diff * diff;
    }
    return sum / static_cast<float>(n);
}

void matmul_bias_relu(const float* input, std::size_t in_dim,
                      const float* weights, const float* bias,
                      std::size_t out_dim, float* output) noexcept {
    for (std::size_t j = 0; j < out_dim; ++j) {
        float sum = bias[j];
        for (std::size_t i = 0; i < in_dim; ++i) {
            sum += input[i] * weights[i * out_dim + j];
        }
        output[j] = relu(sum);
    }
}

// Pre-trained bias constants from the original C file. The corresponding
// weight matrices are deterministically generated in use_builtin_models().
constexpr float ENCODER_B1_INIT[16] = {
    0.01f, -0.02f, 0.03f, 0.01f, -0.01f, 0.02f, -0.03f, 0.01f,
    0.02f, -0.01f, 0.03f, -0.02f, 0.01f, 0.02f, -0.01f, 0.03f,
};
constexpr float ENCODER_B2_INIT[ai_latent_dim] = {
    0.02f, -0.01f, 0.03f, -0.02f, 0.01f, 0.02f, -0.01f, 0.03f,
};
constexpr float DECODER_B1_INIT[16] = {
    -0.01f, 0.02f, -0.02f, 0.01f, 0.03f, -0.01f, 0.02f, -0.03f,
    0.01f, -0.02f, 0.02f, 0.01f, -0.01f, 0.03f, -0.02f, 0.01f,
};
constexpr float CLASSIFIER_B_INIT[ai_num_attack_classes] = {
    0.1f, -0.1f, 0.05f, -0.05f, 0.15f, -0.15f, 0.08f, -0.08f,
};

#ifdef HAVE_HAILO
bool hailo_infer(ai_engine& /*engine*/,
                 const float* /*input*/,
                 float* /*output*/,
                 std::size_t /*batch_size*/) {
    // TODO: hook into HailoRT C SDK using extern "C" calls.
    return false;
}
#endif

[[nodiscard]] inline std::uint8_t proto_byte(flow_protocol p) noexcept {
    return static_cast<std::uint8_t>(p);
}

}  // namespace

// ============================================================================
// ai_engine static method
// ============================================================================

bool ai_engine::has_hailo() noexcept {
#ifdef HAVE_HAILO
    hailo_vdevice_params_t params {};
    hailo_vdevice vdevice;
    if (hailo_create_vdevice(&params, &vdevice) == HAILO_SUCCESS) {
        hailo_release_vdevice(vdevice);
        return true;
    }
#endif
    return false;
}

// ============================================================================
// Lifecycle
// ============================================================================

ai_engine::ai_engine(ai_backend backend, const char* /*model_dir*/)
    : backend_(backend)
{
    if (backend == ai_backend::automatic || backend == ai_backend::hailo) {
        hailo_available_ = has_hailo();
        if (hailo_available_) {
            backend_ = ai_backend::hailo;
            std::snprintf(stats_.hailo_device, sizeof(stats_.hailo_device), "Hailo-8L");
        }
    }

    if (!hailo_available_) {
        backend_ = ai_backend::cpu;
    }
    stats_.hailo_available = hailo_available_;

    use_builtin_models();

    for (std::size_t i = 0; i < ai_feature_dim; ++i) {
        baseline_mean_[i] = 0.5f;
        baseline_std_ [i] = 0.25f;
    }
}

ai_engine::~ai_engine() = default;

void ai_engine::get_stats(ai_engine_stats& out_stats) const {
    std::scoped_lock lock(stats_lock_);
    out_stats = stats_;
}

// ============================================================================
// Feature Extraction (free functions)
// ============================================================================

void ai_extract_features(const flow_key& key,
                         const flow_stats& stats,
                         ai_feature_vector& out) {
    out = ai_feature_vector{};

    double duration_ns  = static_cast<double>(stats.last_seen_ns - stats.first_seen_ns);
    double duration_sec = duration_ns / 1e9;
    if (duration_sec < 0.001) duration_sec = 0.001;

    out.packets_per_sec = static_cast<float>(static_cast<double>(stats.packet_count) / duration_sec) / 100'000.0f;
    out.bytes_per_sec   = static_cast<float>(static_cast<double>(stats.byte_count)   / duration_sec) / 1e8f;
    out.avg_packet_size = static_cast<float>(stats.byte_count / (stats.packet_count + 1)) / 1500.0f;

    out.flow_duration       = static_cast<float>(duration_sec / 60.0);
    out.inter_arrival_time  = static_cast<float>(duration_ns / static_cast<double>(stats.packet_count + 1)) / 1e7f;

    out.is_tcp  = (key.protocol == proto_byte(flow_protocol::tcp))  ? 1.0f : 0.0f;
    out.is_udp  = (key.protocol == proto_byte(flow_protocol::udp))  ? 1.0f : 0.0f;
    out.is_icmp = (key.protocol == proto_byte(flow_protocol::icmp)) ? 1.0f : 0.0f;

    const std::uint32_t total_flags =
        stats.syn_count + stats.ack_count + stats.fin_count + stats.rst_count + 1;
    out.syn_ratio = static_cast<float>(stats.syn_count) / static_cast<float>(total_flags);
    out.ack_ratio = static_cast<float>(stats.ack_count) / static_cast<float>(total_flags);
    out.fin_ratio = static_cast<float>(stats.fin_count) / static_cast<float>(total_flags);
    out.rst_ratio = static_cast<float>(stats.rst_count) / static_cast<float>(total_flags);
    out.syn_ack_ratio = (stats.ack_count > 0)
        ? static_cast<float>(stats.syn_count) / static_cast<float>(stats.ack_count)
        : static_cast<float>(stats.syn_count);
    out.syn_ack_ratio = std::min(out.syn_ack_ratio / 10.0f, 1.0f);

    out.src_port_norm     = static_cast<float>(key.src_port) / 65535.0f;
    out.dst_port_norm     = static_cast<float>(key.dst_port) / 65535.0f;
    out.is_well_known_port = (key.dst_port < 1024) ? 1.0f : 0.0f;
    out.is_dns_port  = (key.dst_port == 53  || key.src_port == 53)  ? 1.0f : 0.0f;
    out.is_ntp_port  = (key.dst_port == 123 || key.src_port == 123) ? 1.0f : 0.0f;
    out.is_http_port = (key.dst_port == 80  || key.dst_port == 443) ? 1.0f : 0.0f;

    float* f = out.data();
    for (std::size_t i = 0; i < ai_feature_dim; ++i) {
        f[i] = std::clamp(f[i], 0.0f, 1.0f);
    }
}

void ai_extract_aggregate_features(const flow_metrics& metrics,
                                   const entropy_analysis* entropy,
                                   ai_feature_vector& out) {
    out = ai_feature_vector{};

    out.packets_per_sec = static_cast<float>(metrics.total_packets) / 1e6f;
    out.bytes_per_sec   = static_cast<float>(metrics.total_bytes)   / 1e9f;

    if (entropy) {
        out.unique_src_ips  = static_cast<float>(entropy->unique_src_ips) / 10'000.0f;
        out.unique_dst_ips  = static_cast<float>(entropy->unique_dst_ips) / 10'000.0f;
        out.src_ip_entropy  = static_cast<float>(entropy->src_ip_entropy / 16.0);
        out.dst_ip_entropy  = static_cast<float>(entropy->dst_ip_entropy / 16.0);
    }

    float* f = out.data();
    for (std::size_t i = 0; i < ai_feature_dim; ++i) {
        f[i] = std::clamp(f[i], 0.0f, 1.0f);
    }
}

// ============================================================================
// Forward passes (private members)
// ============================================================================

void ai_engine::autoencoder_forward(const float* input, float* latent, float* output) const {
    float hidden1[16];
    float hidden2[16];

    matmul_bias_relu(input, ai_feature_dim,
                     reinterpret_cast<const float*>(encoder_w1_), encoder_b1_, 16, hidden1);
    matmul_bias_relu(hidden1, 16,
                     reinterpret_cast<const float*>(encoder_w2_), encoder_b2_, ai_latent_dim, latent);

    matmul_bias_relu(latent, ai_latent_dim,
                     reinterpret_cast<const float*>(decoder_w1_), decoder_b1_, 16, hidden2);

    // Output layer (sigmoid for [0,1] output)
    for (std::size_t j = 0; j < ai_feature_dim; ++j) {
        float sum = decoder_b2_[j];
        for (std::size_t i = 0; i < 16; ++i) {
            sum += hidden2[i] * decoder_w2_[i][j];
        }
        output[j] = sigmoid(sum);
    }
}

void ai_engine::classifier_forward(const float* latent, float* probabilities) const {
    for (std::size_t j = 0; j < ai_num_attack_classes; ++j) {
        float sum = classifier_b_[j];
        for (std::size_t i = 0; i < ai_latent_dim; ++i) {
            sum += latent[i] * classifier_w_[i][j];
        }
        probabilities[j] = sum;
    }
    softmax(probabilities, ai_num_attack_classes);
}

// ============================================================================
// Inference
// ============================================================================

bool ai_engine::detect_anomaly(const ai_feature_vector& features, ai_anomaly_result& out) {
    const double start = get_time_ms();

    float input[ai_feature_dim];
    float output[ai_feature_dim];
    float latent[ai_latent_dim];

    const float* feat = features.data();
    for (std::size_t i = 0; i < ai_feature_dim; ++i) {
        float z = (feat[i] - baseline_mean_[i]) / (baseline_std_[i] + 1e-6f);
        z = std::clamp(z, -3.0f, 3.0f);
        input[i] = (z + 3.0f) / 6.0f;
    }

#ifdef HAVE_HAILO
    if (hailo_available_) {
        if (!hailo_infer(*this, input, output, 1)) {
            autoencoder_forward(input, latent, output);
        }
    } else
#endif
    {
        autoencoder_forward(input, latent, output);
    }

    out.reconstruction_error = mse(input, output, ai_feature_dim);
    out.anomaly_score = 1.0f - std::exp(-out.reconstruction_error * 10.0f);
    out.is_anomaly    = out.anomaly_score > anomaly_threshold_;
    std::memcpy(out.latent, latent, sizeof(out.latent));

    const double elapsed = get_time_ms() - start;
    std::scoped_lock lock(stats_lock_);
    stats_.total_inferences++;
    if (out.is_anomaly) stats_.anomalies_detected++;
    stats_.avg_inference_time_ms =
        (stats_.avg_inference_time_ms * static_cast<double>(stats_.total_inferences - 1) + elapsed)
        / static_cast<double>(stats_.total_inferences);
    if (elapsed > stats_.peak_inference_time_ms) {
        stats_.peak_inference_time_ms = elapsed;
    }

    return true;
}

bool ai_engine::classify_attack(const ai_feature_vector& features, ai_classifier_result& out) {
    ai_anomaly_result anomaly;
    if (!detect_anomaly(features, anomaly)) {
        return false;
    }

    classifier_forward(anomaly.latent, out.probabilities);

    out.predicted_class = attack_type::none;
    out.confidence      = out.probabilities[0];
    for (std::size_t i = 1; i < ai_num_attack_classes; ++i) {
        if (out.probabilities[i] > out.confidence) {
            out.confidence      = out.probabilities[i];
            // Match the original C semantics: probabilities[i] for i>=1 maps
            // to ATTACK_(SYN_FLOOD|UDP_AMPLIFY|...) which are 1u << (i - 1).
            using U = std::underlying_type_t<attack_type>;
            out.predicted_class = static_cast<attack_type>(static_cast<U>(1u << (i - 1)));
        }
    }

    std::scoped_lock lock(stats_lock_);
    if (out.predicted_class != attack_type::none) {
        stats_.attacks_classified++;
    }
    return true;
}

bool ai_engine::infer(const ai_feature_vector& features, ai_inference_result& out) {
    const double start = get_time_ms();

    const bool success = detect_anomaly(features, out.anomaly);
    if (success && out.anomaly.is_anomaly) {
        classify_attack(features, out.classification);
    } else {
        out.classification = ai_classifier_result{};
    }

    out.inference_time_ms = static_cast<float>(get_time_ms() - start);
    out.used_accelerator  = hailo_available_;
    return success;
}

std::size_t ai_engine::infer_batch(const ai_feature_vector* features,
                                   std::size_t count,
                                   ai_inference_result* out_results) {
    if (!features || !out_results || count == 0) return 0;

    std::size_t success_count = 0;
    for (std::size_t i = 0; i < count; ++i) {
        if (infer(features[i], out_results[i])) {
            ++success_count;
        }
    }

    std::scoped_lock lock(stats_lock_);
    ++stats_.batch_count;
    return success_count;
}

// ============================================================================
// Model management
// ============================================================================

bool ai_engine::use_builtin_models() {
    // Deterministic "random" init using sin() of mixed indices, same as the
    // original C code; behavior is preserved bit-for-bit.
    for (std::size_t i = 0; i < ai_feature_dim; ++i) {
        for (std::size_t j = 0; j < 16; ++j) {
            encoder_w1_[i][j] = std::sin(static_cast<float>(i * 17 + j * 31)) * 0.15f;
        }
    }
    std::memcpy(encoder_b1_, ENCODER_B1_INIT, sizeof(ENCODER_B1_INIT));

    for (std::size_t i = 0; i < 16; ++i) {
        for (std::size_t j = 0; j < ai_latent_dim; ++j) {
            encoder_w2_[i][j] = std::sin(static_cast<float>(i * 23 + j * 37)) * 0.18f;
        }
    }
    std::memcpy(encoder_b2_, ENCODER_B2_INIT, sizeof(ENCODER_B2_INIT));

    // Decoder weights initialized to the transpose of encoder weights.
    for (std::size_t i = 0; i < ai_latent_dim; ++i) {
        for (std::size_t j = 0; j < 16; ++j) {
            decoder_w1_[i][j] = encoder_w2_[j][i];
        }
    }
    std::memcpy(decoder_b1_, DECODER_B1_INIT, sizeof(DECODER_B1_INIT));

    for (std::size_t i = 0; i < 16; ++i) {
        for (std::size_t j = 0; j < ai_feature_dim; ++j) {
            decoder_w2_[i][j] = encoder_w1_[j][i];
        }
    }

    for (std::size_t i = 0; i < ai_latent_dim; ++i) {
        for (std::size_t j = 0; j < ai_num_attack_classes; ++j) {
            classifier_w_[i][j] = std::sin(static_cast<float>(i * 41 + j * 43)) * 0.25f;
        }
    }
    std::memcpy(classifier_b_, CLASSIFIER_B_INIT, sizeof(CLASSIFIER_B_INIT));

    return true;
}

bool ai_engine::load_model_hef(ai_model_type /*model_type*/, const char* hef_path) {
#ifdef HAVE_HAILO
    if (!hef_path || !hailo_available_) return false;
    // TODO: load HEF file via HailoRT C SDK.
    return true;
#else
    (void)hef_path;
    return false;
#endif
}

bool ai_engine::load_model_onnx(ai_model_type /*model_type*/, const char* /*onnx_path*/) {
    // TODO: implement ONNX loading.
    return false;
}

// ============================================================================
// Online learning
// ============================================================================

void ai_engine::update_model(const ai_feature_vector& features,
                             attack_type /*label*/,
                             bool is_anomaly) {
    const float* feat = features.data();

    if (baseline_samples_ < MAX_BASELINE_SAMPLES && !is_anomaly) {
        const float alpha = 1.0f / static_cast<float>(baseline_samples_ + 1);
        for (std::size_t i = 0; i < ai_feature_dim; ++i) {
            const float diff = feat[i] - baseline_mean_[i];
            baseline_mean_[i] += alpha * diff;

            // Welford's online variance
            const float diff2 = feat[i] - baseline_mean_[i];
            float m2 = baseline_std_[i] * baseline_std_[i] *
                       static_cast<float>(baseline_samples_);
            m2 += diff * diff2;
            baseline_std_[i] = std::sqrt(m2 / static_cast<float>(baseline_samples_ + 1));
        }
        ++baseline_samples_;
    }
}

void ai_engine::get_baseline(ai_feature_vector& out_baseline) const {
    float* out = out_baseline.data();
    for (std::size_t i = 0; i < ai_feature_dim; ++i) {
        out[i] = baseline_mean_[i];
    }
}

// ============================================================================
// Utility
// ============================================================================

void ai_print_features(const ai_feature_vector& features) {
    std::cout << "Features:\n";
    std::cout << std::format("  Rate:     PPS={:.3f} BPS={:.3f} AvgSize={:.3f}\n",
                             features.packets_per_sec, features.bytes_per_sec, features.avg_packet_size);
    std::cout << std::format("  Protocol: TCP={:.0f} UDP={:.0f} ICMP={:.0f}\n",
                             features.is_tcp, features.is_udp, features.is_icmp);
    std::cout << std::format("  TCP:      SYN={:.3f} ACK={:.3f} FIN={:.3f} RST={:.3f}\n",
                             features.syn_ratio, features.ack_ratio,
                             features.fin_ratio, features.rst_ratio);
    std::cout << std::format("  Entropy:  SrcIP={:.3f} DstIP={:.3f}\n",
                             features.src_ip_entropy, features.dst_ip_entropy);
}

void ai_print_result(const ai_inference_result& result) {
    std::cout << "AI Inference Result:\n";
    std::cout << std::format("  Anomaly:    {} (score={:.3f}, error={:.3f})\n",
                             result.anomaly.is_anomaly ? "YES" : "no",
                             result.anomaly.anomaly_score,
                             result.anomaly.reconstruction_error);
    if (result.anomaly.is_anomaly) {
        std::cout << std::format("  Attack:     {} (confidence={:.1f}%)\n",
                                 ai_attack_type_str(result.classification.predicted_class),
                                 result.classification.confidence * 100.0f);
    }
    std::cout << std::format("  Time:       {:.2f} ms ({})\n",
                             result.inference_time_ms,
                             result.used_accelerator ? "Hailo" : "CPU");
}

const char* ai_attack_type_str(attack_type type) noexcept {
    switch (type) {
        case attack_type::none:        return "Normal";
        case attack_type::syn_flood:   return "SYN Flood";
        case attack_type::udp_amplify: return "UDP Amplification";
        case attack_type::dns_amplify: return "DNS Amplification";
        case attack_type::ntp_amplify: return "NTP Amplification";
        case attack_type::icmp_flood:  return "ICMP Flood";
        case attack_type::http_flood:  return "HTTP Flood";
        case attack_type::slowloris:   return "Slowloris";
        case attack_type::carpet_bomb: return "Carpet Bombing";
        case attack_type::port_scan:   return "Port Scan";
        case attack_type::volumetric:  return "Volumetric";
        default:                       return "Unknown";
    }
}

}  // namespace flowshield
