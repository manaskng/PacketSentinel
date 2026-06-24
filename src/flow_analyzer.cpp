// =============================================================================
// flow_analyzer.cpp -- Anomaly detection scoring implementation
// =============================================================================
// Shannon entropy + Z-score statistical anomaly detection.
// Zero external dependencies. All math is from first principles.
// =============================================================================

#include "flow_analyzer.h"
#include <cmath>
#include <algorithm>

// ---------------------------------------------------------------------------
// shannonEntropy -- byte-level entropy calculation
// ---------------------------------------------------------------------------
// Builds a 256-bin frequency histogram of the payload bytes, then computes:
//   H = -SUM( p(x) * log2(p(x)) )  for each byte value x with p(x) > 0
//
// Results:
//   0.0 bits  = all bytes identical (e.g., NUL padding)
//   4.0-6.0   = typical plaintext HTTP, HTML, JSON
//   7.0-7.5   = compressed data (gzip, images)
//   7.5-8.0   = encrypted data (TLS payload, VPN tunnel, C2 channel)
//   8.0 bits  = theoretically perfect randomness
//
double FlowAnalyzer::shannonEntropy(const uint8_t* data, uint32_t len) {
    if (!data || len == 0) return 0.0;

    // Build frequency histogram (stack-allocated, no heap)
    uint32_t freq[256] = {};
    for (uint32_t i = 0; i < len; ++i) {
        ++freq[data[i]];
    }

    double entropy = 0.0;
    const double n = static_cast<double>(len);

    for (int i = 0; i < 256; ++i) {
        if (freq[i] == 0) continue;
        double p = static_cast<double>(freq[i]) / n;
        entropy -= p * std::log2(p);
    }

    return entropy;
}

// ---------------------------------------------------------------------------
// score -- multi-dimensional anomaly scoring
// ---------------------------------------------------------------------------
// Evaluates 5 independent detectors and returns the highest-scoring result.
// Each detector outputs a score in [0.0, 1.0]. The composite score is the
// maximum of all individual scores (worst-case anomaly wins).
//
// Detector         | Feature Used              | Research Basis
// -----------------|---------------------------|-------------------
// Port Scan        | low pkt count + SYN-only  | NSL-KDD "probe"
// DDoS             | zero variance + high rate | CICIDS2017 "DoS"
// Data Exfiltration| high avg size + volume    | CICIDS2017 "Infiltration"
// High Entropy     | Shannon > 7.5 on non-TLS  | Custom (C2 detection)
// Protocol Anomaly | SYN+FIN or RST ratio      | NSL-KDD flag features
//
AnomalyResult FlowAnalyzer::score(const Flow& flow) {
    AnomalyResult best;
    best.score = 0.0;
    best.type  = AnomalyType::NONE;

    if (flow.packet_count < 2) return best;

    // --- 1. Port Scan Detection -------------------------------------------
    // Short-lived flows with SYN but no data payload are typical of port scans.
    // A port scanner sends SYN to hundreds of ports; each "flow" has 1-3 packets.
    if (flow.packet_count <= SCAN_MAX_PKTS && flow.syn_count > 0 && flow.fin_count == 0) {
        double scan_score = 0.0;
        // Very low byte count relative to packet count suggests no real data
        double avg_bytes = (double)flow.byte_count / flow.packet_count;
        if (avg_bytes < 128.0) {  // Typical SYN packet is ~60 bytes
            scan_score = 0.85;
        } else {
            scan_score = 0.5;
        }
        if (scan_score > best.score) {
            best.score  = scan_score;
            best.type   = AnomalyType::PORT_SCAN;
            best.reason = "Short flow with SYN-only behavior (avg " +
                          std::to_string((int)avg_bytes) + " bytes/pkt)";
        }
    }

    // --- 2. DDoS Detection ------------------------------------------------
    // DDoS floods use identically-sized packets at high volume.
    // Variance near zero + high packet count = amplification attack signature.
    if (flow.packet_count >= DDOS_MIN_PACKETS) {
        double variance = flow.packetSizeVariance();
        if (variance < DDOS_VARIANCE_CEILING) {
            double ddos_score = std::min(1.0,
                0.6 + 0.4 * (1.0 - variance / DDOS_VARIANCE_CEILING));
            if (ddos_score > best.score) {
                best.score  = ddos_score;
                best.type   = AnomalyType::DDOS_SUSPECT;
                best.reason = "Uniform packet sizes (var=" +
                              std::to_string((int)variance) +
                              ") across " + std::to_string(flow.packet_count) + " pkts";
            }
        }
    }

    // --- 3. Data Exfiltration Detection -----------------------------------
    // Unusually large average payload sizes suggest bulk data transfer.
    // Normal browsing flows have avg ~300-800 bytes; exfil flows are 2KB+.
    if (flow.byte_count >= EXFIL_MIN_BYTES) {
        double avg_size = (double)flow.byte_count / flow.packet_count;
        if (avg_size > EXFIL_AVG_SIZE) {
            double exfil_score = std::min(1.0,
                0.5 + 0.5 * ((avg_size - EXFIL_AVG_SIZE) / EXFIL_AVG_SIZE));
            if (exfil_score > best.score) {
                best.score  = exfil_score;
                best.type   = AnomalyType::DATA_EXFILTRATION;
                best.reason = "Large avg payload (" + std::to_string((int)avg_size) +
                              " bytes) with " + std::to_string(flow.byte_count / 1024) + "KB total";
            }
        }
    }

    // --- 4. High Entropy Detection ----------------------------------------
    // Encrypted C2 channels and tunnels on non-TLS ports have near-max entropy.
    // TLS on port 443 is EXPECTED to have high entropy, so we skip those.
    bool is_tls_port = (flow.app_type == AppType::HTTPS ||
                        flow.app_type == AppType::YOUTUBE ||
                        flow.app_type == AppType::NETFLIX ||
                        flow.app_type == AppType::FACEBOOK ||
                        flow.app_type == AppType::GOOGLE ||
                        flow.app_type == AppType::GITHUB ||
                        flow.app_type == AppType::DISCORD ||
                        flow.app_type == AppType::INSTAGRAM ||
                        flow.app_type == AppType::TWITTER ||
                        flow.app_type == AppType::WHATSAPP ||
                        flow.app_type == AppType::TWITCH ||
                        flow.app_type == AppType::REDDIT ||
                        flow.app_type == AppType::TIKTOK);

    if (!is_tls_port && flow.payload_entropy > ENTROPY_THRESHOLD) {
        double entropy_score = std::min(1.0,
            0.5 + 0.5 * ((flow.payload_entropy - ENTROPY_THRESHOLD) / (8.0 - ENTROPY_THRESHOLD)));
        if (entropy_score > best.score) {
            best.score  = entropy_score;
            best.type   = AnomalyType::HIGH_ENTROPY;
            best.reason = "High payload entropy (" +
                          std::to_string(flow.payload_entropy).substr(0, 4) +
                          " bits) on non-TLS traffic";
        }
    }

    // --- 5. Protocol Anomaly Detection ------------------------------------
    // Christmas tree packets (SYN+FIN+RST set) or abnormal flag ratios
    // indicate reconnaissance tools (nmap) or crafted packets.
    if (flow.packet_count >= 3) {
        uint32_t total_flags = flow.syn_count + flow.fin_count + flow.rst_count;
        if (total_flags > 0) {
            // SYN and RST together is highly suspicious
            double syn_ratio = (double)flow.syn_count / flow.packet_count;
            double rst_ratio = (double)flow.rst_count / flow.packet_count;

            if (syn_ratio > FLAG_ANOMALY_RATIO || rst_ratio > FLAG_ANOMALY_RATIO) {
                double proto_score = std::max(syn_ratio, rst_ratio);
                if (proto_score > best.score) {
                    best.score  = proto_score;
                    best.type   = AnomalyType::PROTOCOL_ANOMALY;
                    best.reason = "Abnormal TCP flag ratio (SYN:" +
                                  std::to_string(flow.syn_count) + " FIN:" +
                                  std::to_string(flow.fin_count) + " RST:" +
                                  std::to_string(flow.rst_count) + ")";
                }
            }

            // Christmas tree: all three flags seen in same flow
            if (flow.syn_count > 0 && flow.fin_count > 0 && flow.rst_count > 0) {
                double xmas_score = 0.9;
                if (xmas_score > best.score) {
                    best.score  = xmas_score;
                    best.type   = AnomalyType::PROTOCOL_ANOMALY;
                    best.reason = "Christmas tree scan pattern (SYN+FIN+RST in same flow)";
                }
            }
        }
    }

    return best;
}
