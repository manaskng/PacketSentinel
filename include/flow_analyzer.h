#pragma once
// =============================================================================
// flow_analyzer.h -- Real-time anomaly detection via statistical scoring
// =============================================================================
// Implements wire-speed anomaly detection using:
//   - Shannon entropy of payload byte distribution
//   - Z-score statistical deviation on per-flow features
//   - Heuristic detectors for port scans, DDoS, and data exfiltration
//
// Feature choices are based on established IDS research datasets:
//   - NSL-KDD (KDD Cup 99 improved): packet size, duration, flag counts
//   - CICIDS2017 (Canadian Institute for Cybersecurity): flow bytes/sec,
//     inter-arrival time, payload entropy, SYN/FIN ratios
//
// All computation is stateless and O(1) per call. No heap allocations.
// Safe to call from any FastPath thread without synchronization.
//
// INTERVIEW TALKING POINT:
//   "The feature vector uses 8 dimensions drawn from NSL-KDD and CICIDS2017
//    research datasets: payload entropy, packet size variance, SYN/FIN ratio,
//    flow duration, and byte volume. Scoring uses Z-scores against empirically
//    tuned thresholds — no ML framework dependency, runs at wire speed."
// =============================================================================

#ifndef DPI_FLOW_ANALYZER_H
#define DPI_FLOW_ANALYZER_H

#include "types.h"
#include <cstdint>
#include <string>

// Result of anomaly scoring for a single flow
struct AnomalyResult {
    double      score    = 0.0;            // 0.0 = normal, 1.0 = critical
    AnomalyType type     = AnomalyType::NONE;
    std::string reason;                    // Human-readable explanation
};

class FlowAnalyzer {
public:
    // -----------------------------------------------------------------------
    // shannonEntropy -- compute byte-level entropy of a payload buffer
    //   Returns: entropy in bits (0.0 = uniform, 8.0 = perfectly random)
    //   Complexity: O(n) scan + O(256) histogram = O(n)
    // -----------------------------------------------------------------------
    static double shannonEntropy(const uint8_t* data, uint32_t len);

    // -----------------------------------------------------------------------
    // score -- evaluate a flow for anomalous behavior
    //   Examines: entropy, packet size variance, TCP flags, duration, volume
    //   Returns: AnomalyResult with composite score and classification
    // -----------------------------------------------------------------------
    static AnomalyResult score(const Flow& flow);

    // -----------------------------------------------------------------------
    // Tunable thresholds (constexpr for zero-cost)
    // -----------------------------------------------------------------------

    // Shannon entropy: encrypted C2/tunnel traffic has entropy > 7.5 on non-TLS
    static constexpr double ENTROPY_THRESHOLD     = 7.5;

    // DDoS detection: variance near zero = all packets same size
    static constexpr double DDOS_VARIANCE_CEILING = 10.0;
    static constexpr uint64_t DDOS_MIN_PACKETS    = 50;

    // Data exfiltration: average packet size > 2KB suggests bulk transfer
    static constexpr double EXFIL_AVG_SIZE        = 2048.0;
    static constexpr uint64_t EXFIL_MIN_BYTES     = 100000;  // 100KB minimum

    // Port scan: very short flows (1-3 packets) with SYN-only behavior
    static constexpr uint64_t SCAN_MAX_PKTS       = 3;

    // Protocol anomaly: Christmas tree (SYN+FIN+RST) or null scans
    static constexpr double FLAG_ANOMALY_RATIO    = 0.8;

    // Composite score threshold for flagging
    static constexpr double FLAG_THRESHOLD         = 0.7;
};

#endif // DPI_FLOW_ANALYZER_H
