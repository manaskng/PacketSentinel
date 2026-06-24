#pragma once
// =============================================================================
// dpi_engine.h — Multi-threaded DPI orchestrator
// =============================================================================
// Manages the full thread pipeline:
//   Reader → LB threads → FP threads → Output Writer
//                                    ↗ Live Stats Thread
// =============================================================================

#ifndef DPI_ENGINE_H
#define DPI_ENGINE_H

#include "types.h"
#include "rule_manager.h"
#include "thread_safe_queue.h"
#include "load_balancer.h"
#include "fast_path.h"
#include <string>
#include <vector>
#include <memory>
#include <thread>
#include <atomic>
#include <functional>
#include <chrono>
#include <map>

struct DPIConfig {
    std::string  input_file;
    std::string  output_file;
    int          num_lbs         = 2;   // Number of Load Balancer threads
    int          num_fps_per_lb  = 2;   // Number of FastPath threads per LB
    size_t       queue_capacity  = 1024;
    bool         enable_stats    = true;
    int          stats_interval_ms = 1000;  // Live stats print interval
    bool         write_stats_json  = false; // Write JSON stats file for dashboard
    std::string  stats_json_file   = "stats.json";
};

struct AggregatedStats {
    uint64_t total_packets  = 0;
    uint64_t total_bytes    = 0;
    uint64_t forwarded      = 0;
    uint64_t dropped        = 0;
    uint64_t classified     = 0;
    double   elapsed_sec    = 0.0;
    double   kpps           = 0.0;

    // Per-LB stats
    std::vector<uint64_t> lb_dispatched;
    // Per-FP stats
    std::vector<uint64_t> fp_processed;
    std::vector<uint64_t> fp_forwarded;
    std::vector<uint64_t> fp_dropped;

    // App type counts (aggregated from all FP flow tables)
    std::vector<std::pair<AppType, uint64_t>> app_pkt_counts;
    std::vector<std::string> detected_snis;

    // Anomaly detection stats
    uint64_t total_anomalies = 0;
    std::map<std::string, uint64_t> anomaly_breakdown;  // type -> count

    struct AnomalousFlow {
        std::string src_ip;
        std::string dst_ip;
        double      score;
        std::string type;
        std::string sni;
        uint64_t    packet_count;
    };
    std::vector<AnomalousFlow> top_anomalies;  // top 10 by score
};

class DPIEngine {
public:
    explicit DPIEngine(const DPIConfig& config, const RuleManager& rules);
    ~DPIEngine();

    DPIEngine(const DPIEngine&)            = delete;
    DPIEngine& operator=(const DPIEngine&) = delete;

    // Run the full pipeline (blocking until all packets are processed)
    AggregatedStats run();

    // Print the final report to stdout
    static void printReport(const AggregatedStats& stats,
                            const DPIConfig& config,
                            const RuleManager& rules);

private:
    // Thread functions
    void outputWriterThread(const std::string& output_file);
    void liveStatsThread();

    // Aggregate stats from all FP threads after processing
    AggregatedStats collectStats(double elapsed_sec, uint64_t total_packets,
                                 uint64_t total_bytes);

    DPIConfig        config_;
    const RuleManager& rules_;

    // Thread pipeline (owned)
    std::vector<std::unique_ptr<LoadBalancer>> lbs_;
    std::vector<std::unique_ptr<FastPath>>     fps_;
    TSQueue<Packet>                            output_queue_;

    // Control
    std::atomic<bool>    running_{false};
    std::atomic<uint64_t> live_forwarded_{0};
    std::atomic<uint64_t> live_dropped_{0};
    std::atomic<uint64_t> live_total_{0};
};

#endif // DPI_ENGINE_H
