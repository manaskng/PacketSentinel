// =============================================================================
// dpi_engine.cpp -- Multi-threaded DPI orchestrator implementation
// =============================================================================

#include "dpi_engine.h"
#include "pcap_reader.h"
#include "packet_parser.h"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <chrono>
#include <fstream>
#include <map>
#include <set>
#include <thread>
#include <numeric>

// ---------------------------------------------------------------------------
// Constructor
// ---------------------------------------------------------------------------
DPIEngine::DPIEngine(const DPIConfig& config, const RuleManager& rules)
    : config_(config)
    , rules_(rules)
    , output_queue_(config.queue_capacity * 4)
{
    int total_fps = config_.num_lbs * config_.num_fps_per_lb;

    fps_.reserve(total_fps);
    for (int i = 0; i < total_fps; ++i) {
        fps_.push_back(std::make_unique<FastPath>(
            i, rules_, &output_queue_, config_.queue_capacity));
    }

    lbs_.reserve(config_.num_lbs);
    for (int lb_i = 0; lb_i < config_.num_lbs; ++lb_i) {
        std::vector<FastPath*> lb_fps;
        for (int fp_i = 0; fp_i < config_.num_fps_per_lb; ++fp_i) {
            lb_fps.push_back(fps_[lb_i * config_.num_fps_per_lb + fp_i].get());
        }
        lbs_.push_back(std::make_unique<LoadBalancer>(
            lb_i, std::move(lb_fps), config_.queue_capacity));
    }
}

DPIEngine::~DPIEngine() {
    for (auto& lb : lbs_) lb->stop();
    for (auto& fp : fps_) fp->stop();
    output_queue_.close();
}

// ---------------------------------------------------------------------------
// run -- start all threads, process PCAP, collect stats
// ---------------------------------------------------------------------------
AggregatedStats DPIEngine::run() {
    running_.store(true);

    // 1. Start output writer thread
    std::thread writer_thread([this] {
        outputWriterThread(config_.output_file);
    });

    // 2. Start all FastPath threads
    for (auto& fp : fps_) fp->start();

    // 3. Start all LoadBalancer threads
    for (auto& lb : lbs_) lb->start();

    // 4. Start live stats thread (if enabled)
    std::thread stats_thread;
    if (config_.enable_stats) {
        stats_thread = std::thread([this] { liveStatsThread(); });
    }

    // 5. Reader loop
    PcapReader reader;
    try {
        reader.open(config_.input_file);
    } catch (const std::exception& e) {
        std::cerr << "[Engine] Failed to open input: " << e.what() << "\n";
        running_.store(false);
        for (auto& lb : lbs_) lb->stop();
        for (auto& fp : fps_) fp->stop();
        output_queue_.close();
        if (writer_thread.joinable()) writer_thread.join();
        if (stats_thread.joinable()) stats_thread.join();
        return {};
    }

    FiveTupleHash hasher;
    const size_t  num_lbs = lbs_.size();

    auto start_time = std::chrono::high_resolution_clock::now();
    uint64_t total_packets = 0;
    uint64_t total_bytes   = 0;

    std::cout << "[Engine] Reader started. Processing packets...\n";

    RawPacket raw;
    while (reader.readNextPacket(raw)) {
        ++total_packets;
        total_bytes += raw.header.incl_len;
        live_total_.store(total_packets);

        Packet pkt;
        if (!PacketParser::parseIntoPacket(raw, pkt)) continue;

        size_t lb_idx = hasher(pkt.tuple) % num_lbs;
        lbs_[lb_idx]->inputQueue().push(std::move(pkt));
    }

    auto end_time = std::chrono::high_resolution_clock::now();
    double elapsed = std::chrono::duration<double>(end_time - start_time).count();

    std::cout << "[Engine] Reader done. Read " << total_packets
              << " packets in " << std::fixed << std::setprecision(2)
              << elapsed << "s\n";

    // 6. Shutdown sequence
    for (auto& lb : lbs_) lb->stop();
    for (auto& fp : fps_) fp->stop();
    output_queue_.close();
    running_.store(false);

    if (writer_thread.joinable()) writer_thread.join();
    if (stats_thread.joinable()) stats_thread.join();

    // 7. Collect stats
    auto agg = collectStats(elapsed, total_packets, total_bytes);

    // Write JSON stats if requested
    if (config_.write_stats_json) {
        std::ofstream jf(config_.stats_json_file);
        if (jf.is_open()) {
            jf << "{\n"
               << "  \"total_packets\": "  << agg.total_packets  << ",\n"
               << "  \"total_bytes\": "    << agg.total_bytes    << ",\n"
               << "  \"forwarded\": "      << agg.forwarded      << ",\n"
               << "  \"dropped\": "        << agg.dropped        << ",\n"
               << "  \"classified\": "     << agg.classified     << ",\n"
               << "  \"elapsed_sec\": "    << agg.elapsed_sec    << ",\n"
               << "  \"kpps\": "           << agg.kpps           << ",\n"
               << "  \"app_counts\": {\n";
            for (size_t i = 0; i < agg.app_pkt_counts.size(); ++i) {
                jf << "    \"" << appTypeToString(agg.app_pkt_counts[i].first)
                   << "\": "   << agg.app_pkt_counts[i].second;
                if (i + 1 < agg.app_pkt_counts.size()) jf << ",";
                jf << "\n";
            }
            jf << "  },\n";
            jf << "  \"detected_snis\": [";
            for (size_t i = 0; i < agg.detected_snis.size(); ++i) {
                jf << "\"" << agg.detected_snis[i] << "\"";
                if (i + 1 < agg.detected_snis.size()) jf << ", ";
            }
            jf << "]\n}\n";
            std::cout << "[Engine] Stats written to " << config_.stats_json_file << "\n";
        }
    }

    return agg;
}

// ---------------------------------------------------------------------------
// outputWriterThread -- drain output queue, write to PCAP
// ---------------------------------------------------------------------------
void DPIEngine::outputWriterThread(const std::string& output_file) {
    PcapWriter writer;
    try {
        writer.open(output_file);
    } catch (const std::exception& e) {
        std::cerr << "[Writer] Failed to open output: " << e.what() << "\n";
        return;
    }

    while (true) {
        auto item = output_queue_.pop();
        if (!item) break;
        writer.writePacket(*item);
        live_forwarded_.fetch_add(1);
    }

    std::cout << "[Writer] Wrote " << writer.packetsWritten()
              << " packets to " << output_file << "\n";
}

// ---------------------------------------------------------------------------
// liveStatsThread -- periodic stats during processing
// ---------------------------------------------------------------------------
void DPIEngine::liveStatsThread() {
    auto interval = std::chrono::milliseconds(config_.stats_interval_ms);
    uint64_t last_total = 0;

    while (running_.load()) {
        std::this_thread::sleep_for(interval);
        uint64_t cur_total     = live_total_.load();
        uint64_t cur_forwarded = live_forwarded_.load();
        uint64_t cur_dropped   = 0;
        for (auto& fp : fps_) cur_dropped += fp->dropped();

        uint64_t delta = cur_total - last_total;
        std::cout << "[Stats]"
                  << " Pkts:"   << std::setw(8) << cur_total
                  << " Delta:"  << std::setw(6) << delta
                  << " Fwd:"    << std::setw(8) << cur_forwarded
                  << " Drop:"   << std::setw(6) << cur_dropped
                  << " Q:"      << output_queue_.size()
                  << "\n";
        last_total = cur_total;
    }
}

// ---------------------------------------------------------------------------
// collectStats -- aggregate from all FP flow tables
// ---------------------------------------------------------------------------
AggregatedStats DPIEngine::collectStats(double elapsed_sec,
                                        uint64_t total_packets,
                                        uint64_t total_bytes) {
    AggregatedStats s;
    s.total_packets = total_packets;
    s.total_bytes   = total_bytes;
    s.elapsed_sec   = elapsed_sec;
    s.kpps = elapsed_sec > 0 ? (total_packets / 1000.0) / elapsed_sec : 0;

    s.fp_processed.resize(fps_.size());
    s.fp_forwarded.resize(fps_.size());
    s.fp_dropped.resize(fps_.size());

    std::map<AppType, uint64_t> app_totals;
    std::set<std::string> all_snis;

    for (size_t i = 0; i < fps_.size(); ++i) {
        s.fp_processed[i] = fps_[i]->processed();
        s.fp_forwarded[i] = fps_[i]->forwarded();
        s.fp_dropped[i]   = fps_[i]->dropped();
        s.forwarded       += s.fp_forwarded[i];
        s.dropped         += s.fp_dropped[i];
        s.classified      += fps_[i]->classified();

        for (const auto& kv : fps_[i]->flowTable()) {
            const Flow& flow = kv.second;
            app_totals[flow.app_type] += flow.packet_count;
            if (!flow.sni.empty()) all_snis.insert(flow.sni);
        }
    }

    s.lb_dispatched.resize(lbs_.size());
    for (size_t i = 0; i < lbs_.size(); ++i) {
        s.lb_dispatched[i] = lbs_[i]->totalDispatched();
    }

    s.app_pkt_counts.assign(app_totals.begin(), app_totals.end());
    std::sort(s.app_pkt_counts.begin(), s.app_pkt_counts.end(),
              [](const auto& a, const auto& b) { return a.second > b.second; });

    s.detected_snis.assign(all_snis.begin(), all_snis.end());
    return s;
}

// ---------------------------------------------------------------------------
// printReport -- clean ASCII table report
// ---------------------------------------------------------------------------
void DPIEngine::printReport(const AggregatedStats& s, const DPIConfig& cfg,
                             const RuleManager& rules) {
    const int W = 66;
    auto hline  = [&]() { std::cout << "+" << std::string(W-2,'-') << "+\n"; };
    auto sep    = [&]() { std::cout << "+" << std::string(W-2,'=') << "+\n"; };
    auto row    = [&](const std::string& label, const std::string& val) {
        std::string content = " " + label;
        std::string rval    = val + " ";
        int space = W - 2 - (int)content.size() - (int)rval.size();
        if (space < 1) space = 1;
        std::cout << "|" << content << std::string(space,' ') << rval << "|\n";
    };
    auto section = [&](const std::string& title) {
        hline();
        int pad = W - 2 - (int)title.size();
        int l = pad/2, r = pad - l;
        std::cout << "|" << std::string(l,' ') << title << std::string(r,' ') << "|\n";
        hline();
    };

    std::cout << "\n";
    sep();
    section("DPI ENGINE v2.0 -- Multi-threaded Pipeline Report");
    row("Load Balancers",   std::to_string(cfg.num_lbs));
    row("FastPaths per LB", std::to_string(cfg.num_fps_per_lb));
    row("Total FastPaths",  std::to_string(cfg.num_lbs * cfg.num_fps_per_lb));
    hline();
    row("Total Packets",   std::to_string(s.total_packets));
    row("Total Bytes",     std::to_string(s.total_bytes));
    row("Forwarded",       std::to_string(s.forwarded));
    row("Dropped",         std::to_string(s.dropped));
    row("Classified",      std::to_string(s.classified) + " flows");
    {
        std::ostringstream oss;
        oss << std::fixed << std::setprecision(1) << s.kpps << " Kpps";
        row("Throughput", oss.str());
    }
    sep();

    section("LOAD BALANCER STATISTICS");
    for (size_t i = 0; i < s.lb_dispatched.size(); ++i) {
        row("  LB" + std::to_string(i) + " dispatched", std::to_string(s.lb_dispatched[i]));
    }
    hline();

    section("FAST PATH STATISTICS");
    for (size_t i = 0; i < s.fp_processed.size(); ++i) {
        row("  FP" + std::to_string(i) + " processed/fwd/drop",
            std::to_string(s.fp_processed[i]) + "/" +
            std::to_string(s.fp_forwarded[i]) + "/" +
            std::to_string(s.fp_dropped[i]));
    }
    sep();

    section("APPLICATION BREAKDOWN");
    for (const auto& kv : s.app_pkt_counts) {
        AppType  app = kv.first;
        uint64_t cnt = kv.second;
        double   pct = s.total_packets > 0 ? cnt * 100.0 / s.total_packets : 0.0;
        bool     blk = rules.blockedApps().count(app) > 0;

        std::ostringstream label;
        label << std::left  << std::setw(14) << appTypeToString(app)
              << std::right << std::setw(8)  << cnt
              << " " << std::setw(5) << std::fixed << std::setprecision(1) << pct << "%";

        int bar_fill = static_cast<int>(pct / 5);
        std::string bar = " " + std::string(std::min(bar_fill, 14), '#');
        if (blk) bar += " (BLOCKED)";
        row(label.str(), bar);
    }
    sep();

    if (!s.detected_snis.empty()) {
        section("DETECTED DOMAINS / SNIs");
        for (const auto& sni : s.detected_snis) {
            AppType app = sniToAppType(sni);
            bool    blk = rules.isBlocked(0, app, sni);
            std::string label = "  " + sni;
            if ((int)label.size() > 44) label = label.substr(0, 42) + "..";
            row(label, "-> " + appTypeToString(app) + (blk ? " [BLOCKED]" : ""));
        }
        sep();
    }
    std::cout << "\n";
}
