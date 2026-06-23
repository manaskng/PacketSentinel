// =============================================================================
// main_mt.cpp -- Multi-threaded DPI engine entry point
// =============================================================================

#include "dpi_engine.h"
#include "rule_manager.h"
#include <iostream>
#include <iomanip>
#include <string>
#include <cstring>
#include <chrono>

static void printUsage(const char* name) {
    std::cerr << "\nDPI Engine v2.0 -- Multi-threaded Deep Packet Inspection\n\n"
              << "Usage: " << name << " <input.pcap> <output.pcap> [options]\n\n"
              << "Thread options:\n"
              << "  --lbs N              Load Balancer thread count (default 2)\n"
              << "  --fps M              FastPath threads per LB (default 2)\n"
              << "  --queue-size N       Per-queue capacity (default 1024)\n\n"
              << "Blocking rules:\n"
              << "  --block-app <name>   Block app (YouTube, TikTok, Netflix...)\n"
              << "  --block-ip  <ip>     Block source IP address\n"
              << "  --block-domain <s>   Block domains containing substring\n"
              << "  --throttle-app <n>   Throttle app (delay, don't drop)\n"
              << "  --throttle-ms <N>    Throttle delay in ms (default 10)\n"
              << "  --rules-file <path>  Load rules from JSON file\n\n"
              << "Output:\n"
              << "  --no-stats           Disable live stats\n"
              << "  --stats-json         Write stats.json (for web dashboard)\n"
              << "  --stats-file <path>  Custom stats JSON path\n\n"
              << "Examples:\n"
              << "  " << name << " capture.pcap filtered.pcap\n"
              << "  " << name << " capture.pcap filtered.pcap --lbs 2 --fps 4 --block-app YouTube\n"
              << "  " << name << " capture.pcap filtered.pcap --rules-file rules.json --stats-json\n\n";
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        printUsage(argv[0]);
        return 1;
    }

    DPIConfig   config;
    RuleManager rules;

    config.input_file  = argv[1];
    config.output_file = argv[2];

    for (int i = 3; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "--lbs" && i + 1 < argc) {
            config.num_lbs = std::max(1, std::stoi(argv[++i]));
        } else if (arg == "--fps" && i + 1 < argc) {
            config.num_fps_per_lb = std::max(1, std::stoi(argv[++i]));
        } else if (arg == "--queue-size" && i + 1 < argc) {
            config.queue_capacity = static_cast<size_t>(std::max(16, std::stoi(argv[++i])));
        } else if ((arg == "--block-app" || arg == "-B") && i + 1 < argc) {
            rules.addBlockedApp(argv[++i]);
        } else if ((arg == "--block-ip" || arg == "-I") && i + 1 < argc) {
            rules.addBlockedIP(argv[++i]);
        } else if (arg == "--block-domain" && i + 1 < argc) {
            rules.addBlockedDomain(argv[++i]);
        } else if (arg == "--throttle-app" && i + 1 < argc) {
            rules.addThrottledApp(argv[++i]);
        } else if (arg == "--throttle-ms" && i + 1 < argc) {
            int ms = std::stoi(argv[++i]);
            rules.setThrottleDelay(std::chrono::milliseconds(ms));
        } else if (arg == "--rules-file" && i + 1 < argc) {
            if (!rules.loadFromJSON(argv[++i])) {
                std::cerr << "[Error] Failed to load rules file\n";
                return 1;
            }
        } else if (arg == "--no-stats") {
            config.enable_stats = false;
        } else if (arg == "--stats-json") {
            config.write_stats_json = true;
        } else if (arg == "--stats-file" && i + 1 < argc) {
            config.write_stats_json = true;
            config.stats_json_file  = argv[++i];
        } else if (arg == "--stats-interval" && i + 1 < argc) {
            config.stats_interval_ms = std::stoi(argv[++i]);
        } else {
            std::cerr << "[Warning] Unknown argument: " << arg << "\n";
        }
    }

    // Print configuration banner
    std::cout << "\n"
              << "+------------------------------------------------------------------+\n"
              << "|         DPI ENGINE v2.0 -- Multi-threaded Pipeline               |\n"
              << "+------------------------------------------------------------------+\n"
              << "| Input:   " << std::left << std::setw(55) << config.input_file  << "|\n"
              << "| Output:  " << std::left << std::setw(55) << config.output_file << "|\n"
              << "| LBs: " << config.num_lbs << "  FPs/LB: " << config.num_fps_per_lb
              << "  Total FPs: " << config.num_lbs * config.num_fps_per_lb
              << std::string(36, ' ') << "|\n"
              << "+------------------------------------------------------------------+\n\n";

    if (rules.hasAnyRules()) {
        std::cout << "[Rules Active]\n";
        rules.printRules();
        std::cout << "\n";
    }

    DPIEngine engine(config, rules);
    AggregatedStats stats = engine.run();

    DPIEngine::printReport(stats, config, rules);

    return 0;
}
