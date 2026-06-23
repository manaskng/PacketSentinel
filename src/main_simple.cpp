// =============================================================================
// main_simple.cpp -- Single-threaded DPI engine entry point
// =============================================================================
// Usage:
//   dpi_simple <input.pcap> <output.pcap> [options]
//   Options:
//     --block-app <name>     Block an app type (e.g., YouTube, TikTok)
//     --block-ip  <ip>       Block a source IP address
//     --block-domain <sub>   Block domains containing substring
//     --throttle-app <name>  Throttle (delay) an app
//     --rules-file <path>    Load rules from JSON file
// =============================================================================

#include "types.h"
#include "pcap_reader.h"
#include "packet_parser.h"
#include "sni_extractor.h"
#include "rule_manager.h"

#include <iostream>
#include <iomanip>
#include <unordered_map>
#include <map>
#include <vector>
#include <string>
#include <chrono>
#include <algorithm>
#include <cstring>
#include <thread>

// ---------------------------------------------------------------------------
// Globals / state
// ---------------------------------------------------------------------------
struct Stats {
    uint64_t total_packets  = 0;
    uint64_t total_bytes    = 0;
    uint64_t tcp_packets    = 0;
    uint64_t udp_packets    = 0;
    uint64_t forwarded      = 0;
    uint64_t dropped        = 0;
    uint64_t throttled_pkts = 0;
    uint64_t sni_extracted  = 0;
    uint64_t http_extracted = 0;
    uint64_t dns_extracted  = 0;
};

// Repeat a UTF-8 string N times (box drawing chars are multi-byte)
static std::string repeatStr(const std::string& s, int n) {
    std::string result;
    result.reserve(s.size() * n);
    for (int i = 0; i < n; ++i) result += s;
    return result;
}

// ---------------------------------------------------------------------------
// Print helpers
// ---------------------------------------------------------------------------
static void printBox(const std::string& title, int width = 64) {
    std::string bar = repeatStr("=", width - 2);
    std::cout << "+" << bar << "+\n";
    int pad = width - 2 - static_cast<int>(title.size());
    if (pad < 0) pad = 0;
    int left  = pad / 2;
    int right = pad - left;
    std::cout << "|" << std::string(left, ' ') << title
              << std::string(right, ' ') << "|\n";
    std::cout << "+" << bar << "+\n";
}

static void printRow(const std::string& label, const std::string& value,
                     int width = 64, bool mark = false) {
    std::string content = " " + label;
    std::string rval    = value + (mark ? " (BLOCKED)" : "") + " ";
    int space = width - 2 - static_cast<int>(content.size()) -
                            static_cast<int>(rval.size());
    if (space < 1) space = 1;
    std::cout << "|" << content << std::string(space, ' ') << rval << "|\n";
}

static void printSep(int width = 64) {
    std::cout << "+" << repeatStr("=", width - 2) << "+\n";
}

static void printClose(int width = 64) {
    std::cout << "+" << repeatStr("=", width - 2) << "+\n";
}

static void printBar(int pct, int bar_width = 20) {
    int filled = (pct * bar_width) / 100;
    std::cout << std::string(filled, '#') << std::string(bar_width - filled, ' ');
}

// ---------------------------------------------------------------------------
// Usage
// ---------------------------------------------------------------------------
static void printUsage(const char* name) {
    std::cerr << "\nUsage: " << name << " <input.pcap> <output.pcap> [options]\n\n"
              << "Options:\n"
              << "  --block-app <name>     Block application (YouTube, TikTok, Netflix, etc.)\n"
              << "  --block-ip  <ip>       Block source IP address\n"
              << "  --block-domain <sub>   Block domain containing substring\n"
              << "  --throttle-app <name>  Throttle (delay) application traffic\n"
              << "  --throttle-ms <N>      Throttle delay in milliseconds (default 10)\n"
              << "  --rules-file <path>    Load rules from JSON file\n"
              << "  --stats                Print live stats during processing\n"
              << "\nExamples:\n"
              << "  " << name << " capture.pcap filtered.pcap --block-app YouTube\n"
              << "  " << name << " capture.pcap filtered.pcap --rules-file rules.json\n\n";
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
int main(int argc, char* argv[]) {
    if (argc < 3) {
        printUsage(argv[0]);
        return 1;
    }

    std::string input_file  = argv[1];
    std::string output_file = argv[2];
    bool        live_stats  = false;

    // Parse CLI arguments
    RuleManager rules;
    for (int i = 3; i < argc; ++i) {
        std::string arg = argv[i];
        if ((arg == "--block-app" || arg == "--block-application") && i + 1 < argc) {
            rules.addBlockedApp(argv[++i]);
        } else if (arg == "--block-ip" && i + 1 < argc) {
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
        } else if (arg == "--stats") {
            live_stats = true;
        } else {
            std::cerr << "[Warning] Unknown argument: " << arg << "\n";
        }
    }

    // ---- Print banner -------------------------------------------------------
    std::cout << "\n";
    printBox("  DPI Engine v2.0 (Single-threaded Mode)  ");
    printRow("Input",  input_file);
    printRow("Output", output_file);
    printClose();
    std::cout << "\n";

    if (rules.hasAnyRules()) {
        std::cout << "[Rules Active]\n";
        rules.printRules();
        std::cout << "\n";
    }

    // ---- Open files ---------------------------------------------------------
    PcapReader reader;
    PcapWriter writer;
    try {
        reader.open(input_file);
        writer.open(output_file, reader.snaplen());
    } catch (const std::exception& e) {
        std::cerr << "[Error] " << e.what() << "\n";
        return 1;
    }

    // ---- Flow table and state -----------------------------------------------
    std::unordered_map<FiveTuple, Flow> flows;
    flows.reserve(4096);

    // App stats: count of flows per app type
    std::map<AppType, uint64_t> app_flow_counts;
    std::map<AppType, uint64_t> app_pkt_counts;

    // Detected SNIs for report
    std::map<std::string, AppType> detected_snis;

    Stats stats{};
    auto  start_time = std::chrono::high_resolution_clock::now();

    // ---- Main processing loop -----------------------------------------------
    std::cout << "[Reader] Processing packets...\n";

    RawPacket raw;
    while (reader.readNextPacket(raw)) {
        ++stats.total_packets;
        stats.total_bytes += raw.header.incl_len;

        // Parse packet
        ParsedPacket parsed;
        bool ok = PacketParser::parse(raw, parsed);
        if (!ok || !parsed.is_valid || !parsed.has_ipv4) {
            // Can't parse -- forward unknown packets
            writer.writePacket(raw);
            ++stats.forwarded;
            continue;
        }

        if (parsed.has_tcp) ++stats.tcp_packets;
        if (parsed.has_udp) ++stats.udp_packets;

        // Build 5-tuple and look up/create flow
        FiveTuple tuple = PacketParser::makeFiveTuple(parsed);

        // Get or create flow
        Flow& flow = flows[tuple];
        if (flow.packet_count == 0) {
            // New flow -- initialize
            flow.src_ip = parsed.src_ip;
            flow.dst_ip = parsed.dst_ip;
            // Port-based initial classification
            if (parsed.dst_port == PORT_HTTPS || parsed.src_port == PORT_HTTPS) {
                flow.app_type = AppType::HTTPS;
            } else if (parsed.dst_port == PORT_HTTP || parsed.src_port == PORT_HTTP ||
                       parsed.dst_port == PORT_HTTP_ALT) {
                flow.app_type = AppType::HTTP;
            } else if (parsed.dst_port == PORT_DNS || parsed.src_port == PORT_DNS) {
                flow.app_type = AppType::DNS;
            }
        }

        ++flow.packet_count;
        flow.byte_count += raw.header.incl_len;

        // DPI: extract SNI/Host/DNS (only until we've classified the flow)
        if (!flow.classified && parsed.payload && parsed.payload_len > 0) {
            auto hostname = SNIExtractor::extractAny(
                parsed.payload, parsed.payload_len,
                parsed.dst_port, parsed.src_port);

            if (hostname) {
                flow.sni        = *hostname;
                flow.app_type   = sniToAppType(*hostname);
                flow.classified = true;

                // Track extraction method for stats
                if (parsed.dst_port == PORT_HTTPS || parsed.src_port == PORT_HTTPS) {
                    ++stats.sni_extracted;
                } else if (parsed.dst_port == PORT_DNS || parsed.src_port == PORT_DNS) {
                    ++stats.dns_extracted;
                } else {
                    ++stats.http_extracted;
                }

                detected_snis[*hostname] = flow.app_type;

                // Evaluate rules now that we know the app
                flow.blocked   = rules.isBlocked(tuple.src_ip, flow.app_type, *hostname);
                flow.throttled = rules.isThrottled(flow.app_type);
            } else if (!flow.classified) {
                // Check IP-only rule even without SNI
                flow.blocked = rules.isBlocked(tuple.src_ip, flow.app_type, "");
            }
        } else if (!flow.classified) {
            // Subsequent packets of unclassified flow -- re-check IP rule
            flow.blocked = rules.isBlocked(tuple.src_ip, AppType::UNKNOWN, "");
        }

        // Track per-app packet counts
        ++app_pkt_counts[flow.app_type];

        // Forward or drop
        if (flow.blocked) {
            ++stats.dropped;
        } else {
            if (flow.throttled) {
                ++stats.throttled_pkts;
                std::this_thread::sleep_for(rules.throttleDelay());
            }
            writer.writePacket(raw);
            ++stats.forwarded;
        }

        // Live stats every 10K packets
        if (live_stats && stats.total_packets % 10000 == 0) {
            auto now = std::chrono::high_resolution_clock::now();
            double elapsed = std::chrono::duration<double>(now - start_time).count();
            double kpps = (stats.total_packets / 1000.0) / elapsed;
            std::cout << "\r[Stats] " << stats.total_packets << " pkts | "
                      << std::fixed << std::setprecision(1) << kpps << " Kpps | "
                      << "Fwd: " << stats.forwarded << " Drop: " << stats.dropped
                      << "   " << std::flush;
        }
    }

    if (live_stats) std::cout << "\n";

    auto end_time = std::chrono::high_resolution_clock::now();
    double elapsed_sec = std::chrono::duration<double>(end_time - start_time).count();
    double kpps = elapsed_sec > 0 ? (stats.total_packets / 1000.0) / elapsed_sec : 0;

    // Count flows per app
    for (const auto& kv : flows) {
        ++app_flow_counts[kv.second.app_type];
    }

    std::cout << "[Reader] Done. Read " << stats.total_packets << " packets in "
              << std::fixed << std::setprecision(2) << elapsed_sec << "s ("
              << std::setprecision(1) << kpps << " Kpps)\n\n";

    // ---- Print report -------------------------------------------------------
    printBox("                   PROCESSING REPORT                    ");
    printRow("Total Packets",   std::to_string(stats.total_packets));
    printRow("Total Bytes",     std::to_string(stats.total_bytes));
    printRow("TCP Packets",     std::to_string(stats.tcp_packets));
    printRow("UDP Packets",     std::to_string(stats.udp_packets));
    printRow("Active Flows",    std::to_string(flows.size()));
    printSep();
    printRow("Forwarded",       std::to_string(stats.forwarded));
    printRow("Dropped",         std::to_string(stats.dropped));
    printRow("Throttled",       std::to_string(stats.throttled_pkts));
    printSep();
    printRow("SNI Extracted",   std::to_string(stats.sni_extracted) + " (TLS)");
    printRow("Host Extracted",  std::to_string(stats.http_extracted) + " (HTTP)");
    printRow("DNS Extracted",   std::to_string(stats.dns_extracted) + " (DNS)");
    printSep();

    // Application breakdown
    std::cout << "|" << std::string(62, ' ') << "|\n";
    printRow("APPLICATION BREAKDOWN", "");
    std::cout << "|" << std::string(62, ' ') << "|\n";

    // Sort by packet count descending
    std::vector<std::pair<AppType, uint64_t>> sorted_apps(
        app_pkt_counts.begin(), app_pkt_counts.end());
    std::sort(sorted_apps.begin(), sorted_apps.end(),
              [](const auto& a, const auto& b) { return a.second > b.second; });

    for (const auto& kv : sorted_apps) {
        AppType app   = kv.first;
        uint64_t cnt  = kv.second;
        double   pct  = stats.total_packets > 0
                        ? (cnt * 100.0 / stats.total_packets) : 0.0;
        bool     blocked = rules.blockedApps().count(app) > 0;

        std::ostringstream label, value;
        label << std::left << std::setw(16) << appTypeToString(app)
              << std::right << std::setw(6) << cnt
              << " " << std::setw(5) << std::fixed << std::setprecision(1) << pct << "%";

        // Mini bar
        std::ostringstream bar;
        int bar_fill = static_cast<int>(pct / 5);  // 5% per #
        bar << " " << std::string(std::min(bar_fill, 20), '#');
        if (blocked) bar << " (BLOCKED)";

        printRow(label.str(), bar.str());
    }

    printSep();

    // Detected SNIs
    if (!detected_snis.empty()) {
        std::cout << "|" << std::string(62, ' ') << "|\n";
        printRow("DETECTED DOMAINS / SNIs", "");
        std::cout << "|" << std::string(62, ' ') << "|\n";

        for (const auto& kv : detected_snis) {
            bool blocked = rules.isBlocked(0, kv.second, kv.first);
            std::string label = "  " + kv.first;
            std::string val   = "-> " + appTypeToString(kv.second) +
                                (blocked ? " [BLOCKED]" : "");
            // Truncate long SNIs
            if (label.size() > 40) label = label.substr(0, 38) + "..";
            printRow(label, val);
        }
    }

    printClose();

    // Throughput summary
    std::cout << "\n[Throughput] " << std::fixed << std::setprecision(1)
              << kpps << " Kpps  |  "
              << (stats.total_bytes / 1024.0 / 1024.0 / elapsed_sec)
              << " MB/s  |  Elapsed: "
              << elapsed_sec << "s\n";

    std::cout << "[Output] Wrote " << writer.packetsWritten()
              << " packets to " << output_file << "\n\n";

    return 0;
}
