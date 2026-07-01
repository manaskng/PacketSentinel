// =============================================================================
// fast_path.cpp — Fast Path DPI worker thread implementation
// =============================================================================

#include "fast_path.h"
#include "packet_parser.h"
#include <thread>
#include <chrono>
#include <iostream>

FastPath::FastPath(int id, const RuleManager& rules,
                   TSQueue<Packet>* output_queue, size_t queue_cap,
                   size_t max_flows)
    : id_(id)
    , rules_(rules)
    , output_queue_(output_queue)
    , input_queue_(queue_cap)
    , flow_table_(max_flows)
{
}

FastPath::~FastPath() {
    stop();
}

void FastPath::start() {
    running_.store(true);
    thread_ = std::thread([this] { run(); });
}

void FastPath::stop() {
    input_queue_.close();
    if (thread_.joinable()) {
        thread_.join();
    }
    running_.store(false);
}

// ---------------------------------------------------------------------------
// run — the FastPath thread function (the hot path)
// ---------------------------------------------------------------------------
void FastPath::run() {
    while (true) {
        auto item = input_queue_.pop();
        if (!item) break;  // Queue closed and drained

        processPacket(*item);
        ++processed_;
    }
}

// ---------------------------------------------------------------------------
// processPacket — classify + rule check + route
// ---------------------------------------------------------------------------
void FastPath::processPacket(Packet& pkt) {
    // Retrieve or create the flow for this 5-tuple from LRU table
    // SECURITY FIX: LRU table enforces max_flows limit with eviction
    // This is lock-free because this FP EXCLUSIVELY owns flow_table_
    Flow& flow = flow_table_.getOrCreate(pkt.tuple);

    if (flow.packet_count == 0) {
        // New flow -- initialize with port-based hint
        flow.src_ip = pkt.tuple.src_ip;
        flow.dst_ip = pkt.tuple.dst_ip;
        flow.app_type = pkt.app_hint;
        // Check IP rule immediately (no SNI needed)
        if (rules_.isBlocked(pkt.tuple.src_ip, AppType::UNKNOWN, "")) {
            flow.blocked = true;
        }
    }

    ++flow.packet_count;
    flow.byte_count += pkt.data.size();

    // -- Anomaly feature extraction (minimal overhead) ---------------------

    // Welford's online variance for packet sizes (no vector allocation)
    {
        double size = static_cast<double>(pkt.data.size());
        double delta = size - flow.pkt_size_mean;
        flow.pkt_size_mean += delta / flow.packet_count;
        double delta2 = size - flow.pkt_size_mean;
        flow.pkt_size_m2 += delta * delta2;
    }

    // Track TCP flags from raw packet data
    if (pkt.tuple.protocol == PROTO_TCP && pkt.data.size() >= 14 + 20 + 14) {
        size_t ip_offset = 14;  // After Ethernet header
        uint8_t ihl = (pkt.data[ip_offset] & 0x0F) * 4;
        size_t tcp_offset = ip_offset + ihl;
        if (tcp_offset + 14 <= pkt.data.size()) {
            uint8_t flags = pkt.data[tcp_offset + 13];
            if (flagSYN(flags)) ++flow.syn_count;
            if (flagFIN(flags)) ++flow.fin_count;
            if (flagRST(flags)) ++flow.rst_count;
        }
    }

    // Update timestamps
    uint64_t ts_ms = (uint64_t)pkt.pcap_hdr.ts_sec * 1000 +
                     pkt.pcap_hdr.ts_usec / 1000;
    if (flow.first_seen_ms == 0) flow.first_seen_ms = ts_ms;
    flow.last_seen_ms = ts_ms;

    // Shannon entropy of current payload (overwritten each packet)
    if (pkt.payload && pkt.payload_len > 0) {
        flow.payload_entropy = FlowAnalyzer::shannonEntropy(
            pkt.payload, pkt.payload_len);
    }

    // -- End feature extraction --------------------------------------------

    // If flow is already classified and blocked, fast-drop
    if (flow.blocked) {
        ++dropped_;
        return;
    }

    // DPI classification (only until we've identified the app)
    if (!flow.classified && pkt.payload && pkt.payload_len > 0) {
        classifyFlow(pkt, flow);
    }

    // Rule check after classification
    if (!flow.classified) {
        // Not yet classified -- check IP rule only
        if (rules_.isBlocked(pkt.tuple.src_ip, AppType::UNKNOWN, "")) {
            flow.blocked = true;
            ++dropped_;
            return;
        }
    } else {
        // Fully classified -- check all rules
        if (rules_.isBlocked(pkt.tuple.src_ip, flow.app_type, flow.sni)) {
            flow.blocked = true;
            ++dropped_;
            return;
        }
    }

    // Anomaly scoring (amortized: run every 5 packets to limit overhead)
    if (flow.packet_count >= 5 && flow.packet_count % 5 == 0) {
        auto result = FlowAnalyzer::score(flow);
        flow.anomaly_score = result.score;
        flow.anomaly_type  = result.type;
        if (result.score >= FlowAnalyzer::FLAG_THRESHOLD) {
            ++anomalies_;
        }
    }

    // Throttle mode: delay packet before forwarding
    if (flow.throttled || rules_.isThrottled(flow.app_type)) {
        flow.throttled = true;
        std::this_thread::sleep_for(rules_.throttleDelay());
    }

    // Forward: push to output queue
    output_queue_->push(std::move(pkt));
    ++forwarded_;
}

// ---------------------------------------------------------------------------
// classifyFlow — extract SNI/Host/DNS and update flow state
// ---------------------------------------------------------------------------
void FastPath::classifyFlow(const Packet& pkt, Flow& flow) {
    auto hostname = SNIExtractor::extractAny(
        pkt.payload, pkt.payload_len,
        pkt.tuple.dst_port, pkt.tuple.src_port);

    if (hostname) {
        flow.sni        = *hostname;
        flow.app_type   = sniToAppType(*hostname);
        flow.classified = true;
        flow.throttled  = rules_.isThrottled(flow.app_type);
        ++classified_;
    }
}
