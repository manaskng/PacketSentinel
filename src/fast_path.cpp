// =============================================================================
// fast_path.cpp — Fast Path DPI worker thread implementation
// =============================================================================

#include "fast_path.h"
#include "packet_parser.h"
#include <thread>
#include <chrono>
#include <iostream>

FastPath::FastPath(int id, const RuleManager& rules,
                   TSQueue<Packet>* output_queue, size_t queue_cap)
    : id_(id)
    , rules_(rules)
    , output_queue_(output_queue)
    , input_queue_(queue_cap)
{
    flows_.reserve(1024);  // Pre-allocate for performance
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
    // Retrieve or create the flow for this 5-tuple
    // KEY INSIGHT: This is the only unordered_map access, and it's
    // lock-free because this FP EXCLUSIVELY owns flows_
    Flow& flow = flows_[pkt.tuple];

    if (flow.packet_count == 0) {
        // New flow — initialize with port-based hint
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
        // Not yet classified — check IP rule only
        if (rules_.isBlocked(pkt.tuple.src_ip, AppType::UNKNOWN, "")) {
            flow.blocked = true;
            ++dropped_;
            return;
        }
    } else {
        // Fully classified — check all rules
        if (rules_.isBlocked(pkt.tuple.src_ip, flow.app_type, flow.sni)) {
            flow.blocked = true;
            ++dropped_;
            return;
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
