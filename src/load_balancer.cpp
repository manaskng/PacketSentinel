// =============================================================================
// load_balancer.cpp — Load Balancer thread implementation
// =============================================================================

#include "load_balancer.h"
#include "fast_path.h"
#include <iostream>

LoadBalancer::LoadBalancer(int id, std::vector<FastPath*> fps, size_t queue_capacity)
    : id_(id)
    , fps_(std::move(fps))
    , input_queue_(queue_capacity)
    , dispatched_per_fp_(fps_.size())
{
    // Initialize per-FP counters to 0
    for (auto& counter : dispatched_per_fp_) {
        counter.store(0);
    }
}

LoadBalancer::~LoadBalancer() {
    stop();
}

void LoadBalancer::start() {
    running_.store(true);
    thread_ = std::thread([this] { run(); });
}

void LoadBalancer::stop() {
    // Signal the input queue to close — this unblocks any waiting pop()
    input_queue_.close();
    if (thread_.joinable()) {
        thread_.join();
    }
    running_.store(false);
}

uint64_t LoadBalancer::dispatchedToFP(int fp_idx) const {
    if (fp_idx < 0 || static_cast<size_t>(fp_idx) >= dispatched_per_fp_.size()) {
        return 0;
    }
    return dispatched_per_fp_[fp_idx].load();
}

// ---------------------------------------------------------------------------
// run — the Load Balancer thread function
// ---------------------------------------------------------------------------
void LoadBalancer::run() {
    const size_t num_fps = fps_.size();
    if (num_fps == 0) return;

    FiveTupleHash hasher;

    while (true) {
        // Block until a packet arrives (or queue is closed)
        auto item = input_queue_.pop();
        if (!item) break;  // Queue closed and empty — we're done

        Packet& pkt = *item;

        // Consistent hashing: hash(5-tuple) mod num_fps
        // CRITICAL: same 5-tuple → same FP every time
        size_t fp_idx = hasher(pkt.tuple) % num_fps;

        // Push to selected FastPath's queue (blocks if FP queue is full)
        fps_[fp_idx]->inputQueue().push(std::move(pkt));

        ++dispatched_per_fp_[fp_idx];
        ++total_dispatched_;
    }

    // Propagate shutdown: close all downstream FP queues
    for (FastPath* fp : fps_) {
        fp->inputQueue().close();
    }
}
