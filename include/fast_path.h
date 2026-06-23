#pragma once
// =============================================================================
// fast_path.h — Fast Path (DPI worker) thread
// =============================================================================
// Each FastPath thread:
//   1. Pops packets from its input queue
//   2. Looks up (or creates) the flow in its PRIVATE flow table
//   3. Runs SNI/HTTP/DNS extraction to classify the flow
//   4. Checks rules — blocks or forwards
//   5. Pushes allowed packets to the shared output queue
//
// KEY DESIGN: Each FP owns its flow table exclusively.
// No locking on the hot path. The consistent hashing guarantee from LB
// ensures that all packets of one flow always arrive at the same FP.
//
// INTERVIEW TALKING POINT:
//   "Per-thread flow tables eliminate ALL locking on the classification
//    hot path. A shared flow table would require a read-write lock on
//    every lookup, adding contention that grows with thread count and
//    negates the benefit of parallelism."
// =============================================================================

#ifndef DPI_FAST_PATH_H
#define DPI_FAST_PATH_H

#include "types.h"
#include "thread_safe_queue.h"
#include "rule_manager.h"
#include "sni_extractor.h"
#include <unordered_map>
#include <thread>
#include <atomic>
#include <memory>

class FastPath {
public:
    // id:            index of this FP (globally unique)
    // rules:         shared read-only rule engine
    // output_queue:  shared output queue (written to PCAP by writer thread)
    // queue_cap:     input queue capacity
    FastPath(int id,
             const RuleManager& rules,
             TSQueue<Packet>*   output_queue,
             size_t             queue_cap = 1024);

    ~FastPath();

    FastPath(const FastPath&)            = delete;
    FastPath& operator=(const FastPath&) = delete;

    // Get this FP's input queue (LB pushes packets here)
    TSQueue<Packet>& inputQueue() { return input_queue_; }

    // Start and stop
    void start();
    void stop();

    // Stats (atomic — safe to read from main thread while FP runs)
    uint64_t processed()  const { return processed_.load();  }
    uint64_t forwarded()  const { return forwarded_.load();  }
    uint64_t dropped()    const { return dropped_.load();    }
    uint64_t classified() const { return classified_.load(); }

    int id() const { return id_; }

    // Flow table access (only safe after stop() is called)
    const std::unordered_map<FiveTuple, Flow>& flowTable() const {
        return flows_;
    }

private:
    void run();  // Thread function

    // Process one packet: classify + rule check + forward/drop
    void processPacket(Packet& pkt);

    // Classify a packet (update the flow with SNI/app type)
    void classifyFlow(const Packet& pkt, Flow& flow);

    int                 id_;
    const RuleManager&  rules_;
    TSQueue<Packet>*    output_queue_;    // shared (not owned)
    TSQueue<Packet>     input_queue_;

    // Per-FP flow table — NO LOCKS NEEDED (exclusive ownership)
    std::unordered_map<FiveTuple, Flow> flows_;

    std::thread          thread_;
    std::atomic<bool>    running_{false};

    // Per-FP counters
    std::atomic<uint64_t> processed_{0};
    std::atomic<uint64_t> forwarded_{0};
    std::atomic<uint64_t> dropped_{0};
    std::atomic<uint64_t> classified_{0};
};

#endif // DPI_FAST_PATH_H
