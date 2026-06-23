#pragma once
// =============================================================================
// load_balancer.h — Load Balancer thread for the DPI pipeline
// =============================================================================
// Sits between the Reader and FastPath threads.
// Pops packets from its input queue, hashes the 5-tuple to select a
// FastPath, and pushes to that FP's input queue.
//
// INTERVIEW TALKING POINT:
//   "Why consistent hashing? Because all packets of one connection must go
//    to the same FastPath thread to avoid race conditions on the flow state.
//    Two FPs each seeing half the packets of a connection would each have
//    an incomplete view — they might not see the Client Hello and therefore
//    never extract the SNI."
// =============================================================================

#ifndef DPI_LOAD_BALANCER_H
#define DPI_LOAD_BALANCER_H

#include "types.h"
#include "thread_safe_queue.h"
#include <vector>
#include <thread>
#include <atomic>
#include <memory>
#include <functional>

// Forward declaration
class FastPath;

class LoadBalancer {
public:
    // id:       index of this LB (0..N_LB-1)
    // fps:      pointers to FastPath instances this LB feeds
    LoadBalancer(int id, std::vector<FastPath*> fps, size_t queue_capacity = 1024);

    ~LoadBalancer();

    // Non-copyable
    LoadBalancer(const LoadBalancer&)            = delete;
    LoadBalancer& operator=(const LoadBalancer&) = delete;

    // Get this LB's input queue (Reader pushes packets here)
    TSQueue<Packet>& inputQueue() { return input_queue_; }

    // Start the LB thread
    void start();

    // Signal stop and join the thread
    void stop();

    // Stats
    uint64_t totalDispatched() const { return total_dispatched_.load(); }
    uint64_t dispatchedToFP(int fp_idx) const;

    int id() const { return id_; }

private:
    void run();   // Thread function

    int                      id_;
    std::vector<FastPath*>   fps_;          // downstream FastPaths
    TSQueue<Packet>          input_queue_;

    std::thread              thread_;
    std::atomic<bool>        running_{false};
    std::atomic<uint64_t>    total_dispatched_{0};
    std::vector<std::atomic<uint64_t>> dispatched_per_fp_;
};

#endif // DPI_LOAD_BALANCER_H
