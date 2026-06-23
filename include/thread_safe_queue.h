#pragma once
// =============================================================================
// thread_safe_queue.h — Bounded, thread-safe producer-consumer queue
// =============================================================================
// Header-only template. Uses:
//   - std::mutex      for mutual exclusion
//   - std::condition_variable for efficient blocking (no busy-wait!)
//
// INTERVIEW TALKING POINT:
//   "Why condition_variable over a spin-loop (busy-wait)?
//    Spin-loops burn CPU cycles on an empty queue. condition_variable puts
//    the thread to sleep and wakes it only when new data arrives, allowing
//    the OS to schedule other work. This matters at scale."
//
// Poison Pill Shutdown Pattern:
//   Producer calls pushPoison() when done. Consumer checks isPoison() on
//   each item. Poison is propagated downstream so all threads drain cleanly.
// =============================================================================

#ifndef DPI_THREAD_SAFE_QUEUE_H
#define DPI_THREAD_SAFE_QUEUE_H

#include <queue>
#include <mutex>
#include <condition_variable>
#include <optional>
#include <atomic>
#include <chrono>

template<typename T>
class TSQueue {
public:
    // Construct with capacity limit (backpressure: push blocks when full)
    explicit TSQueue(size_t capacity = 1024)
        : capacity_(capacity), poison_count_(0) {}

    // Non-copyable, non-movable (owns mutex/cv)
    TSQueue(const TSQueue&)            = delete;
    TSQueue& operator=(const TSQueue&) = delete;

    // ---- Blocking push (blocks if full) -------------------------------------
    // Adds item to the queue. Blocks indefinitely if at capacity.
    // Returns false only if the queue has been permanently closed.
    bool push(T item) {
        std::unique_lock<std::mutex> lock(mutex_);
        not_full_.wait(lock, [this] {
            return queue_.size() < capacity_ || closed_;
        });
        if (closed_) return false;
        queue_.push(std::move(item));
        lock.unlock();
        not_empty_.notify_one();
        return true;
    }

    // ---- Non-blocking push --------------------------------------------------
    // Returns true if item was added, false if queue is full or closed.
    bool try_push(T item) {
        std::unique_lock<std::mutex> lock(mutex_);
        if (queue_.size() >= capacity_ || closed_) return false;
        queue_.push(std::move(item));
        lock.unlock();
        not_empty_.notify_one();
        return true;
    }

    // ---- Blocking pop (blocks until item available) -------------------------
    // Returns nullopt if the queue is closed and empty.
    std::optional<T> pop() {
        std::unique_lock<std::mutex> lock(mutex_);
        not_empty_.wait(lock, [this] {
            return !queue_.empty() || closed_;
        });
        if (queue_.empty()) return std::nullopt;  // closed and empty
        T item = std::move(queue_.front());
        queue_.pop();
        lock.unlock();
        not_full_.notify_one();
        return item;
    }

    // ---- Non-blocking pop ---------------------------------------------------
    bool try_pop(T& out) {
        std::unique_lock<std::mutex> lock(mutex_);
        if (queue_.empty()) return false;
        out = std::move(queue_.front());
        queue_.pop();
        lock.unlock();
        not_full_.notify_one();
        return true;
    }

    // ---- Timed pop (returns nullopt on timeout) ------------------------------
    std::optional<T> pop_for(std::chrono::milliseconds timeout) {
        std::unique_lock<std::mutex> lock(mutex_);
        if (!not_empty_.wait_for(lock, timeout, [this] {
                return !queue_.empty() || closed_;
            })) {
            return std::nullopt;  // timeout
        }
        if (queue_.empty()) return std::nullopt;
        T item = std::move(queue_.front());
        queue_.pop();
        lock.unlock();
        not_full_.notify_one();
        return item;
    }

    // ---- Poison pill pattern ------------------------------------------------
    // Call close() when the producer is done. Consumers will see nullopt
    // from pop() once the queue is drained.
    void close() {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            closed_ = true;
        }
        // Wake ALL waiting consumers so they can exit
        not_empty_.notify_all();
        not_full_.notify_all();
    }

    bool isClosed() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return closed_ && queue_.empty();
    }

    // ---- Stats --------------------------------------------------------------
    size_t size() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return queue_.size();
    }

    size_t capacity() const { return capacity_; }

    bool empty() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return queue_.empty();
    }

private:
    mutable std::mutex      mutex_;
    std::condition_variable not_empty_;
    std::condition_variable not_full_;
    std::queue<T>           queue_;
    size_t                  capacity_;
    bool                    closed_ = false;
    std::atomic<int>        poison_count_;
};

#endif // DPI_THREAD_SAFE_QUEUE_H
