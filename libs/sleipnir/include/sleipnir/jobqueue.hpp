// Thread-safe MPMC job queue with a graceful shutdown flag.
#pragma once

#include <condition_variable>
#include <mutex>
#include <optional>
#include <queue>

namespace sln {

template <typename T>
class JobQueue {
public:
    void push(T item) {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            queue_.push(std::move(item));
        }
        cv_.notify_one();
    }

    // Blocks until an item is available or close() is called with the queue
    // drained. Returns std::nullopt after close.
    std::optional<T> pop() {
        std::unique_lock<std::mutex> lock(mutex_);
        cv_.wait(lock, [this] { return !queue_.empty() || closed_; });
        if (queue_.empty()) return std::nullopt;
        T item = std::move(queue_.front());
        queue_.pop();
        if (queue_.empty()) cv_.notify_all();
        return item;
    }

    void close() {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            closed_ = true;
        }
        cv_.notify_all();
    }

    bool closed() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return closed_;
    }

    // Wait until the queue is closed and fully drained.
    void wait_drained() {
        std::unique_lock<std::mutex> lock(mutex_);
        drained_cv_.wait(lock, [this] { return closed_ && queue_.empty(); });
    }

private:
    mutable std::mutex mutex_;
    std::condition_variable cv_;
    std::condition_variable drained_cv_;
    std::queue<T> queue_;
    bool closed_ = false;
};

} // namespace sln
