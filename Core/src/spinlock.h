// Copyright (c) 2023- Charlie Vigue. All rights reserved.


#ifndef CLVLIB_CORE_SPINLOCK_H
#define CLVLIB_CORE_SPINLOCK_H
#include <atomic>
#include <thread>

namespace clv {

/**
 * @brief User space spinlock
 * @note Shamelesly derived from https://rigtorp.se/spinlock/
 * @note Use a spinlock if the waits will be infrequent, brief, and trips to the kernel are
 *       excessively costly.
 * @details a simple implementation of a spinlock, which is a synchronization mechanism used
 *          in concurrent programming to ensure that only one thread can access a shared
 *          resource at a time.
 *
 * The spinlock struct has three member functions:
 *
 * lock(): This function is used to acquire the lock. It takes no input. If the lock is available,
 * it sets the internal lock_ flag to true using an atomic operation (exchange) and returns. If
 * the lock is already held by another thread, it enters a loop where it continuously checks the
 * lock_ flag using a relaxed load (load(std::memory_order_relaxed)), which is more efficient than
 * an acquire load. If the lock is still held, it calls std::this_thread::yield() to allow other
 * threads to run, avoiding busy waiting and reducing CPU usage.
 *
 * try_lock(): This function attempts to acquire the lock without blocking. It takes no input and
 * returns a boolean value indicating whether the lock was successfully acquired or not. It first
 * checks if the lock_ flag is false using a relaxed load (load(std::memory_order_relaxed)). If the
 * lock is free, it tries to set the lock_ flag to true using an atomic operation (exchange) with
 * acquire semantics. If both operations succeed, it returns true, indicating that the lock was
 * acquired. Otherwise, it returns false.
 *
 * unlock(): This function is used to release the lock. It takes no input and simply sets the internal
 * lock_ flag to false using an atomic store operation (store(false, std::memory_order_release)).
 *
 * The spinlock struct uses an std::atomic<bool> variable lock_ to represent the lock state. The
 * initial value of lock_ is false, indicating that the lock is initially available.
 *
 * The purpose of the spinlock is to provide a simple and efficient way to ensure mutual exclusion in
 * a multi-threaded environment. When a thread needs to access a shared resource, it calls lock() to
 * acquire the lock. If the lock is already held by another thread, the calling thread spins (waits)
 * until the lock is released. Once the thread has finished accessing the shared resource, it calls
 * unlock() to release the lock, allowing other threads to acquire it.
 */
struct spinlock
{
    void lock() noexcept
    {
        for (;;)
        {
            // Optimistically assume the lock is free on the first try
            if (!lock_.exchange(true, std::memory_order_acquire))
                return;

            // Wait for lock to be released without generating cache misses
            while (lock_.load(std::memory_order_relaxed))
                std::this_thread::yield();
        }
    }

    bool try_lock() noexcept
    {
        // First do a relaxed load to check if lock is free in order to prevent
        // unnecessary cache misses if someone does while(!try_lock())
        return !lock_.load(std::memory_order_relaxed) && !lock_.exchange(true, std::memory_order_acquire);
    }

    void unlock() noexcept
    {
        lock_.store(false, std::memory_order_release);
    }

  private:
    std::atomic<bool> lock_ = {0};
};


} // namespace clv


#endif // CLVLIB_CORE_SPINLOCK_H
