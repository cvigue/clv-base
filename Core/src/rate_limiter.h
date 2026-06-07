// Copyright (c) 2023- Charlie Vigue. All rights reserved.


#ifndef CLV_CORE_RATE_LIMITER_H
#define CLV_CORE_RATE_LIMITER_H

#include <chrono>
#include <cstdint>

namespace clv {

/**
 * @brief Lightweight rate limiter for log messages (single-threaded).
 *
 * Tracks a timestamp; Due() returns true at most once per interval.
 * Designed for hot-path warning suppression (e.g., anti-replay "too old").
 *
 * @tparam Clock  Clock type (defaults to steady_clock; override for testing).
 */
template <typename Clock = std::chrono::steady_clock>
struct RateLimiter
{
    RateLimiter(std::chrono::seconds interval = std::chrono::seconds{1}) : log_interval_(interval)
    {
    }

    bool Due(typename Clock::time_point now = Clock::now()) noexcept
    {
        return DueImpl(now, log_interval_);
    }

    bool Due(typename Clock::time_point now,
             std::chrono::seconds interval) noexcept
    {
        return DueImpl(now, interval);
    }

    bool Due(std::chrono::seconds interval) noexcept
    {
        return DueImpl(Clock::now(), interval);
    }

    std::int64_t SuppressedCount() noexcept
    {
        auto result = suppressed_count_;
        suppressed_count_ = 0;
        return result;
    }

  private:
    bool DueImpl(typename Clock::time_point now,
                 std::chrono::seconds interval) noexcept
    {
        if (now - last_log_time_ >= interval)
        {
            last_log_time_ = now;
            return true;
        }
        ++suppressed_count_;
        return false;
    }

  private:
    std::chrono::seconds log_interval_{1};
    typename Clock::time_point last_log_time_{};
    std::uint64_t suppressed_count_{0};
};

} // namespace clv

#endif // CLV_CORE_RATE_LIMITER_H
