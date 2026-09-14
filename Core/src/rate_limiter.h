// Copyright (c) 2023- Charlie Vigue. All rights reserved.


#ifndef CLV_CORE_RATE_LIMITER_H
#define CLV_CORE_RATE_LIMITER_H

#include <chrono>
#include <cstdint>

namespace clv {

/**
 * @brief Lightweight single-threaded rate gate.
 *
 * Tracks a timestamp; Due() returns true at most once per interval. Used both
 * for hot-path log suppression (e.g., anti-replay "too old") and to throttle
 * real work (e.g., per-peer float catch-up).
 *
 * The interval is accepted as any @c std::chrono::duration and stored at the
 * clock's native tick resolution, so callers can gate at seconds, milliseconds,
 * or finer without picking a unit at the type level.
 *
 * @tparam Clock  Clock type (defaults to steady_clock; override for testing).
 */
template <typename Clock = std::chrono::steady_clock>
struct RateLimiter
{
    using Duration = typename Clock::duration;
    using TimePoint = typename Clock::time_point;

    RateLimiter() noexcept : interval_(std::chrono::duration_cast<Duration>(std::chrono::seconds{1}))
    {
    }

    template <typename Rep, typename Period>
    explicit RateLimiter(std::chrono::duration<Rep, Period> interval) noexcept
        : interval_(std::chrono::duration_cast<Duration>(interval))
    {
    }

    bool Due(TimePoint now = Clock::now()) noexcept
    {
        return DueImpl(now, interval_);
    }

    template <typename Rep, typename Period>
    bool Due(TimePoint now, std::chrono::duration<Rep, Period> interval) noexcept
    {
        return DueImpl(now, std::chrono::duration_cast<Duration>(interval));
    }

    template <typename Rep, typename Period>
    bool Due(std::chrono::duration<Rep, Period> interval) noexcept
    {
        return DueImpl(Clock::now(), std::chrono::duration_cast<Duration>(interval));
    }

    std::int64_t SuppressedCount() noexcept
    {
        auto result = suppressed_count_;
        suppressed_count_ = 0;
        return result;
    }

  private:
    bool DueImpl(TimePoint now, Duration interval) noexcept
    {
        if (now - last_time_ >= interval)
        {
            last_time_ = now;
            return true;
        }
        ++suppressed_count_;
        return false;
    }

  private:
    Duration interval_;
    TimePoint last_time_{};
    std::uint64_t suppressed_count_{0};
};

} // namespace clv

#endif // CLV_CORE_RATE_LIMITER_H
