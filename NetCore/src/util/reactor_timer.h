// Copyright (c) 2023- Charlie Vigue. All rights reserved.

#ifndef CLV_NETCORE_REACTOR_TIMER_H
#define CLV_NETCORE_REACTOR_TIMER_H

#include <asio/any_io_executor.hpp>
#include <asio/error.hpp>
#include <asio/steady_timer.hpp>

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <utility>

namespace clv::netcore {

/**
 * @brief Asio reactor timer for periodic ticks and debounced one-shots.
 *
 * Owns an @c asio::steady_timer. Outstanding waits are cancelled on @c cancel()
 * and from the destructor. Handlers are ignored when cancelled or when the
 * optional enable predicate returns false.
 *
 * Threading: all methods and callbacks run on the timer's executor (typically
 * a single-threaded @c io_context reactor). Not internally synchronized.
 */
class ReactorTimer
{
  public:
    using duration = std::chrono::steady_clock::duration;
    using clock = std::chrono::steady_clock;

    explicit ReactorTimer(asio::any_io_executor ex) : state_(std::make_shared<State>(std::move(ex)))
    {
    }

    ReactorTimer(const ReactorTimer &) = delete;
    ReactorTimer &operator=(const ReactorTimer &) = delete;

    ReactorTimer(ReactorTimer &&) noexcept = default;
    ReactorTimer &operator=(ReactorTimer &&) noexcept = default;

    ~ReactorTimer()
    {
        cancel();
    }

    /// @brief Gate for firing handlers. Empty predicate means always enabled.
    void set_enabled(std::function<bool()> pred)
    {
        if (!state_)
            return;
        state_->enabled = std::move(pred);
    }

    /// @brief Interval used by @c start_periodic. If already periodic and armed, re-arms.
    void set_interval(duration interval)
    {
        if (!state_ || interval <= duration::zero())
            return;
        state_->interval = interval;
        if (state_->mode == Mode::Periodic && state_->armed)
            arm_wait(state_);
    }

    [[nodiscard]] duration interval() const noexcept
    {
        return state_ ? state_->interval : duration::zero();
    }

    /**
     * @brief Start (or restart) a recurring timer.
     *
     * Cancels any prior wait. After each successful tick, reschedules using the
     * current interval unless cancelled or disabled.
     */
    template <typename F>
    void start_periodic(duration interval, F &&on_tick)
    {
        if (!state_ || interval <= duration::zero())
            return;
        state_->mode = Mode::Periodic;
        state_->interval = interval;
        state_->tick = std::function<void()>(std::forward<F>(on_tick));
        arm_wait(state_);
    }

    /**
     * @brief Arm a one-shot wait if not already armed.
     * @return @c false when a wait is already outstanding (debounce).
     */
    template <typename F>
    [[nodiscard]] bool try_arm(duration delay, F &&on_fire)
    {
        if (!state_ || delay <= duration::zero())
            return false;
        if (state_->armed)
            return false;
        state_->mode = Mode::OneShot;
        state_->interval = delay;
        state_->tick = std::function<void()>(std::forward<F>(on_fire));
        arm_wait(state_);
        return true;
    }

    /// @brief Cancel any outstanding wait; subsequent handlers no-op.
    void cancel()
    {
        if (!state_)
            return;
        state_->mode = Mode::Idle;
        state_->armed = false;
        state_->tick = {};
        state_->timer.cancel();
    }

    [[nodiscard]] bool armed() const noexcept
    {
        return state_ && state_->armed;
    }

  private:
    enum class Mode : std::uint8_t
    {
        Idle,
        Periodic,
        OneShot,
    };

    struct State
    {
        explicit State(asio::any_io_executor ex) : timer(std::move(ex))
        {
        }

        asio::steady_timer timer;
        std::function<bool()> enabled;
        std::function<void()> tick;
        duration interval{duration::zero()};
        Mode mode{Mode::Idle};
        bool armed{false};
    };

    static bool is_enabled(const State &state)
    {
        return !state.enabled || state.enabled();
    }

    static void arm_wait(const std::shared_ptr<State> &state)
    {
        if (!state || state->mode == Mode::Idle || !state->tick)
            return;

        state->armed = true;
        state->timer.expires_after(state->interval);
        state->timer.async_wait([state](const asio::error_code &ec)
        {
            const bool was_periodic = state->mode == Mode::Periodic;
            state->armed = false;

            if (ec == asio::error::operation_aborted || state->mode == Mode::Idle)
                return;

            if (state->mode == Mode::OneShot)
                state->mode = Mode::Idle;

            if (!is_enabled(*state))
                return;

            if (state->tick)
                state->tick();

            // Reschedule only if still periodic and not cancelled during tick.
            if (was_periodic && state->mode == Mode::Periodic && state->tick && is_enabled(*state))
                arm_wait(state);
        });
    }

    std::shared_ptr<State> state_;
};

} // namespace clv::netcore

#endif // CLV_NETCORE_REACTOR_TIMER_H
