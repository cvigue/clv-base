// Copyright (c) 2023- Charlie Vigue. All rights reserved.

#include <bits/chrono.h>
#include <gtest/gtest.h>

#include "util/reactor_timer.h"

#include <asio/io_context.hpp>

#include <chrono>

using clv::netcore::ReactorTimer;
using namespace std::chrono_literals;

namespace {

void PumpUntil(asio::io_context &io, auto &&pred, std::chrono::milliseconds budget = 500ms)
{
    const auto deadline = std::chrono::steady_clock::now() + budget;
    while (!pred() && std::chrono::steady_clock::now() < deadline)
    {
        io.run_for(5ms);
        if (io.stopped())
            io.restart();
    }
}

} // namespace

TEST(ReactorTimerTest, Periodic_FiresMultipleTimes)
{
    asio::io_context io;
    ReactorTimer timer(io.get_executor());
    int ticks = 0;
    timer.start_periodic(20ms, [&]
    { ++ticks; });

    PumpUntil(io, [&]
    { return ticks >= 3; });
    timer.cancel();
    EXPECT_GE(ticks, 3);
}

TEST(ReactorTimerTest, Cancel_StopsFurtherTicks)
{
    asio::io_context io;
    ReactorTimer timer(io.get_executor());
    int ticks = 0;
    timer.start_periodic(15ms, [&]
    { ++ticks; });

    PumpUntil(io, [&]
    { return ticks >= 1; });
    timer.cancel();
    const int after_cancel = ticks;
    io.run_for(60ms);
    EXPECT_EQ(ticks, after_cancel);
    EXPECT_FALSE(timer.armed());
}

TEST(ReactorTimerTest, EnabledPredicate_SkipsTickAndReschedule)
{
    asio::io_context io;
    ReactorTimer timer(io.get_executor());
    bool enabled = true;
    int ticks = 0;
    timer.set_enabled([&]
    { return enabled; });
    timer.start_periodic(15ms, [&]
    { ++ticks; });

    PumpUntil(io, [&]
    { return ticks >= 1; });
    enabled = false;
    const int frozen = ticks;
    io.run_for(80ms);
    EXPECT_EQ(ticks, frozen);
}

TEST(ReactorTimerTest, TryArm_DebouncesWhileArmed)
{
    asio::io_context io;
    ReactorTimer timer(io.get_executor());
    int fires = 0;

    EXPECT_TRUE(timer.try_arm(30ms, [&]
    { ++fires; }));
    EXPECT_TRUE(timer.armed());
    EXPECT_FALSE(timer.try_arm(30ms, [&]
    { ++fires; }));

    PumpUntil(io, [&]
    { return fires >= 1; });
    EXPECT_EQ(fires, 1);
    EXPECT_FALSE(timer.armed());

    EXPECT_TRUE(timer.try_arm(20ms, [&]
    { ++fires; }));
    PumpUntil(io, [&]
    { return fires >= 2; });
    EXPECT_EQ(fires, 2);
}

TEST(ReactorTimerTest, SetInterval_AppliesToNextWait)
{
    asio::io_context io;
    ReactorTimer timer(io.get_executor());
    int ticks = 0;
    timer.start_periodic(100ms, [&]
    { ++ticks; });
    timer.set_interval(15ms);

    PumpUntil(io, [&]
    { return ticks >= 2; },
              200ms);
    timer.cancel();
    EXPECT_GE(ticks, 2);
}

TEST(ReactorTimerTest, Destructor_CancelsOutstandingWait)
{
    asio::io_context io;
    int ticks = 0;
    {
        ReactorTimer timer(io.get_executor());
        timer.start_periodic(50ms, [&]
        { ++ticks; });
        EXPECT_TRUE(timer.armed());
    }
    io.run_for(100ms);
    EXPECT_EQ(ticks, 0);
}
