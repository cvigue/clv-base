// Copyright (c) 2023- Charlie Vigue. All rights reserved.


#include "gtest/gtest.h"

#include <thread>

#include "timer.h"
#include "event.h"
#include "auto_thread.h"

using namespace clv;
using namespace std::literals;

using ThreadT = AutoThread<>;

TEST(EventTestSuite, create)
{
    Event e;
}

TEST(EventTestSuite, wait)
{
    const auto delay = 20ms;
    Event e;
    Timer t;

    auto th = ThreadT([&]()
    { std::this_thread::sleep_for(delay); e.Notify(); });

    auto lock = e.Wait();
    EXPECT_GE(t.Elapsed<std::chrono::milliseconds>(), delay);
    EXPECT_TRUE(lock.owns_lock());
}

TEST(EventTestSuite, wait_for)
{
    const auto delay = 50ms;
    const auto wait_limit = 20ms;
    Event e;
    Timer t;

    auto th = ThreadT([&]()
    { std::this_thread::sleep_for(delay); e.Notify(); });

    auto lock = e.WaitFor(wait_limit);
    EXPECT_GE(t.Elapsed<std::chrono::milliseconds>(), wait_limit);
    EXPECT_FALSE(lock.owns_lock());
}

TEST(EventTestSuite, wait_pred)
{
    const auto delay = 20ms;
    Event e;
    Timer t;
    auto done = false;

    auto th = ThreadT([&]()
    {
                             {
                              std::this_thread::sleep_for(5ms);
                              auto pl = std::unique_lock(e.GetMutex());
                              std::this_thread::sleep_for(delay - 5ms);
                             }
                             done = true;
                             e.Notify(); });

    auto lock = e.Wait([&]()
    { return done; });

#ifdef _WIN32
    auto delay_window = 50ms;
#else
    auto delay_window = 5ms;
#endif

    EXPECT_LE(t.Elapsed<std::chrono::milliseconds>(), delay + delay_window);
    EXPECT_TRUE(lock.owns_lock());
}

TEST(EventTestSuite, wait_for_pred_false)
{
    const auto delay = 40ms;
    const auto wait_limit = 20ms;
    Event e;
    Timer t;
    auto done = false;

    auto th = ThreadT([&]()
    {
                             std::this_thread::sleep_for(delay);
                             e.Notify(); });

    auto lock = e.WaitFor(wait_limit, [&]()
    { return done; });

    auto elapsed = t.Elapsed<std::chrono::milliseconds>();

#ifdef _WIN32
    auto delay_window = 50ms;
#else
    auto delay_window = 5ms;
#endif

    EXPECT_LE(elapsed, wait_limit + delay_window);
    EXPECT_FALSE(lock.owns_lock());
}

TEST(EventTestSuite, wait_for_pred_true)
{
    const auto delay = 40ms;
    const auto wait_limit = 20ms;
    Event e;
    Timer t;
    auto done = false;

    auto th = ThreadT([&]()
    {
                             std::this_thread::sleep_for(wait_limit/2);
                             done = true;
                             std::this_thread::sleep_for(delay);
                             e.Notify(); });

    auto lock = e.WaitFor(wait_limit, [&]()
    { return done; });

    auto elapsed = t.Elapsed<std::chrono::milliseconds>();

#ifdef _WIN32
    auto delay_window = 50ms;
#else
    auto delay_window = 5ms;
#endif

    EXPECT_LE(elapsed, wait_limit + delay_window);
    EXPECT_TRUE(lock.owns_lock());
}

TEST(EventTestSuite, unique_lock)
{
    Event e;
    std::unique_lock l{e.GetMutex()}; // Compilation is success
}

TEST(EventTestSuite, lock)
{
    Event e1;
    Event e2;
    std::lock(e1.GetMutex(), e2.GetMutex()); // Compilation is success
}

TEST(EventTestSuite, member_fn_lock)
{
    Event e1;
    auto eLock = e1.Lock<std::unique_lock<std::mutex>>();
    EXPECT_TRUE(eLock.owns_lock());
}
