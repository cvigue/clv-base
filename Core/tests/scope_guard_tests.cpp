// Copyright (c) 2023- Charlie Vigue. All rights reserved.



#include <gtest/gtest.h>

#include "scope_guard.h"

using namespace clv;

TEST(ScopeGuardImpl, scope_exit_simple)
{
    int i = 0;
    EXPECT_EQ(i, 0);
    {
        auto sg = scope_exit([&i]()
        { ++i; });
    }
    EXPECT_EQ(i, 1);
}

TEST(ScopeGuardImpl, scope_exit_release)
{
    int i = 0;
    EXPECT_EQ(i, 0);
    {
        auto sg = scope_exit([&i]()
        { ++i; });
        sg.release();
    }
    EXPECT_EQ(i, 0);
}

TEST(ScopeGuardImpl, scope_fail_nofail)
{
    int i = 0;
    EXPECT_EQ(i, 0);
    {
        auto sg = scope_fail([&i]()
        { ++i; });
    }
    EXPECT_EQ(i, 0);
}

TEST(ScopeGuardImpl, scope_fail_fail)
{
    int i = 0;
    EXPECT_EQ(i, 0);
    try
    {
        auto sg = scope_fail([&i]()
        { ++i; });
        throw std::runtime_error("test");
    }
    catch (std::runtime_error &)
    {
    }
    EXPECT_EQ(i, 1);
}

TEST(ScopeGuardImpl, scope_success_nofail)
{
    int i = 0;
    EXPECT_EQ(i, 0);
    {
        auto sg = scope_success([&i]()
        { ++i; });
    }
    EXPECT_EQ(i, 1);
}

TEST(ScopeGuardImpl, scope_success_fail)
{
    int i = 0;
    EXPECT_EQ(i, 0);
    try
    {
        auto sg = scope_success([&i]()
        { ++i; });
        throw std::runtime_error("test");
    }
    catch (std::runtime_error &)
    {
    }
    EXPECT_EQ(i, 0);
}

// Test move semantics
TEST(ScopeGuardImpl, scope_exit_move_constructor)
{
    int i = 0;
    {
        auto guard1 = scope_exit([&i]()
        { ++i; });
        auto guard2 = scope_exit(std::move(guard1));
        // guard1 should be inactive after move
    } // guard2 should fire here, not guard1
    EXPECT_EQ(i, 1);
}

TEST(ScopeGuardImpl, scope_exit_move_and_release)
{
    int i = 0;
    {
        auto guard1 = scope_exit([&i]()
        { ++i; });
        auto guard2 = scope_exit(std::move(guard1));
        guard2.release();
        // Neither guard should fire
    }
    EXPECT_EQ(i, 0);
}

// Test stateful callable with complex capture
TEST(ScopeGuardImpl, stateful_callable_complex_capture)
{
    int counter = 0;
    std::string message;
    {
        auto guard = scope_exit([&counter, &message]()
        {
            counter += 10;
            message = "cleanup executed";
        });
    }
    EXPECT_EQ(counter, 10);
    EXPECT_EQ(message, "cleanup executed");
}

// Test multiple consecutive moves
TEST(ScopeGuardImpl, multiple_consecutive_moves)
{
    int i = 0;
    {
        auto guard1 = scope_exit([&i]()
        { ++i; });
        auto guard2 = scope_exit(std::move(guard1));
        auto guard3 = scope_exit(std::move(guard2));
        auto guard4 = scope_exit(std::move(guard3));
        // Only guard4 should be active
    }
    EXPECT_EQ(i, 1);
}

// Test release after move
TEST(ScopeGuardImpl, release_on_moved_from_guard)
{
    int i = 0;
    {
        auto guard1 = scope_exit([&i]()
        { ++i; });
        auto guard2 = scope_exit(std::move(guard1));
        guard1.release(); // Should be safe (no-op on moved-from object)
    }
    EXPECT_EQ(i, 1);
}

// Test scope_fail with move
TEST(ScopeGuardImpl, scope_fail_with_move)
{
    int i = 0;
    try
    {
        auto guard1 = scope_fail([&i]()
        { ++i; });
        auto guard2 = scope_fail(std::move(guard1));
        throw std::runtime_error("test");
    }
    catch (std::runtime_error &)
    {
    }
    EXPECT_EQ(i, 1); // guard2 should fire, not guard1
}

// Test scope_success with move
TEST(ScopeGuardImpl, scope_success_with_move)
{
    int i = 0;
    {
        auto guard1 = scope_success([&i]()
        { ++i; });
        auto guard2 = scope_success(std::move(guard1));
    }
    EXPECT_EQ(i, 1); // guard2 should fire, not guard1
}

// Test release() returning the callable
TEST(ScopeGuardImpl, release_returns_callable)
{
    int i = 0;
    std::optional<std::function<void()>> cleanup;
    {
        auto guard = scope_exit([&i]()
        { i += 10; });
        cleanup = guard.release();
        EXPECT_TRUE(cleanup.has_value());
    } // guard should not fire
    EXPECT_EQ(i, 0);

    // Now invoke the saved cleanup
    if (cleanup)
    {
        (*cleanup)();
    }
    EXPECT_EQ(i, 10);
}

// Test invoke() calling cleanup early
TEST(ScopeGuardImpl, invoke_executes_early)
{
    int i = 0;
    {
        auto guard = scope_exit([&i]()
        { i += 5; });
        EXPECT_EQ(i, 0);
        guard.invoke(); // Execute early
        EXPECT_EQ(i, 5);
    } // Should not execute again
    EXPECT_EQ(i, 5);
}

// Test invoke() on already released guard is no-op
TEST(ScopeGuardImpl, invoke_after_release_is_noop)
{
    int i = 0;
    auto guard = scope_exit([&i]()
    { ++i; });
    guard.release();
    guard.invoke(); // Should be no-op
    EXPECT_EQ(i, 0);
}

// Test multiple invoke() calls
TEST(ScopeGuardImpl, multiple_invoke_calls)
{
    int i = 0;
    {
        auto guard = scope_exit([&i]()
        { ++i; });
        guard.invoke();
        EXPECT_EQ(i, 1);
        guard.invoke(); // Should be no-op
        EXPECT_EQ(i, 1);
    }
    EXPECT_EQ(i, 1);
}

// Test release() on already invoked guard returns nullopt
TEST(ScopeGuardImpl, release_after_invoke_returns_nullopt)
{
    int i = 0;
    auto guard = scope_exit([&i]()
    { ++i; });
    guard.invoke();
    EXPECT_EQ(i, 1);

    auto cleanup = guard.release();
    EXPECT_FALSE(cleanup.has_value());
}

// Test reset() with new cleanup function
TEST(ScopeGuardImpl, reset_with_new_function)
{
    int i = 0;
    {
        scope_exit<std::function<void()>> guard([&i]()
        { i = 10; });
        guard.reset([&i]()
        { i = 20; }); // Replace cleanup
    }
    EXPECT_EQ(i, 20); // New cleanup should fire
}

// Test reset() multiple times
TEST(ScopeGuardImpl, reset_multiple_times)
{
    int i = 0;
    {
        scope_exit<std::function<void()>> guard([&i]()
        { i = 1; });
        guard.reset([&i]()
        { i = 2; });
        guard.reset([&i]()
        { i = 3; });
        guard.reset([&i]()
        { i = 4; });
    }
    EXPECT_EQ(i, 4); // Last cleanup should fire
}

// Test reset() after invoke()
TEST(ScopeGuardImpl, reset_after_invoke)
{
    int i = 0;
    {
        scope_exit<std::function<void()>> guard([&i]()
        { i += 10; });
        guard.invoke(); // Execute first cleanup
        EXPECT_EQ(i, 10);
        guard.reset([&i]()
        { i += 5; }); // Install new cleanup
    }
    EXPECT_EQ(i, 15); // New cleanup should fire at scope exit
}

// Test reset() after release()
TEST(ScopeGuardImpl, reset_after_release)
{
    int i = 0;
    {
        scope_exit<std::function<void()>> guard([&i]()
        { i = 10; });
        guard.release(); // Disable
        guard.reset([&i]()
        { i = 20; }); // Re-enable with new cleanup
    }
    EXPECT_EQ(i, 20); // New cleanup should fire
}

// Test reset() allows guard reuse pattern
TEST(ScopeGuardImpl, reset_reuse_pattern)
{
    std::vector<int> order;
    {
        scope_exit<std::function<void()>> guard([&order]()
        { order.push_back(1); });
        guard.invoke();
        EXPECT_EQ(order.size(), 1u);
        EXPECT_EQ(order[0], 1);

        guard.reset([&order]()
        { order.push_back(2); });
        guard.invoke();
        EXPECT_EQ(order.size(), 2u);
        EXPECT_EQ(order[1], 2);

        guard.reset([&order]()
        { order.push_back(3); });
    }
    EXPECT_EQ(order.size(), 3u);
    EXPECT_EQ(order[2], 3);
}
