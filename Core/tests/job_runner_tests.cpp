// Copyright (c) 2026- Charlie Vigue. All rights reserved.

#include "job_runner.h"

#include <atomic>
#include <future>
#include <string>
#include <gtest/gtest.h>

using namespace clv;

// ---------------------------------------------------------------------------
// Initial state
// ---------------------------------------------------------------------------

TEST(JobRunnerTest, DefaultConstruct_Empty)
{
    JobRunner<int> jr;
    EXPECT_TRUE(jr.results().empty());
    EXPECT_TRUE(jr.prune());
}

TEST(JobRunnerTest, Join_OnEmpty_IsNoOp)
{
    JobRunner<void> jr;
    jr.join(); // must not block or throw
    EXPECT_TRUE(jr.results().empty());
}

// ---------------------------------------------------------------------------
// run()
// ---------------------------------------------------------------------------

TEST(JobRunnerTest, Run_AddsFuture)
{
    JobRunner<int> jr;
    EXPECT_EQ(jr.results().size(), 0u);
    jr.run([]
    { return 42; });
    EXPECT_EQ(jr.results().size(), 1u);
    jr.join();
}

TEST(JobRunnerTest, Run_FutureIsValid)
{
    JobRunner<int> jr;
    jr.run([]
    { return 1; });
    EXPECT_TRUE(jr.results().front().valid());
    jr.join();
}

TEST(JobRunnerTest, MultipleRuns_AccumulateFutures)
{
    JobRunner<int> jr;
    jr.run([]
    { return 1; });
    jr.run([]
    { return 2; });
    jr.run([]
    { return 3; });
    EXPECT_EQ(jr.results().size(), 3u);
    jr.join();
}

TEST(JobRunnerTest, Run_VoidLambda)
{
    JobRunner<void> jr;
    jr.run([] {});
    EXPECT_EQ(jr.results().size(), 1u);
    jr.join();
}

TEST(JobRunnerTest, Run_StringResult)
{
    JobRunner<std::string> jr;
    jr.run([]
    { return std::string{"hello"}; });
    EXPECT_TRUE(jr.results().front().valid());
    jr.join();
}

// ---------------------------------------------------------------------------
// join()
// ---------------------------------------------------------------------------

TEST(JobRunnerTest, Join_ClearsResults)
{
    JobRunner<int> jr;
    jr.run([]
    { return 7; });
    jr.run([]
    { return 8; });
    jr.join();
    EXPECT_TRUE(jr.results().empty());
}

TEST(JobRunnerTest, Join_WaitsForCompletion)
{
    std::atomic<bool> done{false};
    JobRunner<void> jr;
    jr.run([&done]
    { done.store(true, std::memory_order_release); });
    jr.join();
    EXPECT_TRUE(done.load(std::memory_order_acquire));
}

TEST(JobRunnerTest, Join_MultipleJobsAllComplete)
{
    std::atomic<int> counter{0};
    JobRunner<void> jr;
    for (int i = 0; i < 8; ++i)
        jr.run([&counter]
        { counter.fetch_add(1, std::memory_order_relaxed); });
    jr.join();
    EXPECT_EQ(counter.load(), 8);
    EXPECT_TRUE(jr.results().empty());
}

// ---------------------------------------------------------------------------
// prune()
// ---------------------------------------------------------------------------

TEST(JobRunnerTest, Prune_OnEmpty_ReturnsTrue)
{
    JobRunner<void> jr;
    EXPECT_TRUE(jr.prune());
}

TEST(JobRunnerTest, Prune_CompletedJob_ReturnsTrue)
{
    JobRunner<int> jr;
    jr.run([]
    { return 0; });
    // Wait for the job to finish before pruning
    jr.results().front().wait();
    EXPECT_TRUE(jr.prune());
    EXPECT_TRUE(jr.results().empty());
}

TEST(JobRunnerTest, Prune_PendingJob_ReturnsFalse)
{
    std::promise<void> gate;
    std::shared_future<void> gfuture = gate.get_future().share();

    JobRunner<void> jr;
    jr.run([gfuture]
    { gfuture.wait(); });

    // Job is blocked — prune must not remove it
    EXPECT_FALSE(jr.prune());
    EXPECT_EQ(jr.results().size(), 1u);

    gate.set_value(); // unblock
    jr.join();
    EXPECT_TRUE(jr.results().empty());
}

TEST(JobRunnerTest, Prune_PartiallyComplete)
{
    std::promise<void> gate;
    std::shared_future<void> gfuture = gate.get_future().share();

    JobRunner<int> jr;
    // One job completes immediately, one is blocked
    jr.run([]
    { return 1; });
    jr.run([gfuture]
    { gfuture.wait(); return 2; });

    // Wait for the first job to actually finish
    jr.results().front().wait();

    // prune should remove completed job, keep pending one
    bool all_done = jr.prune();
    EXPECT_FALSE(all_done);
    EXPECT_EQ(jr.results().size(), 1u);

    gate.set_value();
    jr.join();
}
