// Copyright (c) 2023- Charlie Vigue. All rights reserved.

#include <cstddef>
#include <gtest/gtest.h>

#include "alloc_pool.h"
#include "make_pooled.h"
#include "job_runner.h"

#include <iostream>
#include <memory>
#include <chrono>
#include <vector>

using namespace clv;

struct test1
{
    test1() = default;
    test1(int a_, int b_)
        : a(a_), b(b_)
    {
    }
    int a = 1;
    int b = 2;
};

template <std::size_t cap>
struct test2
{
    test2() = default;
    char ch[cap];
};

template <typename T>
auto alloc_many(int outer, int inner)
{
    auto start = std::chrono::system_clock::now();
    for (auto i = outer; i > 0; --i)
    {
        auto vec = std::vector<T *>();
        for (auto j = inner; j > 0; --j)
        {
            vec.push_back(new T());
        }
        for (auto &&ptr : vec)
        {
            delete ptr;
        }
    }
    return std::chrono::system_clock::now() - start;
}

template <typename T>
auto alloc_many_mt(int outer, int inner, int jobs)
{
    auto start = std::chrono::system_clock::now();

    auto jr = JobRunner<void>();
    for (int i = 0; i < jobs; ++i)
    {
        jr.run([outer, inner]()
        { alloc_many<T>(outer, inner); });
    }
    jr.join();

    return std::chrono::system_clock::now() - start;
}

TEST(MakePooledAllocPool, BasicConstruction)
{
    auto t1 = MakePooled<test1, AllocPool, 32>();
    EXPECT_EQ(t1.a, 1);
    EXPECT_EQ(t1.b, 2);
}

TEST(MakePooledAllocPool, UniquePtr)
{
    auto t1 = std::make_unique<MakePooled<test1, AllocPool, 32>>();
    EXPECT_NE(t1, nullptr);
    EXPECT_EQ(t1->a, 1);
    EXPECT_EQ(t1->b, 2);
}

TEST(MakePooledAllocPool, UniqueParamConstruction)
{
    auto t1 = std::make_unique<MakePooled<test1, AllocPool, 32>>(3, 4);
    EXPECT_NE(t1, nullptr);
    EXPECT_EQ(t1->a, 3);
    EXPECT_EQ(t1->b, 4);
}

TEST(MakePooledAllocPool, PerformanceBasic)
{
    auto d1 = alloc_many<test1>(100, 500);
    auto d2 = alloc_many<MakePooled<test1, AllocPool, 100>>(100, 500);

    // Verify pool statistics
    auto pool_count = MakePooled<test1, AllocPool, 100>::Pool_PoolCount();
    auto total_blocks = MakePooled<test1, AllocPool, 100>::Pool_TotalBlocks();

    // Should have created multiple pools (100 blocks per pool, 50K allocations)
    EXPECT_GT(pool_count, 0);
    EXPECT_GE(total_blocks, 100);
}

template <auto iterations,
          auto allocations,
          auto thrd,
          auto count_per_block,
          auto blocksz>
void MtTest()
{
    auto d1 = alloc_many_mt<test2<blocksz>>(iterations, allocations, thrd);
    auto d2 = alloc_many_mt<MakePooled<test2<blocksz>, AllocPool, count_per_block>>(iterations, allocations, thrd);
    auto factor = (d1 * 100 / d2);
    std::cout << "new/delete: " << d1 << std::endl;
    std::cout << "pooled    : " << d2 << std::endl;
    std::cout << "difference: " << factor << ((factor < 100) ? "% --> Slower than malloc" : "%") << std::endl;

    auto pools = MakePooled<test2<blocksz>, AllocPool, count_per_block>::Pool_PoolCount();
    auto alloc_cnt = iterations * allocations * thrd;
    auto block_cnt = pools * count_per_block;
    std::cout << "Pools allocated: " << pools << std::endl;
    std::cout << "         Blocks: " << pools * count_per_block << std::endl;
    std::cout << "      Avg reuse: " << double(alloc_cnt) / double(block_cnt) << std::endl;
    std::cout << "    Allocations: " << alloc_cnt << std::endl;
    EXPECT_LT(block_cnt, alloc_cnt);
}

TEST(MakePooledAllocPool, PerformanceMT_1600x2t)
{
    constexpr std::size_t iterations = 2000;
    constexpr std::size_t allocations = 200;
    constexpr std::size_t thrd = 2;
    constexpr std::size_t count_per_block = 50;
    constexpr std::size_t blocksz = 1600;
    MtTest<iterations, allocations, thrd, count_per_block, blocksz>();
}