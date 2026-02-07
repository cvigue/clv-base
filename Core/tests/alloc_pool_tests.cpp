// Copyright (c) 2023- Charlie Vigue. All rights reserved.


#include "gtest/gtest.h"
#include "alloc_pool.h"
#include <random>
#include <unordered_set>
#include <atomic>

using namespace clv;

TEST(AllocPool, BasicAllocFree)
{
    AllocPool<10> pool(10);

    auto ptr1 = pool.alloc();
    EXPECT_NE(ptr1, nullptr);

    auto ptr2 = pool.alloc();
    EXPECT_NE(ptr2, nullptr);
    EXPECT_NE(ptr1, ptr2);
    EXPECT_EQ(sizeof("deadbeef_"), pool.alloc_size());

    memcpy(ptr1, "deadbeef1", pool.alloc_size());
    memcpy(ptr2, "deadbeef2", pool.alloc_size());

    EXPECT_EQ(memcmp(ptr1, "deadbeef1", pool.alloc_size()), 0);
    EXPECT_EQ(memcmp(ptr2, "deadbeef2", pool.alloc_size()), 0);

    pool.free(ptr1);
    pool.free(ptr2);
}

TEST(AllocPool, AllocAfterFree)
{
    AllocPool<6> pool(10);

    auto ptr1 = pool.alloc();
    EXPECT_NE(ptr1, nullptr);

    pool.free(ptr1);

    auto ptr2 = pool.alloc();
    EXPECT_NE(ptr2, nullptr);
    EXPECT_NE(ptr1, ptr2);
}

TEST(AllocPool, AllocUntilEmptyThenRefill)
{
    AllocPool<16> pool(10);

    std::vector<void *> pointers;
    for (int i = 0; i < 5; i++)
    {
        auto ptr = pool.alloc();
        EXPECT_NE(ptr, nullptr);
        pointers.push_back(ptr);
    }

    for (auto ptr : pointers)
    {
        pool.free(ptr);
    }
}

TEST(AllocPool, AllocUntilEmptySetThenRefill)
{
    AllocPool<16> pool(10);

    std::vector<void *> pointers;
    for (int i = 0; i < 5; i++)
    {
        auto ptr = pool.alloc();
        EXPECT_NE(ptr, nullptr);
        memset(ptr, i, pool.alloc_size());
        pointers.push_back(ptr);
    }

    for (auto ptr : pointers)
    {
        pool.free(ptr);
    }
}

TEST(AllocPool, AllocMoreThanBlockCount)
{
    AllocPool<16> pool(10);

    std::vector<void *> pointers;
    for (int i = 0; i < 15; i++)
    {
        auto ptr = pool.alloc();
        EXPECT_NE(ptr, nullptr);
        pointers.push_back(ptr);
    }

    auto ptr = pool.alloc();
    EXPECT_NE(ptr, nullptr);
    pointers.push_back(ptr);

    for (auto ptr : pointers)
    {
        pool.free(ptr);
    }
}

TEST(AllocPool, ConcurrentStress)
{
    AllocPool<32> pool(64);
    const int thread_count = 8;
    const int iter_count = 10000;
    std::vector<std::thread> workers;
    for (int i = 0; i < thread_count; ++i)
    {
        workers.emplace_back([&pool]()
        {
            for (int j = 0; j < iter_count; ++j)
            {
                auto ptr = pool.alloc();
                ASSERT_NE(ptr, nullptr);
                // Write something
                memset(ptr, (j & 0xff), pool.alloc_size());
                pool.free(ptr);
            }
        });
    }

    for (auto &t : workers)
        t.join();
}

TEST(AllocPool, ConcurrentRandomStress)
{
    AllocPool<32> pool(32);
    const int thread_count = 8;
    const int iter_count = 1000;
    std::vector<std::thread> workers;
    std::atomic<int> allocs{0};
    std::atomic<int> frees{0};
    for (int i = 0; i < thread_count; ++i)
    {
        workers.emplace_back([&pool, i, &allocs, &frees]()
        {
            std::mt19937 rng(1234 + i);
            std::vector<void *> local;
            for (int j = 0; j < iter_count; ++j)
            {
                if (local.empty() || (rng() & 1))
                {
                    auto ptr = pool.alloc();
                    ASSERT_NE(ptr, nullptr);
                    memset(ptr, 0xAA + (i & 0xff), pool.alloc_size());
                    local.push_back(ptr);
                    allocs.fetch_add(1, std::memory_order_relaxed);
                }
                else
                {
                    // free a random one
                    size_t idx = rng() % local.size();
                    auto ptr = local[idx];
                    pool.free(ptr);
                    frees.fetch_add(1, std::memory_order_relaxed);
                    local.erase(local.begin() + idx);
                }
            }
            // cleanup remaining
            for (auto p : local)
                pool.free(p);
        });
    }
    for (auto &t : workers)
        t.join();

    EXPECT_GE(allocs.load(), frees.load());
}

TEST(AllocPool, PoolGrowth)
{
    AllocPool<16> pool(8);
    size_t initial = pool.pool_count();
    std::vector<void *> pointers;
    for (int i = 0; i < 200; ++i)
    {
        auto p = pool.alloc();
        ASSERT_NE(p, nullptr);
        pointers.push_back(p);
    }
    EXPECT_GT(pool.pool_count(), initial);
    for (auto p : pointers)
        pool.free(p);
}

TEST(AllocPool, UniquePointers)
{
    AllocPool<24> pool(8);
    std::unordered_set<void *> seen;
    const int cnt = 200;
    std::vector<void *> pointers;
    for (int i = 0; i < cnt; ++i)
    {
        auto p = pool.alloc();
        ASSERT_NE(p, nullptr);
        ASSERT_EQ(seen.find(p), seen.end()); // ensure unique
        seen.insert(p);
        pointers.push_back(p);
    }
    for (auto p : pointers)
    {
        pool.free(p);
    }
}
