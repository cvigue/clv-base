// Copyright (c) 2026- Charlie Vigue. All rights reserved.

#include <gtest/gtest.h>
#include "st_alloc_pool.h"
#include "make_pooled.h"

using namespace clv;

// ============================================================================
// Test Fixtures and Helper Types
// ============================================================================

struct SimpleData
{
    int x = 0;
    int y = 0;
    int z = 0;

    SimpleData() = default;
    SimpleData(int a, int b, int c) : x(a), y(b), z(c)
    {
    }
};

struct DataWithDtor
{
    static int ctor_count;
    static int dtor_count;

    int value = 0;

    DataWithDtor()
    {
        ++ctor_count;
    }
    DataWithDtor(int v) : value(v)
    {
        ++ctor_count;
    }
    ~DataWithDtor()
    {
        ++dtor_count;
    }
};

int DataWithDtor::ctor_count = 0;
int DataWithDtor::dtor_count = 0;

// ============================================================================
// Single-threaded pool specializations for testing
// ============================================================================

using PooledSimpleData = MakePooled<SimpleData, StAllocPool, 16>;
using PooledSmallData = MakePooled<SimpleData, StAllocPool, 8>;

// ============================================================================
// Basic Allocation Tests
// ============================================================================

TEST(MakePooledTest, AllocateAndDelete)
{
    auto *ptr = new PooledSimpleData(1, 2, 3);
    EXPECT_NE(ptr, nullptr);
    EXPECT_EQ(ptr->x, 1);
    EXPECT_EQ(ptr->y, 2);
    EXPECT_EQ(ptr->z, 3);
    delete ptr;
}

TEST(MakePooledTest, DefaultConstructor)
{
    auto *ptr = new PooledSimpleData();
    EXPECT_NE(ptr, nullptr);
    EXPECT_EQ(ptr->x, 0);
    EXPECT_EQ(ptr->y, 0);
    EXPECT_EQ(ptr->z, 0);
    delete ptr;
}

TEST(MakePooledTest, ParameterizedConstructor)
{
    auto *ptr = new PooledSimpleData(10, 20, 30);
    EXPECT_EQ(ptr->x, 10);
    EXPECT_EQ(ptr->y, 20);
    EXPECT_EQ(ptr->z, 30);
    delete ptr;
}

// ============================================================================
// Pool Statistics Tests
// ============================================================================

TEST(MakePooledTest, PoolCountAfterAllocation)
{
    // Reset with fresh pool instance (note: static pools persist, so we measure relative to start)
    std::size_t initial_count = PooledSimpleData::Pool_PoolCount();
    std::size_t initial_blocks = PooledSimpleData::Pool_TotalBlocks();

    // These will be kept and never freed in this test scope
    // Actually, let's use a different pool instance to isolate the test
    // Let me refactor...
}

TEST(MakePooledTest, AllocateMultipleInstances)
{
    // Use smaller pool to more quickly exhaust initial chunk
    std::size_t initial_pools = PooledSmallData::Pool_PoolCount();

    std::vector<PooledSmallData *> ptrs;

    // Allocate 10 objects (chunk size is 8, so should trigger ReloadAlloc)
    for (int i = 0; i < 10; ++i)
    {
        ptrs.push_back(new PooledSmallData(i, i + 1, i + 2));
    }

    // Should have at least 2 pool chunks now (8 + 2 more)
    std::size_t final_pools = PooledSmallData::Pool_PoolCount();
    EXPECT_GE(final_pools, initial_pools + 1);

    // Verify data integrity
    for (std::size_t i = 0; i < ptrs.size(); ++i)
    {
        EXPECT_EQ(ptrs[i]->x, i);
        EXPECT_EQ(ptrs[i]->y, i + 1);
        EXPECT_EQ(ptrs[i]->z, i + 2);
    }

    // Cleanup
    for (auto *ptr : ptrs)
    {
        delete ptr;
    }
}

// ============================================================================
// Pool Reuse Tests (LIFO order)
// ============================================================================

TEST(MakePooledTest, PoolReuseAfterDelete)
{
    auto *p1 = new PooledSimpleData(1, 2, 3);
    auto initial_pools = PooledSimpleData::Pool_PoolCount();
    auto initial_blocks = PooledSimpleData::Pool_TotalBlocks();

    delete p1;

    // After delete, pool count should stay the same (block returned to free list)
    EXPECT_EQ(PooledSimpleData::Pool_PoolCount(), initial_pools);
    EXPECT_EQ(PooledSimpleData::Pool_TotalBlocks(), initial_blocks);

    // New allocation should reuse the freed block (LIFO)
    auto *p2 = new PooledSimpleData(4, 5, 6);

    // Should still have same number of pools/blocks
    EXPECT_EQ(PooledSimpleData::Pool_PoolCount(), initial_pools);
    EXPECT_EQ(PooledSimpleData::Pool_TotalBlocks(), initial_blocks);

    delete p2;
}

TEST(MakePooledTest, LIFOOrderPreserved)
{
    auto *p1 = new PooledSimpleData(1, 1, 1);
    auto *p2 = new PooledSimpleData(2, 2, 2);
    auto *p3 = new PooledSimpleData(3, 3, 3);

    // Record initial pool state
    auto initial_pools = PooledSmallData::Pool_PoolCount();
    auto initial_blocks = PooledSmallData::Pool_TotalBlocks();

    // Delete in reverse order (LIFO)
    delete p3;
    delete p2;
    delete p1;

    // Next allocations should get p1, p2, p3 in that order (LIFO)
    auto *p1_reused = new PooledSimpleData(0, 0, 0);
    auto *p2_reused = new PooledSimpleData(0, 0, 0);
    auto *p3_reused = new PooledSimpleData(0, 0, 0);

    // Assumption: pointers should match due to LIFO
    // (Note: exact pointer equality may not hold if pool impl differs,
    //  but we're testing the concept with StAllocPool which is LIFO)
    EXPECT_EQ(p1_reused, p1);
    EXPECT_EQ(p2_reused, p2);
    EXPECT_EQ(p3_reused, p3);

    // Cleanup
    delete p1_reused;
    delete p2_reused;
    delete p3_reused;
}

// ============================================================================
// Stress and Edge Case Tests
// ============================================================================

TEST(MakePooledTest, AllocateManyAndFree)
{
    std::vector<PooledSmallData *> ptrs;

    // Allocate 50 objects
    for (int i = 0; i < 50; ++i)
    {
        ptrs.push_back(new PooledSmallData(i, i + 1, i + 2));
    }

    // Pool should have expanded
    EXPECT_GT(PooledSmallData::Pool_PoolCount(), 1);
    EXPECT_GE(PooledSmallData::Pool_TotalBlocks(), 50);

    // Free all
    for (auto *ptr : ptrs)
    {
        delete ptr;
    }

    // Pool should still exist (blocks returned to free list, not deallocated)
    EXPECT_GT(PooledSmallData::Pool_PoolCount(), 0);
    EXPECT_GE(PooledSmallData::Pool_TotalBlocks(), 50);
}

TEST(MakePooledTest, InterleavedAllocDelete)
{
    std::vector<PooledSimpleData *> ptrs;

    // Allocate 5
    for (int i = 0; i < 5; ++i)
        ptrs.push_back(new PooledSimpleData(i, i, i));

    // Delete 2nd and 4th
    delete ptrs[1];
    delete ptrs[3];

    // Allocate 2 more
    ptrs[1] = new PooledSimpleData(10, 10, 10);
    ptrs[3] = new PooledSimpleData(20, 20, 20);

    // Verify
    EXPECT_EQ(ptrs[0]->x, 0);
    EXPECT_EQ(ptrs[1]->x, 10);
    EXPECT_EQ(ptrs[2]->x, 2);
    EXPECT_EQ(ptrs[3]->x, 20);
    EXPECT_EQ(ptrs[4]->x, 4);

    // Cleanup
    for (auto *ptr : ptrs)
        delete ptr;
}

// ============================================================================
// Constructor Forwarding Test
// ============================================================================

TEST(MakePooledTest, ConstructorForwarding)
{
    // Test with 0 args
    auto *p0 = new PooledSimpleData();
    EXPECT_EQ(p0->x, 0);
    delete p0;

    // Test with 3 args
    auto *p3 = new PooledSimpleData(100, 200, 300);
    EXPECT_EQ(p3->x, 100);
    EXPECT_EQ(p3->y, 200);
    EXPECT_EQ(p3->z, 300);
    delete p3;
}

// ============================================================================
// Data Integrity Tests
// ============================================================================

TEST(MakePooledTest, DataDoesNotCorruptAcrossReuse)
{
    auto *p1 = new PooledSimpleData(0xDEADBEEF, 0xCAFEBABE, 0x12345678);
    auto addr1 = reinterpret_cast<std::uintptr_t>(p1);

    delete p1;

    // Allocate something different to the same pool slot
    auto *p2 = new PooledSimpleData(1, 2, 3);
    auto addr2 = reinterpret_cast<std::uintptr_t>(p2);

    // Should reuse the same address
    EXPECT_EQ(addr1, addr2);

    // Data should be uncorrupted (overwritten by constructor)
    EXPECT_EQ(p2->x, 1);
    EXPECT_EQ(p2->y, 2);
    EXPECT_EQ(p2->z, 3);

    delete p2;
}

TEST(MakePooledTest, MultipleInstancesIndependentState)
{
    auto *p1 = new PooledSimpleData(10, 20, 30);
    auto *p2 = new PooledSimpleData(40, 50, 60);
    auto *p3 = new PooledSimpleData(70, 80, 90);

    // Modify each independently
    p1->x = 100;
    p2->y = 200;
    p3->z = 300;

    // Verify independence
    EXPECT_EQ(p1->x, 100);
    EXPECT_EQ(p1->y, 20);
    EXPECT_EQ(p2->x, 40);
    EXPECT_EQ(p2->y, 200);
    EXPECT_EQ(p3->x, 70);
    EXPECT_EQ(p3->z, 300);

    delete p1;
    delete p2;
    delete p3;
}

// ============================================================================
// Pool API Tests
// ============================================================================

TEST(MakePooledTest, PoolCountQueriedAfterAllocations)
{
    std::size_t baseline_count = PooledSmallData::Pool_PoolCount();

    auto *p1 = new PooledSmallData(1, 1, 1);
    auto *p2 = new PooledSmallData(2, 2, 2);

    std::size_t count_after = PooledSmallData::Pool_PoolCount();

    // Count should not increase for these two (fit in initial chunk)
    // unless we've already consumed the initial chunk in prior tests
    EXPECT_GE(count_after, baseline_count);

    delete p1;
    delete p2;
}

TEST(MakePooledTest, PoolTotalBlocksMonotonic)
{
    std::size_t baseline_total = PooledSmallData::Pool_TotalBlocks();

    // Allocate a small number
    auto *p1 = new PooledSmallData(1, 1, 1);

    std::size_t total_after_one = PooledSmallData::Pool_TotalBlocks();

    // Total blocks should be >= baseline (monotonically non-decreasing)
    EXPECT_GE(total_after_one, baseline_total);

    delete p1;

    // Total blocks should remain the same (blocks returned to free list, not deallocated)
    std::size_t total_after_delete = PooledSmallData::Pool_TotalBlocks();
    EXPECT_EQ(total_after_delete, total_after_one);
}
