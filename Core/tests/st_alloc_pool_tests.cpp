// Copyright (c) 2026- Charlie Vigue. All rights reserved.

#include <cstddef>
#include <cstdint>
#include <gtest/gtest.h>
#include <ios>
#include <vector>
#include "st_alloc_pool.h"

using namespace clv;

// ============================================================================
// Basic Allocation Tests
// ============================================================================

TEST(StAllocPoolTest, AllocReturnsValidPointer)
{
    StAllocPool<256> pool(8);
    void *ptr = pool.alloc();
    EXPECT_NE(ptr, nullptr);
}

TEST(StAllocPoolTest, AllocReturnsDistinctPointers)
{
    StAllocPool<256> pool(8);
    void *ptr1 = pool.alloc();
    void *ptr2 = pool.alloc();
    void *ptr3 = pool.alloc();

    EXPECT_NE(ptr1, ptr2);
    EXPECT_NE(ptr2, ptr3);
    EXPECT_NE(ptr1, ptr3);
}

TEST(StAllocPoolTest, FreeAndReallocReturnsSamePointer)
{
    StAllocPool<256> pool(8);
    void *ptr1 = pool.alloc();
    pool.free(ptr1);
    void *ptr2 = pool.alloc();

    // After freeing, the same block should be reused (LIFO)
    EXPECT_EQ(ptr1, ptr2);
}

TEST(StAllocPoolTest, AllocMoreThanInitialCapacity)
{
    StAllocPool<256> pool(4); // Allocate 4 blocks per chunk

    // Allocate 6 blocks (more than initial 4)
    std::vector<void *> ptrs;
    for (int i = 0; i < 6; ++i)
    {
        ptrs.push_back(pool.alloc());
    }

    // All should be distinct
    for (std::size_t i = 0; i < ptrs.size(); ++i)
    {
        for (std::size_t j = i + 1; j < ptrs.size(); ++j)
        {
            EXPECT_NE(ptrs[i], ptrs[j]);
        }
    }

    // Pool count should be 2 (initial 4 + refill of 4)
    EXPECT_EQ(pool.pool_count(), 2);
    EXPECT_EQ(pool.total_blocks(), 8);
}

TEST(StAllocPoolTest, DataCanBeWrittenAndRead)
{
    StAllocPool<64> pool(4);
    void *ptr = pool.alloc();

    // Write to the block
    auto *bytes = static_cast<uint8_t *>(ptr);
    for (int i = 0; i < 64; ++i)
    {
        bytes[i] = static_cast<uint8_t>(i);
    }

    // Read back
    for (int i = 0; i < 64; ++i)
    {
        EXPECT_EQ(bytes[i], i);
    }
}

// ============================================================================
// Pool Resizing and Metadata Tests
// ============================================================================

TEST(StAllocPoolTest, PoolCountInitiallyZero)
{
    StAllocPool<256> pool(8, false); // Don't allocate on construct
    EXPECT_EQ(pool.pool_count(), 0);
    EXPECT_EQ(pool.total_blocks(), 0);
}

TEST(StAllocPoolTest, PoolCountIncrementsOnAlloc)
{
    StAllocPool<256> pool(4, false);
    EXPECT_EQ(pool.pool_count(), 0);

    pool.alloc(); // Triggers ReloadAlloc
    EXPECT_EQ(pool.pool_count(), 1);
    EXPECT_EQ(pool.total_blocks(), 4);

    // Allocate 4 more (uses remaining in first chunk)
    for (int i = 0; i < 3; ++i)
        pool.alloc();
    EXPECT_EQ(pool.pool_count(), 1); // Still one chunk

    // Allocate one more (triggers second ReloadAlloc)
    pool.alloc();
    EXPECT_EQ(pool.pool_count(), 2);
    EXPECT_EQ(pool.total_blocks(), 8);
}

TEST(StAllocPoolTest, BlocksPerPoolConstant)
{
    StAllocPool<256> pool(16);
    EXPECT_EQ(pool.blocks_per_pool(), 16);
}

TEST(StAllocPoolTest, AllocSizeConstant)
{
    StAllocPool<1024> pool(8);
    EXPECT_EQ(pool.alloc_size(), 1024);
}

// ============================================================================
// Stress Tests
// ============================================================================

TEST(StAllocPoolTest, AllocAndFreeMany)
{
    StAllocPool<512> pool(16);
    std::vector<void *> ptrs;

    // Allocate 100 blocks
    for (int i = 0; i < 100; ++i)
    {
        ptrs.push_back(pool.alloc());
    }

    EXPECT_EQ(pool.total_blocks(), 112); // 16 * 7 chunks

    // Free all of them
    for (void *ptr : ptrs)
    {
        pool.free(ptr);
    }

    // Allocate again—should reuse
    std::vector<void *> ptrs2;
    for (int i = 0; i < 100; ++i)
    {
        ptrs2.push_back(pool.alloc());
    }

    // Should still be 7 chunks (no new allocations)
    EXPECT_EQ(pool.pool_count(), 7);
}

TEST(StAllocPoolTest, LIFOOrderAfterFree)
{
    StAllocPool<256> pool(8);

    void *p1 = pool.alloc();
    void *p2 = pool.alloc();
    void *p3 = pool.alloc();

    pool.free(p3);
    pool.free(p2);
    pool.free(p1);

    // LIFO order: should get p1, p2, p3
    EXPECT_EQ(pool.alloc(), p1);
    EXPECT_EQ(pool.alloc(), p2);
    EXPECT_EQ(pool.alloc(), p3);
}

TEST(StAllocPoolTest, InterleavedAllocFree)
{
    StAllocPool<256> pool(4);

    void *p1 = pool.alloc();
    void *p2 = pool.alloc();
    pool.free(p1);
    void *p3 = pool.alloc(); // Should get p1

    EXPECT_EQ(p1, p3);
    EXPECT_NE(p2, p3);
}

// ============================================================================
// Multiple Block Size Tests
// ============================================================================

TEST(StAllocPoolTest, SmallBlockSize)
{
    StAllocPool<16> pool(32);
    void *ptr = pool.alloc();
    EXPECT_NE(ptr, nullptr);
    EXPECT_EQ(pool.alloc_size(), 16);
}

TEST(StAllocPoolTest, LargeBlockSize)
{
    StAllocPool<8192> pool(4);
    void *ptr = pool.alloc();
    EXPECT_NE(ptr, nullptr);
    EXPECT_EQ(pool.alloc_size(), 8192);
}

// ============================================================================
// Alignment Tests
// ============================================================================

TEST(StAllocPoolTest, BlocksAreAligned)
{
    StAllocPool<256> pool(8);

    // Allocate several blocks and check alignment
    for (int i = 0; i < 8; ++i)
    {
        void *ptr = pool.alloc();
        auto addr = reinterpret_cast<std::uintptr_t>(ptr);

        // Check alignment to max_align_t (typically 16 on most platforms)
        EXPECT_EQ(addr % alignof(std::max_align_t), 0)
            << "Block " << i << " at " << std::hex << addr << " not aligned to max_align_t";
    }
}

// ============================================================================
// Edge Cases
// ============================================================================

TEST(StAllocPoolTest, SingleBlockPerChunk)
{
    StAllocPool<256> pool(1);
    void *p1 = pool.alloc();
    void *p2 = pool.alloc();
    void *p3 = pool.alloc();

    EXPECT_NE(p1, p2);
    EXPECT_NE(p2, p3);
    EXPECT_EQ(pool.pool_count(), 3);
}

TEST(StAllocPoolTest, ConstructorDeferredAllocation)
{
    StAllocPool<256> pool(8, false);
    EXPECT_EQ(pool.pool_count(), 0);

    // First alloc triggers ReloadAlloc
    void *ptr = pool.alloc();
    EXPECT_NE(ptr, nullptr);
    EXPECT_EQ(pool.pool_count(), 1);
}
