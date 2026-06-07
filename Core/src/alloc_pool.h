// Copyright (c) 2023- Charlie Vigue. All rights reserved.


#ifndef CLVLIB_CORE_ALLOCPOOL_H
#define CLVLIB_CORE_ALLOCPOOL_H

#include <cstddef>
#include <vector>
#include <memory>
#include <mutex>

#include "spinlock.h"
#include "tagged_pointer.h"

namespace clv {

/**
 * @brief Memory allocation pool.
 * @param block_per_pool The number of blocks to allocate at a time.
 * @tparam block_size The size of each block in the pool. Must be >= sizeof(void*).
 * @details This struct manages a pool of memory blocks of size mBlockSize. It
 *          allocates blocks of \p mBlocksPerPool blocks at a time and hands out
 *          pointers to free blocks on alloc() and takes back pointers on free(). It
 *          is lock-free except during allocation of additional pool blocks.
 */
template <std::size_t block_size, bool allocate_on_construct = true>
struct AllocPool
{
    ~AllocPool() = default; // Consider lingering allocation diagnostics here
    AllocPool(const std::size_t blocks_per_pool) noexcept;
    AllocPool(const AllocPool &) = delete;
    AllocPool(AllocPool &&) = delete;
    AllocPool &operator=(const AllocPool &) = delete;
    AllocPool &operator=(AllocPool &&) = delete;

  public:
    void *alloc();
    void free(void *block) noexcept;
    std::size_t total_blocks() const noexcept;
    std::size_t pool_count() const noexcept;
    constexpr std::size_t blocks_per_pool() const noexcept;
    constexpr std::size_t alloc_size() const noexcept;

  private:
    struct PoolElementT
    {
        PoolElementT *next = nullptr;
        unsigned char data[block_size];
    };
    using PoolT = std::unique_ptr<PoolElementT[]>;
    using PoolVectorT = std::vector<PoolT>;
    using PoolListHeadT = TaggedPointer<PoolElementT>;

  private:
    void ReloadAlloc();

  private:
    PoolVectorT mPools;               ///< Container for all the pooled blocks
    clv::spinlock mReload;            ///< Mutex for reloading logic
    PoolListHeadT mAllocList;         ///< Unallocated blocks available for use + tagbits
    PoolListHeadT mFreedList;         ///< Blocks that have been returned + tagbits
    const std::size_t mBlocksPerPool; ///< How many blocks to allocate in each pool
};
/**
 * @brief Construct a new AllocPool<block_size>::AllocPool object
 * @param blocks_per_pool count of block_size blocks in each allocated pool
 */
template <std::size_t block_size, bool alloc_on_construct>
AllocPool<block_size, alloc_on_construct>::AllocPool(const std::size_t blocks_per_pool) noexcept
    : mPools(),
      mReload(),
      mAllocList(nullptr),
      mFreedList(nullptr),
      mBlocksPerPool(blocks_per_pool)
{
    if constexpr (alloc_on_construct)
        ReloadAlloc();
}
/**
 * @brief Allocates a block of memory from the pool.
 * @return void* A pointer to the allocated block of memory.
 * @details This method allocates a block of memory from the pool. It first attempts
 *          to pop a block off the free list by atomically swapping the head of the
 *          free list with the next block in the list. If the free list is empty, it
 *          calls ReloadAlloc() to allocate more blocks, then retries the allocation.
 */
template <std::size_t block_size, bool alloc_on_construct>
inline void *AllocPool<block_size, alloc_on_construct>::alloc()
{
    PoolElementT *head = nullptr;
    PoolElementT *next_head = nullptr;
    std::uint64_t head_tag = 0;
    while (true)
    {
        auto v = mAllocList.split();
        head = v.first;
        head_tag = v.second;
        while (head == nullptr)
        {
            ReloadAlloc();
            v = mAllocList.split();
            head = v.first;
            head_tag = v.second;
        }
        next_head = head->next;
        PoolElementT *expected_ptr = head;
        std::uint64_t expected_tag = head_tag;
        if (mAllocList.compare_exchange_pointer_and_tag(expected_ptr,
                                                        expected_tag,
                                                        next_head,
                                                        PoolListHeadT::next_tag(expected_tag)))
            return static_cast<void *>(&head->data[0]);
        // else, retry loop
    }
}
/**
 * @brief Frees a block of memory back to the pool.
 * @param block A pointer to the block of memory to free.
 * @details This method frees a block of memory back to the freed block pool by
 *          atomically adding it to the head of the free list.
 */
template <std::size_t block_size, bool alloc_on_construct>
inline void AllocPool<block_size, alloc_on_construct>::free(void *block) noexcept
{
    PoolElementT *head = nullptr;
    std::uint64_t head_tag = 0;
    while (true)
    {
        auto v = mFreedList.split();
        head = v.first;
        head_tag = v.second;
        auto elem = reinterpret_cast<PoolElementT *>(reinterpret_cast<unsigned char *>(block) - offsetof(PoolElementT, data));
        elem->next = head;
        PoolElementT *expected_ptr = head;
        std::uint64_t expected_tag = head_tag;
        if (mFreedList.compare_exchange_pointer_and_tag(expected_ptr,
                                                        expected_tag,
                                                        elem,
                                                        PoolListHeadT::next_tag(expected_tag)))
            return;
    }
}
/**
 * @brief Returns the number of blocks allocated.
 * @return std::size_t The number of blocks allocated.
 */
template <std::size_t block_size, bool alloc_on_construct>
inline std::size_t AllocPool<block_size, alloc_on_construct>::total_blocks() const noexcept
{
    return pool_count() * blocks_per_pool();
}
/**
 * @brief Returns the number of pools allocated.
 * @return std::size_t The number of pool allocated.
 */
template <std::size_t block_size, bool alloc_on_construct>
inline std::size_t AllocPool<block_size, alloc_on_construct>::pool_count() const noexcept
{
    return mPools.size();
}
/**
 * @brief Returns the number of blocks per allocated block.
 * @return std::size_t The number of blocks allocated at a time.
 */
template <std::size_t block_size, bool alloc_on_construct>
inline constexpr std::size_t AllocPool<block_size, alloc_on_construct>::blocks_per_pool() const noexcept
{
    return mBlocksPerPool;
}
/**
 * @brief Returns the size of each block in the pool.
 * @return std::size_t The size in bytes of each block.
 */
template <std::size_t block_size, bool alloc_on_construct>
inline constexpr std::size_t AllocPool<block_size, alloc_on_construct>::alloc_size() const noexcept
{
    return block_size;
}

/**
 * @brief Reloads the allocation list.
 * @tparam block_size
 * @throws if \c new throws
 * @details The ReloadAlloc() method manages refilling the allocation pool when it runs
 *          out of free blocks.
 *
 * It takes no inputs and refills the pool with new blocks so that future allocation requests can
 * be satisfied. It first checks if a reload is already happening using a spinlock. This prevents
 * concurrent reloads.
 *
 * It then checks if the allocation list is empty. If so, it tries to reuse the freed list if any blocks
 * are freed. Otherwise it allocates a new pool, links the blocks together into a free list, and sets that
 * as the new allocation list.
 *
 * This allows the pool to refill itself with new blocks when needed in a thread-safe way. The reload
 * logic handles all necessary steps like allocating, linking, and publishing the new block list.
 */
template <std::size_t block_size, bool alloc_on_construct>
inline void AllocPool<block_size, alloc_on_construct>::ReloadAlloc()
{
    auto reloading = std::unique_lock(mReload, std::try_to_lock);
    if (reloading)
    {
        auto v = mAllocList.split();
        if (v.first == nullptr)
        {
            // We know mAllocList was already nullptr, that's how we got here. and
            // so we exchange nullptr with mFreedList to try to reuse freed blocks first.
            auto [freedptr, _] = mFreedList.exchange(nullptr);

            // If that's also empty, we do a somewhat more costly refill from the allocator.
            if (freedptr == nullptr)
            {
                // Create pool and link it internally
                mPools.emplace_back(new PoolElementT[mBlocksPerPool]);
                for (auto i = std::size_t(0); i < (mBlocksPerPool - 1); ++i)
                {
                    // This mess links the blocks inside the pool in a single link list
                    mPools.back().get()[i].next = &(mPools.back().get()[i + 1]);
                }
                freedptr = mPools.back().get();
            }

            // freedptr is now sure to point to something, and AllocList is sure to not
            // Store the pointer with next tag value using store() helper. We don't care about tag
            // value here we use 0 as initial tag — callers will CAS on updates.
            mAllocList.store(freedptr, 0, std::memory_order_release);
        }

        reloading.unlock();      // Should happen before notify_all
        mAllocList.notify_all(); // Notify all waiting threads that new blocks are available
    }
    else
    {
        mAllocList.wait_for_ptr_non_null(std::memory_order_acquire);
    }
}

} // namespace clv

#endif // CLVLIB_CORE_ALLOCPOOL_H
