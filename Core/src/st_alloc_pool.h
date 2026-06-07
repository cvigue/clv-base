// Copyright (c) 2026- Charlie Vigue. All rights reserved.

#ifndef CLVLIB_CORE_ST_ALLOC_POOL_H
#define CLVLIB_CORE_ST_ALLOC_POOL_H

#include <cstddef>
#include <cstdint>
#include <vector>
#include <memory>

namespace clv {

/**
 * @brief Single-threaded memory allocation pool.
 * @tparam block_size The size of each block in the pool (in bytes).
 * @details This class manages a pool of fixed-size memory blocks for single-threaded use.
 *          It allocates blocks in chunks (blocks_per_pool at a time) and hands out
 *          pointers to free blocks on alloc() and takes them back on free().
 *          All operations are lock-free (single-threaded — no atomics or synchronization).
 */
template <std::size_t block_size>
struct StAllocPool
{
    ~StAllocPool() = default;

    /**
     * @brief Construct a single-threaded allocation pool.
     * @param blocks_per_pool Number of blocks to allocate per pool chunk
     * @param allocate_on_construct If true, allocate the first pool chunk immediately
     */
    StAllocPool(std::size_t blocks_per_pool,
                bool allocate_on_construct = true) noexcept;

    StAllocPool(const StAllocPool &) = delete;
    StAllocPool(StAllocPool &&) = delete;
    StAllocPool &operator=(const StAllocPool &) = delete;
    StAllocPool &operator=(StAllocPool &&) = delete;

  public:
    /**
     * @brief Allocate a block of memory from the pool.
     * @return Pointer to a block of @p block_size bytes.
     * @details If the free list is empty, allocates a new pool chunk and retries.
     */
    void *alloc();

    /**
     * @brief Return a block of memory to the pool.
     * @param block Pointer previously returned by alloc()
     */
    void free(void *block) noexcept;

    /**
     * @brief Total number of blocks ever allocated across all pool chunks.
     */
    std::size_t total_blocks() const noexcept;

    /**
     * @brief Number of pool chunks allocated so far.
     */
    std::size_t pool_count() const noexcept;

    /**
     * @brief Number of blocks per pool chunk (configured at construction).
     */
    constexpr std::size_t blocks_per_pool() const noexcept;

    /**
     * @brief Size of each block (compile-time constant, in bytes).
     */
    constexpr std::size_t alloc_size() const noexcept;

  private:
    struct PoolElement
    {
        PoolElement *next = nullptr;
        alignas(std::max_align_t) unsigned char data[block_size];
    };

    using PoolT = std::unique_ptr<PoolElement[]>;
    using PoolVectorT = std::vector<PoolT>;

  private:
    void ReloadAlloc();

  private:
    PoolVectorT pools_;                 ///< Container for all allocated pool chunks
    PoolElement *free_list_;            ///< Head of free list (simple singly-linked)
    const std::size_t blocks_per_pool_; ///< How many blocks per chunk
};

// ============================================================================
// Implementation
// ============================================================================

template <std::size_t block_size>
inline StAllocPool<block_size>::StAllocPool(std::size_t blocks_per_pool,
                                            bool allocate_on_construct) noexcept
    : pools_(), free_list_(nullptr), blocks_per_pool_(blocks_per_pool)
{
    if (allocate_on_construct)
        ReloadAlloc();
}

template <std::size_t block_size>
inline void *StAllocPool<block_size>::alloc()
{
    if (free_list_ == nullptr)
        ReloadAlloc();

    PoolElement *elem = free_list_;
    free_list_ = free_list_->next;
    return &elem->data;
}

template <std::size_t block_size>
inline void StAllocPool<block_size>::free(void *block) noexcept
{
    // Recover the PoolElement from the data pointer
    auto *elem = reinterpret_cast<PoolElement *>(
        reinterpret_cast<std::uintptr_t>(block) - offsetof(PoolElement, data));

    // Push to front of free list
    elem->next = free_list_;
    free_list_ = elem;
}

template <std::size_t block_size>
inline std::size_t StAllocPool<block_size>::total_blocks() const noexcept
{
    return pools_.size() * blocks_per_pool_;
}

template <std::size_t block_size>
inline std::size_t StAllocPool<block_size>::pool_count() const noexcept
{
    return pools_.size();
}

template <std::size_t block_size>
inline constexpr std::size_t StAllocPool<block_size>::blocks_per_pool() const noexcept
{
    return blocks_per_pool_;
}

template <std::size_t block_size>
inline constexpr std::size_t StAllocPool<block_size>::alloc_size() const noexcept
{
    return block_size;
}

template <std::size_t block_size>
inline void StAllocPool<block_size>::ReloadAlloc()
{
    auto pool = std::make_unique<PoolElement[]>(blocks_per_pool_);

    // Link all elements into the free list (in reverse order to maintain order)
    for (int i = static_cast<int>(blocks_per_pool_) - 1; i >= 0; --i)
    {
        pool[i].next = free_list_;
        free_list_ = &pool[i];
    }

    // Store the pool chunk (transfers ownership to pools_ vector)
    pools_.push_back(std::move(pool));
}

} // namespace clv

#endif // CLVLIB_CORE_ST_ALLOC_POOL_H
