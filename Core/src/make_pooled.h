// Copyright (c) 2023- Charlie Vigue. All rights reserved.


#ifndef CLVLIB_CORE_MAKEPOOLED_H
#define CLVLIB_CORE_MAKEPOOLED_H

#include <cstddef>
#include <utility>

namespace clv {

/**
 * @brief MakePooled enables pooled allocation for an existing type.
 *
 * The MakePooled template enables pooled allocation for an existing type (TypeT) using
 * a specified memory pool provider. It overrides the new and delete operators to allocate
 * and free instances from the pool, enabling fast allocation and deallocation of many
 * small objects of TypeT.
 *
 * MakePooled inherits from TypeT and forwards arguments to TypeT's constructor.
 *
 * The overridden new operator checks if the requested size matches the pool's block size.
 * If so, it allocates a block from the pool. Otherwise, it defers to the default new operator.
 *
 * The overridden delete operator checks if the deleted block size matches the pool's
 * block size. If so, it frees the block to the pool. Otherwise, it defers to the default
 * delete operator.
 *
 * A static pool member (mPool) is used to manage the memory pool. The pool type is specified
 * via the PoolProviderT template template parameter.
 *
 * @tparam TypeT The type to enable pooled allocation for.
 * @tparam PoolProviderT A template template parameter for the pool (e.g., StAllocPool, AllocPool).
 *                        Must be a template parameterized by block_size.
 * @tparam BlocksPerPool The number of objects to allocate per pool chunk (default 256).
 *
 * Example usage:
 *   struct MyData { int x; int y; };
 *   using PooledMyData = MakePooled<MyData, StAllocPool, 64>;
 *   auto ptr = new PooledMyData(10, 20);
 *   delete ptr;  // Returns to pool
 */
template <typename TypeT, template <std::size_t> typename PoolProviderT, std::size_t BlocksPerPool = 256>
struct MakePooled : TypeT
{
    template <typename... ArgsT>
    MakePooled(ArgsT &&...args) noexcept(noexcept(TypeT(std::forward<ArgsT>(args)...)))
        : TypeT(std::forward<ArgsT>(args)...)
    {
    }

    static void *operator new(std::size_t cnt)
    {
        if (cnt != mPool.alloc_size())
            return ::operator new(cnt);
        return mPool.alloc();
    }

    static void operator delete(void *ptr, std::size_t sz)
    {
        if (sz != mPool.alloc_size())
            ::operator delete(ptr);
        else
            mPool.free(ptr);
    }

  public: // Pooling API
    /// @brief Query the number of pool chunks allocated.
    static std::size_t Pool_PoolCount() noexcept
    {
        return mPool.pool_count();
    }

    /// @brief Query the total number of blocks across all pool chunks.
    static std::size_t Pool_TotalBlocks() noexcept
    {
        return mPool.total_blocks();
    }

  private:
    inline static PoolProviderT<sizeof(TypeT)> mPool{BlocksPerPool};
};

} // namespace clv

#endif // CLVLIB_CORE_MAKEPOOLED_H
