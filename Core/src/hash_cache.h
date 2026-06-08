// Copyright (c) 2023- Charlie Vigue. All rights reserved.

#ifndef CLV_CORE_HASH_CACHE_H
#define CLV_CORE_HASH_CACHE_H

#include <array>
#include <bit>
#include <cstddef>

namespace clv {

template <typename KeyT, typename ValueT, typename HashT, size_t min_cap>
struct HashCache
{
    ValueT &operator[](KeyT k) noexcept
    {
        return mCache[i_mask & mHasher(k)];
    }
    const ValueT &operator[](KeyT k) const noexcept
    {
        return mCache[i_mask & mHasher(k)];
    }
    size_t capacity() const noexcept
    {
        return capacity_limit;
    }

  private:
    static constexpr size_t capacity_limit = (size_t(1) << std::bit_width(min_cap - 1));
    static constexpr size_t i_mask = capacity_limit - 1;

  private:
    using TableT = std::array<ValueT, capacity_limit>;

  private:
    TableT mCache;
    HashT mHasher;
};

} // namespace clv

#endif // CLV_CORE_HASH_CACHE_H
