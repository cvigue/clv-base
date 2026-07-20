// Copyright (c) 2023- Charlie Vigue. All rights reserved.

#ifndef CLV_CORE_LRU_CACHE_H
#define CLV_CORE_LRU_CACHE_H

#include <cstddef>
#include <list>
#include <optional>
#include <unordered_map>
#include <utility>

#include "optional_ref.h"

namespace clv {

/**
    @brief A simple LRU cache implementation
    @tparam KeyT The key type, must have well defined equality semantics and be hashable
    @tparam ValueT The value type, must be copyable or movable
    @tparam HashT Hash functor for @c KeyT (defaults to @c std::hash)

    Recency order is MRU at the front of the internal list and LRU at the back.
    @c get / @c put / @c touch promote to MRU; @c peek / @c update do not.
*/
template <typename KeyT, typename ValueT, typename HashT = std::hash<KeyT>>
class LruCache
{
    using Node = std::pair<KeyT, ValueT>; // Key-value pair
    std::list<Node> mCache;
    std::unordered_map<KeyT, typename std::list<Node>::iterator, HashT> mMap;
    const size_t mCapacity;
    std::optional<KeyT> mPinnedKey;

    void trim_one() noexcept;
    [[nodiscard]] std::optional<Node> extract_lru_victim() noexcept;

  public:
    /**
        @brief Construct a new Lru Cache object
        @param capacity The maximum number of elements the cache can hold.
    */
    explicit LruCache(size_t capacity);

    /**
        @brief Optional key that is skipped during LRU eviction (e.g. local identity).
    */
    void set_pinned_key(std::optional<KeyT> pinned) noexcept;

    [[nodiscard]] size_t size() const noexcept;

    [[nodiscard]] size_t capacity() const noexcept;

    /**
        @brief Get a reference to the value associated with the key
        @param key The key to search for
        @return A reference to the value associated with the key if it exists,
                otherwise std::nullopt
        @note This allows the value to be updated in place
    */
    [[nodiscard]] optional_ref<ValueT &> get(const KeyT &key) noexcept;

    /**
        @brief Get a reference to the value associated with the key
        @param key The key to search for
        @return A reference to the value associated with the key if it exists,
                otherwise std::nullopt
        @note This allows the value to be inspected without changing the MRU order
    */
    [[nodiscard]] optional_ref<const ValueT &> peek(const KeyT &key) const noexcept;

    /**
        @brief Promote @p key to MRU without changing its value.
        @return false if @p key is not present.
    */
    bool touch(const KeyT &key) noexcept;

    /**
        @brief Replace the value for @p key without changing LRU order.
        @return false if @p key is not present.
    */
    bool update(const KeyT &key, ValueT &&value) noexcept;

    /**
        @brief Replace the value for @p key without changing LRU order.
        @return false if @p key is not present.
    */
    bool update(const KeyT &key, const ValueT &value) noexcept;

    /**
        @brief Remove @p key if present.
        @return true when an entry was removed.
    */
    bool erase(const KeyT &key) noexcept;

    /**
        @brief Remove all entries. Capacity and pinned key are unchanged.
    */
    void clear() noexcept;

    /**
        @brief Put a key-value pair into the cache
        @param key The key to create or update
        @param value The value to associate with the key
        @return true if the key existed and was updated, false if the key was created
    */
    bool put(const KeyT &key, ValueT &&value) noexcept;

    /**
        @brief Put a moved key-value pair into the cache
        @return true if the key existed and was updated, false if the key was created
    */
    bool put(KeyT &&key, ValueT &&value) noexcept;

    /**
        @brief Put a key-value pair into the cache
        @param key The key to create or update
        @param value The value to associate with the key
        @return true if the key existed and was updated, false if the key was created
    */
    bool put(const KeyT &key, const ValueT &value) noexcept;

    /**
        @brief Insert or replace like @c put, returning any entry trimmed for capacity.
        @return The evicted (key, value) when a novel insert forced an LRU trim;
                @c std::nullopt on update-of-existing or when no trim occurred.
    */
    [[nodiscard]] std::optional<std::pair<KeyT, ValueT>> put_reporting_eviction(const KeyT &key,
                                                                                ValueT &&value) noexcept;

    /**
        @brief Insert or replace like @c put, returning any entry trimmed for capacity.
    */
    [[nodiscard]] std::optional<std::pair<KeyT, ValueT>> put_reporting_eviction(KeyT &&key,
                                                                                ValueT &&value) noexcept;

    /**
        @brief Visit entries from MRU to LRU.
        @param fn Invoked as @c fn(const KeyT&, const ValueT&) for each entry.
    */
    template <typename Fn>
    void for_each(Fn &&fn) const
    {
        for (const auto &node : mCache)
            fn(node.first, node.second);
    }

    /**
        @brief Visit entries from LRU to MRU.
        @param fn Invoked as @c fn(const KeyT&, const ValueT&) for each entry.
    */
    template <typename Fn>
    void for_each_lru_first(Fn &&fn) const
    {
        for (auto it = mCache.rbegin(); it != mCache.rend(); ++it)
            fn(it->first, it->second);
    }

    /**
        @brief Get a reference to the value associated with the key
        @param key The key to search for
        @return A reference to the value associated with the key if it exists,
                otherwise std::nullopt
        @note This allows the value to be updated in place
    */
    [[nodiscard]] optional_ref<ValueT &> operator[](const KeyT &key) noexcept;
};

template <typename KeyT, typename ValueT, typename HashT>
std::optional<typename LruCache<KeyT, ValueT, HashT>::Node>
LruCache<KeyT, ValueT, HashT>::extract_lru_victim() noexcept
{
    if (mCache.empty())
        return std::nullopt;

    for (auto it = mCache.end(); it != mCache.begin();)
    {
        --it;
        if (mPinnedKey && it->first == *mPinnedKey)
            continue;

        Node out = std::move(*it);
        mMap.erase(out.first);
        mCache.erase(it);
        return out;
    }

    // Every entry is pinned — evict LRU anyway.
    Node out = std::move(mCache.back());
    mMap.erase(out.first);
    mCache.pop_back();
    return out;
}

template <typename KeyT, typename ValueT, typename HashT>
void LruCache<KeyT, ValueT, HashT>::trim_one() noexcept
{
    (void)extract_lru_victim();
}

template <typename KeyT, typename ValueT, typename HashT>
LruCache<KeyT, ValueT, HashT>::LruCache(size_t capacity)
    : mCapacity(capacity ? capacity : 1)
{
}

template <typename KeyT, typename ValueT, typename HashT>
void LruCache<KeyT, ValueT, HashT>::set_pinned_key(std::optional<KeyT> pinned) noexcept
{
    mPinnedKey = std::move(pinned);
}

template <typename KeyT, typename ValueT, typename HashT>
size_t LruCache<KeyT, ValueT, HashT>::size() const noexcept
{
    return mCache.size();
}

template <typename KeyT, typename ValueT, typename HashT>
size_t LruCache<KeyT, ValueT, HashT>::capacity() const noexcept
{
    return mCapacity;
}

template <typename KeyT, typename ValueT, typename HashT>
optional_ref<ValueT &> LruCache<KeyT, ValueT, HashT>::get(const KeyT &key) noexcept
{
    if (auto it = mMap.find(key); it != mMap.end())
    {
        mCache.splice(mCache.begin(), mCache, it->second);
        return it->second->second;
    }
    return std::nullopt;
}

template <typename KeyT, typename ValueT, typename HashT>
optional_ref<const ValueT &> LruCache<KeyT, ValueT, HashT>::peek(const KeyT &key) const noexcept
{
    auto it = mMap.find(key);
    return it != mMap.end() ? optional_ref<const ValueT &>(it->second->second)
                            : optional_ref<const ValueT &>(std::nullopt);
}

template <typename KeyT, typename ValueT, typename HashT>
bool LruCache<KeyT, ValueT, HashT>::touch(const KeyT &key) noexcept
{
    auto it = mMap.find(key);
    if (it == mMap.end())
        return false;

    mCache.splice(mCache.begin(), mCache, it->second);
    return true;
}

template <typename KeyT, typename ValueT, typename HashT>
bool LruCache<KeyT, ValueT, HashT>::update(const KeyT &key, ValueT &&value) noexcept
{
    auto it = mMap.find(key);
    if (it == mMap.end())
        return false;

    it->second->second = std::move(value);
    return true;
}

template <typename KeyT, typename ValueT, typename HashT>
bool LruCache<KeyT, ValueT, HashT>::update(const KeyT &key, const ValueT &value) noexcept
{
    return update(key, ValueT(value));
}

template <typename KeyT, typename ValueT, typename HashT>
bool LruCache<KeyT, ValueT, HashT>::erase(const KeyT &key) noexcept
{
    auto it = mMap.find(key);
    if (it == mMap.end())
        return false;

    mCache.erase(it->second);
    mMap.erase(it);
    return true;
}

template <typename KeyT, typename ValueT, typename HashT>
void LruCache<KeyT, ValueT, HashT>::clear() noexcept
{
    mCache.clear();
    mMap.clear();
}

template <typename KeyT, typename ValueT, typename HashT>
std::optional<std::pair<KeyT, ValueT>>
LruCache<KeyT, ValueT, HashT>::put_reporting_eviction(const KeyT &key, ValueT &&value) noexcept
{
    if (auto it = mMap.find(key); it != mMap.end())
    {
        mCache.splice(mCache.begin(), mCache, it->second);
        it->second->second = std::move(value);
        return std::nullopt;
    }

    std::optional<std::pair<KeyT, ValueT>> evicted;
    if (mCache.size() >= mCapacity)
        evicted = extract_lru_victim();

    mCache.emplace_front(key, std::move(value));
    mMap[key] = mCache.begin();
    return evicted;
}

template <typename KeyT, typename ValueT, typename HashT>
std::optional<std::pair<KeyT, ValueT>>
LruCache<KeyT, ValueT, HashT>::put_reporting_eviction(KeyT &&key, ValueT &&value) noexcept
{
    if (auto it = mMap.find(key); it != mMap.end())
    {
        mCache.splice(mCache.begin(), mCache, it->second);
        it->second->second = std::move(value);
        return std::nullopt;
    }

    std::optional<std::pair<KeyT, ValueT>> evicted;
    if (mCache.size() >= mCapacity)
        evicted = extract_lru_victim();

    KeyT stored_key = std::move(key);
    mCache.emplace_front(std::move(stored_key), std::move(value));
    mMap[mCache.front().first] = mCache.begin();
    return evicted;
}

template <typename KeyT, typename ValueT, typename HashT>
bool LruCache<KeyT, ValueT, HashT>::put(const KeyT &key, ValueT &&value) noexcept
{
    const bool existed = mMap.find(key) != mMap.end();
    (void)put_reporting_eviction(key, std::move(value));
    return existed;
}

template <typename KeyT, typename ValueT, typename HashT>
bool LruCache<KeyT, ValueT, HashT>::put(KeyT &&key, ValueT &&value) noexcept
{
    const bool existed = mMap.find(key) != mMap.end();
    (void)put_reporting_eviction(std::move(key), std::move(value));
    return existed;
}

template <typename KeyT, typename ValueT, typename HashT>
optional_ref<ValueT &> LruCache<KeyT, ValueT, HashT>::operator[](const KeyT &key) noexcept
{
    return get(key);
}

template <typename KeyT, typename ValueT, typename HashT>
bool LruCache<KeyT, ValueT, HashT>::put(const KeyT &key, const ValueT &value) noexcept
{
    return put(key, ValueT(value));
}

} // namespace clv

#endif // CLV_CORE_LRU_CACHE_H
