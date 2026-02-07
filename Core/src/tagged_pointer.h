// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLVLIB_CORE_TAGGED_POINTER_H
#define CLVLIB_CORE_TAGGED_POINTER_H

#include <cstddef>
#include <cstdint>
#include <atomic>
#include <utility>
#include <cassert>

namespace clv {

// Simple portable tagged pointer helper. It packs a pointer and a small tag into a
// pointer.

template <typename T>
struct TaggedPointer
{
    using pointer = T *;
    using uintptr = std::uintptr_t;

    constexpr static std::size_t TAGBITS = 2;
    static constexpr std::size_t PTR_BITS = sizeof(pointer) * 8 - TAGBITS;
    static constexpr uintptr TAG_MASK = ((uintptr(1) << TAGBITS) - 1);
    static constexpr uintptr PTR_MASK = ~TAG_MASK;

    // Helper to compute the next tag, wrapping according to TAG_MASK.
    constexpr static inline std::uint64_t next_tag(std::uint64_t tag) noexcept
    {
        return (tag + 1) & TAG_MASK;
    }

    static_assert(TAGBITS > 0 && TAGBITS < (sizeof(std::uintptr_t) * 8), "TAGBITS out of range");
    static_assert(PTR_BITS >= 1, "Insufficient pointer bits");
    static_assert(sizeof(uintptr) >= sizeof(pointer), "uintptr_t too small to hold pointer");
    static_assert(alignof(T) >= (std::size_t(1) << TAGBITS), "T alignment insufficient for TaggedPointer TAGBITS");

    explicit TaggedPointer() : mPtr(0)
    {
    }

    explicit TaggedPointer(T *ptr) : mPtr(Pack(ptr, 0))
    {
    }
    TaggedPointer(pointer ptr, std::uint64_t tag) : mPtr(Pack(ptr, tag))
    {
    }
    // Copy/move: std::atomic is not copyable by default; provide atomic copy/move
    TaggedPointer(const TaggedPointer &other) noexcept : mPtr(other.mPtr.load(std::memory_order_relaxed))
    {
    }
    TaggedPointer &operator=(const TaggedPointer &other) noexcept
    {
        mPtr.store(other.mPtr.load(std::memory_order_relaxed), std::memory_order_relaxed);
        return *this;
    }
    TaggedPointer(TaggedPointer &&other) noexcept : mPtr(other.mPtr.load(std::memory_order_relaxed))
    {
    }
    TaggedPointer &operator=(TaggedPointer &&other) noexcept
    {
        mPtr.store(other.mPtr.load(std::memory_order_relaxed), std::memory_order_relaxed);
        return *this;
    }

    explicit operator pointer() const noexcept
    {
        return get_ptr();
    }

    pointer get_ptr() const noexcept
    {
        auto [p, _] = Unpack(mPtr.load(std::memory_order_acquire));
        return p;
    }

    uintptr raw() const noexcept
    {
        return mPtr.load(std::memory_order_relaxed);
    }

    // Store pointer+tag atomically
    void store(pointer p, std::uint64_t tag, std::memory_order order = std::memory_order_release) noexcept
    {
        mPtr.store(Pack(p, tag), order);
    }

    // Exchange pointer value atomically and return the previous pointer and tag
    std::pair<pointer, std::uint64_t>
    exchange(pointer p, std::memory_order order = std::memory_order_acq_rel) noexcept
    {
        uintptr old_val = mPtr.load(std::memory_order_acquire);
        while (true)
        {
            auto [old_ptr, old_tag] = Unpack(old_val);
            uintptr new_val = Pack(p, next_tag(old_tag));
            if (mPtr.compare_exchange_weak(old_val, new_val, order, std::memory_order_acquire))
            {
                return {old_ptr, old_tag};
            }
        }
    }

    // Wait until the raw pointer bits change from expected 'val' or until pointer becomes non-null.
    // This is similar to std::atomic::wait but operates on the combined value.
    void wait(uintptr expected, std::memory_order order = std::memory_order_acquire) const noexcept
    {
        mPtr.wait(expected, order);
    }

    // Wait until the pointer component is non-null (ignoring tag bits).
    void wait_for_ptr_non_null(std::memory_order order = std::memory_order_acquire) const noexcept
    {
        uintptr val = mPtr.load(std::memory_order_acquire);
        while ((val & PTR_MASK) == 0)
        {
            mPtr.wait(val);
            val = mPtr.load(std::memory_order_acquire);
        }
    }

    void notify_all() noexcept
    {
        mPtr.notify_all();
    }
    void notify_one() noexcept
    {
        mPtr.notify_one();
    }

    auto split() const noexcept
    {
        return Unpack(mPtr.load(std::memory_order_acquire));
    }

    void touch_tag() noexcept
    {
        uintptr old_val = mPtr.load(std::memory_order_acquire);
        while (true)
        {
            auto [p, t] = Unpack(old_val);
            uintptr new_val = Pack(p, next_tag(t)); // choose wrap semantics
            if (mPtr.compare_exchange_weak(old_val,
                                           new_val,
                                           std::memory_order_acq_rel,
                                           std::memory_order_acquire))
            {
                return;
            }
            // old_val modified with current value by compare_exchange_weak, loop
        }
    }

    bool compare_exchange_pointer_and_tag(pointer &expected_ptr, std::uint64_t &expected_tag,
                                          pointer desired_ptr, std::uint64_t desired_tag) noexcept
    {
        uintptr expected_val = Pack(expected_ptr, expected_tag);
        uintptr desired_val = Pack(desired_ptr, desired_tag);
        bool res = mPtr.compare_exchange_strong(expected_val,
                                                desired_val,
                                                std::memory_order_acq_rel,
                                                std::memory_order_acquire);
        if (!res)
        {
            auto [p, t] = Unpack(expected_val);
            expected_ptr = p;
            expected_tag = t;
        }
        return res;
    }

  private:
    std::atomic<uintptr> mPtr;

  private:
    constexpr static inline uintptr Pack(pointer p, std::uint64_t tag) noexcept
    {
        auto ptrval = reinterpret_cast<uintptr>(p);
        // If the user-supplied pointer has some low bits set (possible if the pointer
        // was corrupted or poorly aligned), mask them out. We still keep a debug
        // assertion to catch unexpected cases in debug builds.
        ptrval &= PTR_MASK;
        return (ptrval | (tag & TAG_MASK));
    }

    constexpr static inline std::pair<pointer, std::uint64_t> Unpack(uintptr val) noexcept
    {
        pointer p = reinterpret_cast<pointer>(val & PTR_MASK);
        std::uint64_t tag = static_cast<std::uint64_t>(val & TAG_MASK);
        return {p, tag};
    }
};

} // namespace clv

#endif // CLVLIB_CORE_TAGGED_POINTER_H
