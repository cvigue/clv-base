//

#ifndef CLV_CORE_STATIC_VECTOR_H
#define CLV_CORE_STATIC_VECTOR_H

#include <cstddef>
#include <array>
#include <span>
#include <stdexcept>
#include <type_traits>
#include <vector>

namespace clv {

/**
 * @brief A thin wrapper around std::array to provide vector-like interface for fixed-capacity buffers.
 *
 * Restricted to trivially destructible types because shrink operations (resize, clear, pop_back)
 * do not call destructors — elements simply become inaccessible by adjusting mSize.
 * This is safe and zero-cost for trivial types (char, uint8_t, int, POD structs, etc.).
 */
template <typename T, size_t N>
    requires std::is_trivially_destructible_v<T>
class StaticVector
{
    std::array<T, N> mArray{};
    size_t mSize = 0;
    size_t mCapacity = N;

  public:
    using value_type = T;
    using size_type = size_t;
    using iterator = typename std::array<T, N>::iterator;
    using const_iterator = typename std::array<T, N>::const_iterator;

    StaticVector() = default;
    StaticVector(const StaticVector &) = default;
    StaticVector &operator=(const StaticVector &) = default;
    StaticVector(StaticVector &&) = default;
    StaticVector &operator=(StaticVector &&) = default;

    /// Constructor from iterator range
    template <typename InputIt>
    StaticVector(InputIt first, InputIt last)
        : mSize(0)
    {
        for (auto it = first; it != last; ++it)
        {
            if (mSize >= N)
                throw std::runtime_error("Iterator range exceeds fixed capacity");
            mArray[mSize++] = *it;
        }
        mCapacity = N;
    }

    /// Move constructor from std::vector (enables efficient conversion)
    StaticVector(std::vector<T> &&vec)
        : mSize(vec.size())
    {
        if (vec.size() > N)
            throw std::runtime_error("Vector size exceeds fixed capacity");
        std::copy(vec.begin(), vec.end(), mArray.begin());
        mCapacity = N;
    }

    constexpr size_type size() const noexcept
    {
        return mSize;
    }
    constexpr size_type capacity() const noexcept
    {
        return mCapacity;
    }
    constexpr bool empty() const noexcept
    {
        return mSize == 0;
    }

    void resize(size_type new_size)
    {
        if (new_size > N)
            throw std::runtime_error("Cannot resize beyond fixed capacity");
        mSize = new_size;
        mCapacity = std::max(new_size, mCapacity);
    }

    void reserve(size_type new_cap)
    {
        if (new_cap > N)
            throw std::runtime_error("Cannot reserve beyond fixed capacity");
        mCapacity = new_cap;
    }

    constexpr size_type max_size() const noexcept
    {
        return N; // Fixed capacity
    }

    void push_back(const T &v)
    {
        if (mSize >= N)
            throw std::runtime_error("Capacity exceeded");
        mArray[mSize++] = v;
    }

    void pop_back()
    {
        if (mSize > 0)
            --mSize;
    }

    T &operator[](size_type i)
    {
        return mArray[i];
    }
    const T &operator[](size_type i) const
    {
        return mArray[i];
    }

    T &back()
    {
        return mArray[mSize - 1];
    }
    const T &back() const
    {
        return mArray[mSize - 1];
    }

    void clear()
    {
        mSize = 0;
    }

    T *data() noexcept
    {
        return mArray.data();
    }
    const T *data() const noexcept
    {
        return mArray.data();
    }

    /// Get span over used elements.
    std::span<T> span() noexcept
    {
        return std::span<T>(mArray.data(), mSize);
    }
    std::span<const T> span() const noexcept
    {
        return std::span<const T>(mArray.data(), mSize);
    }

    iterator begin() noexcept
    {
        return mArray.begin();
    }
    iterator end() noexcept
    {
        return mArray.begin() + mSize;
    }
    const_iterator begin() const noexcept
    {
        return mArray.begin();
    }
    const_iterator end() const noexcept
    {
        return mArray.begin() + mSize;
    }
    const_iterator cbegin() const noexcept
    {
        return begin();
    }
    const_iterator cend() const noexcept
    {
        return end();
    }
};


} // namespace clv

#endif // CLV_CORE_STATIC_VECTOR_H
