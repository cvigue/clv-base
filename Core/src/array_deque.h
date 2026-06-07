// Copyright (c) 2023- Charlie Vigue. All rights reserved.


#ifndef CLV_CORE_ARRAYDEQUE_H
#define CLV_CORE_ARRAYDEQUE_H

#include <cstddef>
#include <algorithm>
#include <stdexcept>
#include <vector>
#include <span>
#include <type_traits>
#include <utility>
#include <ranges>

namespace clv {

template <typename T>
concept IsCharacterType = std::is_same_v<std::remove_cv_t<T>, char>
                          || std::is_same_v<std::remove_cv_t<T>, signed char>
                          || std::is_same_v<std::remove_cv_t<T>, unsigned char>;

/**
    @brief a buffer implementation that provides dynamic resizing and manipulation of a sequence of elements

    The ArrayDeque class is a double-ended buffer (ArrayDeque) implementation that provides dynamic resizing
    and manipulation of a sequence of elements.

    Data layout [conceptual]:
    @verbatim
    |--------------|------------------ Buffered Data --------------------|--------------|
    ^-- headroom --^                                                     ^              ^
    ^              ^----- size ------------------------------------------^              ^
    ^                                                                    ^-- tailroom --^
    ^-- capacity -----------------------------------------------------------------------^
    ^                                                                                   ^
    ^----------------------------- Total Available Space -------------------------------^
    @endverbatim

    Data layout [as coded]:
    @verbatim
    |--------------|------------------ Buffered Data --------------------|--------------|
    ^--- mBegin ---^                                                     ^              ^
    ^-------------------- vector.size() ---------------------------------^              ^
    ^                                                                                   ^
    ^-- capacity() - vector.capacity() -------------------------------------------------^
    @endverbatim
*/
template <typename TypeT, typename ContainerT = std::vector<TypeT>>
struct ArrayDeque
{
    // Types
    using value_type = TypeT;                                   ///< Type of each element
    using size_type = typename ContainerT::size_type;           ///< Used for sizes and indexes
    using iterator = typename ContainerT::iterator;             ///< Container iterator
    using const_iterator = typename ContainerT::const_iterator; ///< container const iterator
    using view_type = std::span<value_type>;                    ///< Span view of the buffer
    using const_view_type = std::span<const value_type>;        ///< Span view of the buffer

    constexpr static size_type VIEW_TO_END = std::numeric_limits<size_type>::max();

    ArrayDeque();
    template <size_t sz>
    ArrayDeque(const value_type (&data)[sz])
        requires IsCharacterType<TypeT>;
    ArrayDeque(const value_type *data, size_type sz, size_type hr = 0, size_type tr = 0);
    ArrayDeque(size_type sz, size_type hr = 0, size_type tr = 0);
    ArrayDeque(const_view_type data, size_type hr = 0, size_type tr = 0);

    ArrayDeque(ArrayDeque &&) noexcept = default;
    ArrayDeque &operator=(ArrayDeque &&) = default;

    ArrayDeque(const ArrayDeque &) = default;
    ArrayDeque &operator=(const ArrayDeque &) = default;

    // Immutable API
    bool empty() const noexcept;
    size_type size() const noexcept;
    size_type capacity() const noexcept;
    constexpr size_type max_size() const noexcept;
    size_type available() const noexcept;
    size_type headroom() const noexcept;
    size_type tailroom() const noexcept;
    const value_type &front() const;
    const value_type &back() const;
    const value_type &operator[](const size_type i) const;
    const_iterator begin() const;
    const_iterator end() const;
    const_iterator cbegin() const;
    const_iterator cend() const;
    const value_type *data() const noexcept;
    template <typename ArrayLikeT>
        requires std::ranges::range<ArrayLikeT>
    bool operator==(const ArrayLikeT &other) const;
    template <typename ArrayLikeT>
        requires std::ranges::range<ArrayLikeT>
    auto operator<=>(const ArrayLikeT &other) const;

    // Mutable API
    void clear(const size_type headroom = 0) noexcept;
    value_type *align(const size_type alignment = 16u);
    void set_tailroom(const size_type req);
    void set_headroom(const size_type req);
    void push_front(const value_type, const size_type = 1);
    void push_back(const value_type);
    value_type &front();
    value_type &back();
    value_type pop_front();
    value_type pop_back();
    value_type &operator[](const size_type i);
    iterator begin();
    iterator end();
    view_type allocate(const size_type pos, const size_type req);
    view_type allocate(const_iterator pos, const size_type req);
    view_type allocate_head(const size_type req);
    view_type allocate_tail(const size_type req);
    void free(const size_type pos, const size_type req);
    void free(const_iterator pos, const size_type req);
    void free_head(const size_type req);
    void free_tail(const size_type req);
    value_type *data() noexcept;

    // Views
    const_view_type const_view() const noexcept;
    const_view_type const_view(size_type offset, size_type len = VIEW_TO_END) const noexcept;
    const_view_type const_view(const_iterator first, const_iterator last) const noexcept;
    const_view_type view() const noexcept;
    view_type view() noexcept;
    view_type view(size_type offset, size_type len = VIEW_TO_END) noexcept;
    view_type view(iterator first, iterator last) noexcept;

    // Implementation details
  private:
    void move_data(const_iterator first, const_iterator last, iterator dest);

    // Data
  private:
    size_type mBegin = 0; /**< The index of the first valid element in the buffer. */
    ContainerT mData;     /**< Using container as storage */
};
/**
   @brief Construct a new ArrayDeque<TypeT> object
   @tparam TypeT Type of the data elements
   @details This constructor creates an empty buffer with no free space.
 */
template <typename TypeT, typename ContainerT>
inline ArrayDeque<TypeT, ContainerT>::ArrayDeque()
    : ArrayDeque(0u)
{
}
/**
   @brief Construct a new ArrayDeque<TypeT> object
   @tparam TypeT Type of the data elements
   @param data The data to be copied into the buffer
   @param sz The size of the data area pointed to by data
   @param hr The amount of headroom to allocate
   @param tr The amount of tailroom to allocate
 */
template <typename TypeT, typename ContainerT>
ArrayDeque<TypeT, ContainerT>::ArrayDeque(const value_type *data,
                                          size_type sz,
                                          size_type hr,
                                          size_type tr)
    : ArrayDeque(sz, hr, tr)
{
    mData.resize(hr + sz);
    std::copy(data, data + sz, begin());
}
/**
   @brief Construct a new ArrayDeque<TypeT> object
   @tparam TypeT Type of the data elements
   @param sz The size of the buffer
   @param hr The amount of headroom to allocate
   @param tr The amount of tailroom to allocate
 */
template <typename TypeT, typename ContainerT>
inline ArrayDeque<TypeT, ContainerT>::ArrayDeque(size_type sz, size_type hr, size_type tr)
    : mBegin(hr), mData()
{
    mData.reserve(sz + hr + tr);
    mData.resize(hr);
}
/**
   @brief Construct a new ArrayDeque<TypeT> object
   @tparam TypeT Type of the data elements
   @param data The data to be copied into the buffer
   @param hr The amount of headroom to allocate
   @param tr The amount of tailroom to allocate
 */
template <typename TypeT, typename ContainerT>
inline ArrayDeque<TypeT, ContainerT>::ArrayDeque(const_view_type data, size_type hr, size_type tr)
    : mBegin(hr), mData()
{
    mData.reserve(data.size() + hr + tr);
    mData.resize(hr);
    mData.insert(mData.begin() + hr, data.begin(), data.end());
    // Headroom and tailroom already reserved.
}
/**
    @brief Construct a new ArrayDeque object
    @tparam TypeT Type of the data elements
    @tparam sz size of the data area pointed to by data
    @param data The data to be copied into the buffer
    @param sz The size of the data area pointed to by data
    @param hr The amount of headroom to allocate
    @param tr The amount of tailroom to allocate
    @details Removes terminating null character from the data since the C array is not
    decayed to a pointer.
*/
template <typename TypeT, typename ContainerT>
template <size_t sz>
ArrayDeque<TypeT, ContainerT>::ArrayDeque(const value_type (&data)[sz])
    requires IsCharacterType<TypeT>
    : ArrayDeque(data, sz - 1, 0u, 0u)
{
}
/**
   @brief Checks if the buffer is empty.
   @return true if the buffer is empty, false otherwise.
 */
template <typename TypeT, typename ContainerT>
bool ArrayDeque<TypeT, ContainerT>::empty() const noexcept
{
    return mBegin == mData.size();
}
/**
   @brief Returns the number of valid elements in the buffer.
   @return The size of the buffer.
 */
template <typename TypeT, typename ContainerT>
auto ArrayDeque<TypeT, ContainerT>::size() const noexcept -> size_type
{
    return mData.size() - mBegin;
}
/**
   @brief Returns the total capacity of the buffer.
   @return The capacity of the buffer.
 */
template <typename TypeT, typename ContainerT>
auto ArrayDeque<TypeT, ContainerT>::capacity() const noexcept -> size_type
{
    return mData.capacity();
}
/**
   @brief Returns the maximum size of the buffer.
   @return The maximum size of the buffer.
 */
template <typename TypeT, typename ContainerT>
auto constexpr ArrayDeque<TypeT, ContainerT>::max_size() const noexcept -> size_type
{
    return mData.max_size();
}
/**
   @brief Returns the unused capacity of the buffer.
   @return The available capacity of the buffer.
 */
template <typename TypeT, typename ContainerT>
auto ArrayDeque<TypeT, ContainerT>::available() const noexcept -> size_type
{
    return capacity() - size();
}
/**
   @brief Returns the headroom (empty space at the beginning) of the buffer.
   @return The empty space at the beginning of the buffer.
 */
template <typename TypeT, typename ContainerT>
auto ArrayDeque<TypeT, ContainerT>::headroom() const noexcept -> size_type
{
    return mBegin;
}
/**
   @brief Returns the tailroom (empty space at the end) of the buffer.
   @return The empty space at the end of the buffer.
 */
template <typename TypeT, typename ContainerT>
auto ArrayDeque<TypeT, ContainerT>::tailroom() const noexcept -> size_type
{
    return mData.capacity() - mData.size();
}
/**
   @brief Clears the buffer and sets the headroom (empty space at the beginning).
   @param headroom The amount of headroom to set.
   @return Reference to the modified ArrayDeque object.
 */
template <typename TypeT, typename ContainerT>
void ArrayDeque<TypeT, ContainerT>::clear(const size_type headroom) noexcept
{
    mData.clear();
    mData.resize(headroom);
    mBegin = headroom;
}
/**
   @brief Aligns the start of the data to an n byte boundary
   @param alignment n byte alignment request
   @details This is useful if, for instance, the buffer of bytes actually contains a data
   structure that requires or benefits from being aligned.
*/
template <typename TypeT, typename ContainerT>
auto ArrayDeque<TypeT, ContainerT>::align(const size_type alignment) -> value_type *
{
    auto origin_align = reinterpret_cast<size_type>(data()) % alignment;
    set_headroom(headroom() - origin_align); // Implicit assumption the underlying buffer is aligned
    return data();
}
/**
   @brief Sets the tailroom (empty space at the end) of the buffer.
          Resizes the buffer if necessary.
   @param req The amount of tailroom to set.
   @return Reference to the modified ArrayDeque object.
 */
template <typename TypeT, typename ContainerT>
void ArrayDeque<TypeT, ContainerT>::set_tailroom(const size_type req)
{
    mData.reserve(size() + headroom() + req);
}
/**
   @brief Sets the headroom (empty space at the beginning) of the buffer.
          Resizes the buffer if necessary.
   @param req The amount of headroom to set.
   @return Reference to the modified ArrayDeque object.
 */
template <typename TypeT, typename ContainerT>
void ArrayDeque<TypeT, ContainerT>::set_headroom(const size_type req)
{
    if (req > headroom())
    {
        size_type delta = req - mBegin;
        size_type original_size = size();
        mData.resize(mData.size() + delta);
        move_data(begin(), begin() + original_size, begin() + delta);
        mBegin = req;
    }
}
/**
   @brief Push the given value onto the front of the buffer, allocate space if possible.
   @return auto& Fluent reference to this
 */
template <typename TypeT, typename ContainerT>
void ArrayDeque<TypeT, ContainerT>::push_front(const value_type v, const size_type grow_hint)
{
    if (headroom() == 0)
        set_headroom(grow_hint ? grow_hint : 1);
    mData[--mBegin] = v;
}
/**
   @brief Push the given value onto the back of the buffer, allocate space if possible.
   @return auto& Fluent reference to this
 */
template <typename TypeT, typename ContainerT>
void ArrayDeque<TypeT, ContainerT>::push_back(const value_type v)
{
    mData.push_back(v);
}
/**
   @brief Return a const reference to the value on the front of the buffer
   @return const ArrayDeque<TypeT>::value_type&
 */
template <typename TypeT, typename ContainerT>
auto ArrayDeque<TypeT, ContainerT>::front() const -> const value_type &
{
    return *(mData.data() + mBegin);
}
/**
   @brief Return a const reference to the value on the back of the buffer
   @return const ArrayDeque<TypeT>::value_type&
 */
template <typename TypeT, typename ContainerT>
auto ArrayDeque<TypeT, ContainerT>::back() const -> const value_type &
{
    return mData.back();
}
/**
   @brief Return a reference to the value on the front of the buffer
   @return const ArrayDeque<TypeT>::value_type&
 */
template <typename TypeT, typename ContainerT>
auto ArrayDeque<TypeT, ContainerT>::front() -> value_type &
{
    return const_cast<typename ArrayDeque<TypeT, ContainerT>::value_type &>(std::as_const(*this).front());
}
/**
   @brief Return a reference to the value on the back of the buffer
   @return const ArrayDeque<TypeT>::value_type&
 */
template <typename TypeT, typename ContainerT>
auto ArrayDeque<TypeT, ContainerT>::back() -> value_type &
{
    return mData.back();
}
/**
   @brief Removes the front item from the buffer and returns it by value
   @return ArrayDeque<TypeT>::value_type
 */
template <typename TypeT, typename ContainerT>
auto ArrayDeque<TypeT, ContainerT>::pop_front() -> value_type
{
    if (empty())
        throw std::runtime_error("pop_front: Buffer underflow");
    return *(mData.data() + mBegin++);
}
/**
   @brief Removes the back item from the buffer and returns it by value
   @return ArrayDeque<TypeT>::value_type
 */
template <typename TypeT, typename ContainerT>
auto ArrayDeque<TypeT, ContainerT>::pop_back() -> value_type
{
    if (empty())
        throw std::runtime_error("pop_back: Buffer underflow");
    auto rv = mData.back();
    mData.pop_back();
    return rv;
}
/**
   @brief Accesses the element at the specified index in the buffer (const version).
   @param i The index of the element to access.
   @return Reference to the const element at the specified index.
 */
template <typename TypeT, typename ContainerT>
auto ArrayDeque<TypeT, ContainerT>::operator[](const size_type i) const -> const value_type &
{
    if (i < size())
        return *(data() + i);
    throw std::runtime_error(std::string("[") + std::to_string(i) + "]: Index out of bounds");
}
/**
   @brief Accesses the element at the specified index in the buffer.
   @param i The index of the element to access.
   @return Reference to the element at the specified index.
 */
template <typename TypeT, typename ContainerT>
auto ArrayDeque<TypeT, ContainerT>::operator[](const size_type i) -> value_type &
{
    return const_cast<typename ArrayDeque<TypeT, ContainerT>::value_type &>(std::as_const(*this)[i]);
}
/**
   @brief Returns a const iterator pointing to the beginning of the buffer.
   @return Const iterator pointing to the beginning of the buffer.
 */
template <typename TypeT, typename ContainerT>
auto ArrayDeque<TypeT, ContainerT>::cbegin() const -> const_iterator
{
    return mData.cbegin() + mBegin;
}
/**
   @brief Returns a const iterator pointing to the beginning of the buffer.
   @return Const iterator pointing to the beginning of the buffer.
 */
template <typename TypeT, typename ContainerT>
auto ArrayDeque<TypeT, ContainerT>::begin() const -> const_iterator
{
    return cbegin();
}
/**
   @brief Returns an iterator pointing to the beginning of the buffer.
   @return Iterator pointing to the beginning of the buffer.
 */
template <typename TypeT, typename ContainerT>
auto ArrayDeque<TypeT, ContainerT>::begin() -> iterator
{
    return mData.begin() + mBegin;
}
/**
   @brief Returns a const iterator pointing to the end of the buffer.
   @return Const iterator pointing to one past the end of the buffer.
 */
template <typename TypeT, typename ContainerT>
auto ArrayDeque<TypeT, ContainerT>::cend() const -> const_iterator
{
    return mData.cend();
}
/**
   @brief Returns a const iterator pointing to the end of the buffer.
   @return Const iterator pointing to one past the end of the buffer.
 */
template <typename TypeT, typename ContainerT>
auto ArrayDeque<TypeT, ContainerT>::end() const -> const_iterator
{
    return cend();
}
/**
   @brief Returns an iterator pointing to the end of the buffer.
   @return Iterator pointing to one past the end of the buffer.
 */
template <typename TypeT, typename ContainerT>
auto ArrayDeque<TypeT, ContainerT>::end() -> iterator
{
    return mData.end();
}
/**
   @brief Allocates space in the buffer at the specified position. Resizes the buffer
          if necessary.
   @details This is useful if some copy-like operation wishes to inject a known number
   of elements into the buffer at the given location. Examples might be a file read or
   socket recv if the size of the operation is known or bounded. If the actual elements
   read and copied ends up being less, we will need a free function to close that gap.

   @see free(const size_type pos, const size_type req)
   @see free(const const_iterator pos, const size_type req)

   @param pos The position in the buffer to allocate space within the active data.
   @param req The amount of space to allocate.
   @return view (std::span) of the allocated space.
   @throw std::runtime_error if the specified position is out of bounds.
 */
template <typename TypeT, typename ContainerT>
auto ArrayDeque<TypeT, ContainerT>::allocate(const size_type pos, const size_type req) -> view_type
{
    if (pos == 0)
        return allocate_head(req);
    if (pos == size())
        return allocate_tail(req);
    if (pos > mData.size())
        throw std::runtime_error(std::string("allocate(") + std::to_string(pos) + " ...) Out of bounds");

    // The general case - make a hole
    size_type original_size = mData.size();
    mData.resize(original_size + req);
    move_data(begin() + pos, begin() + original_size, begin() + pos + req);
    return view_type(data() + pos, req);
}
/**
    @brief Allocates space in the buffer at the specified position. Resizes the buffer
           if necessary.
    @details This is useful if some copy-like operation wishes to inject a known number
    of elements into the buffer at the given location. Examples might be a file read or
    socket recv if the size of the operation is known or bounded. If the actual elements
    read and copied ends up being less, we will need a free function to close that gap.
    @param pos The position in the buffer to allocate space within the active data.
    @param req The amount of space to allocate.
    @return view (std::span) of the allocated space.
*/
template <typename TypeT, typename ContainerT>
auto ArrayDeque<TypeT, ContainerT>::allocate(const_iterator pos, const size_type req) -> view_type
{
    return allocate(pos - begin(), req);
}
/**
    @brief Allocates space at the beginning of the buffer. Resizes the buffer if necessary.
    @tparam TypeT Type of the data elements
    @param req The amount of space to allocate.
    @return view (std::span) of the allocated space.
*/
template <typename TypeT, typename ContainerT>
auto ArrayDeque<TypeT, ContainerT>::allocate_head(const size_type req) -> view_type
{
    set_headroom(req);
    mBegin -= req;
    return view_type(data(), req);
}
/**
    @brief Allocates space at the end of the buffer. Resizes the buffer if necessary.
    @tparam TypeT Type of the data elements
    @param req The amount of space to allocate.
    @return view (std::span) of the allocated space.
*/
template <typename TypeT, typename ContainerT>
auto ArrayDeque<TypeT, ContainerT>::allocate_tail(const size_type req) -> view_type
{
    set_tailroom(req);
    auto rv = data() + size();
    mData.resize(mData.size() + req);
    return view_type(rv, req);
}
/**
    @brief Frees space in the buffer at the specified position.
    @tparam TypeT Type of the data elements
    @param pos The position in the buffer to free space within the active data.
    @param req The amount of space to free.
    @throw std::runtime_error if the specified position is out of bounds.
*/
template <typename TypeT, typename ContainerT>
void ArrayDeque<TypeT, ContainerT>::free(const size_type pos, const size_type req)
{
    if (pos == 0)
    {
        free_head(req);
        return;
    }
    if (pos == size())
    {
        free_tail(req);
        return;
    }
    if (mBegin + pos + req > mData.size())
        throw std::runtime_error("Out of bounds");
    else // General case - snip out the hole
    {
        auto source = begin() + pos + req;
        auto dest = begin() + pos;
        move_data(source, end(), dest);
        mData.resize(mData.size() - req);
    }
}
/**
    @brief Frees space in the buffer at the specified position.
    @tparam TypeT Type of the data elements
    @param pos The position in the buffer to free space within the active data.
    @param req The amount of space to free.
    @throw std::runtime_error if the specified position is out of bounds.
*/
template <typename TypeT, typename ContainerT>
void ArrayDeque<TypeT, ContainerT>::free(const_iterator pos, const size_type req)
{
    free(&*pos - data(), req);
}
/**
    @brief Frees space at the beginning of the buffer.
    @tparam TypeT Type of the data elements
    @param req The amount of space to free.
    @throw std::runtime_error if the size requested is more than available
*/
template <typename TypeT, typename ContainerT>
void ArrayDeque<TypeT, ContainerT>::free_head(const size_type req)
{
    if (req > size())
        throw std::runtime_error("Buffer underflow");
    mBegin += req;
}
/**
    @brief Frees space at the end of the buffer.
    @tparam TypeT Type of the data elements
    @param req The amount of space to free.
    @throw std::runtime_error if the size requested is more than available.
*/
template <typename TypeT, typename ContainerT>
void ArrayDeque<TypeT, ContainerT>::free_tail(const size_type req)
{
    if (req > size())
        throw std::runtime_error("Buffer underflow");
    mData.resize(mData.size() - req);
}
/**
   @brief Returns a mutable pointer to the first data in the buffer
   @return auto* pointer to first data in buffer or one past the end if buffer is empty
 */
template <typename TypeT, typename ContainerT>
auto ArrayDeque<TypeT, ContainerT>::data() noexcept -> value_type *
{
    return mData.data() + mBegin;
}
/**
   @brief Returns a const pointer to the first data in the buffer
   @return auto* pointer to first data in buffer or one past the end if buffer is empty
 */
template <typename TypeT, typename ContainerT>
auto ArrayDeque<TypeT, ContainerT>::data() const noexcept -> const value_type *
{
    return mData.data() + mBegin;
}
/**
    @brief Compare the contents of the buffer with another buffer
    @tparam ArrayLikeT Type of the other buffer
    @param other The other buffer to compare with
    @return auto The result of the comparison
*/
template <typename TypeT, typename ContainerT>
template <typename ArrayLikeT>
    requires std::ranges::range<ArrayLikeT>
bool ArrayDeque<TypeT, ContainerT>::operator==(const ArrayLikeT &other) const
{
    return std::ranges::equal(*this, other);
}
/**
    @brief Compare the contents of the buffer with another buffer
    @tparam ArrayLikeT Type of the other buffer
    @param other The other buffer to compare with
    @return auto The result of the comparison
*/
template <typename TypeT, typename ContainerT>
template <typename ArrayLikeT>
    requires std::ranges::range<ArrayLikeT>
auto ArrayDeque<TypeT, ContainerT>::operator<=>(const ArrayLikeT &other) const
{
    return std::lexicographical_compare_three_way(begin(), end(), other.begin(), other.end());
}
/**
   @brief Returns a const view of the buffer
   @return const_view_type
 */
template <typename TypeT, typename ContainerT>
auto ArrayDeque<TypeT, ContainerT>::const_view() const noexcept -> const_view_type
{
    return const_view_type(data(), size());
}
template <typename TypeT, typename ContainerT>
auto ArrayDeque<TypeT, ContainerT>::const_view(size_type offset,
                                               size_type len) const noexcept -> const_view_type
{
    offset = std::clamp(offset, size_type(0u), size());
    len = std::clamp(len, size_type(0u), size() - offset);
    return const_view_type(data() + offset, len);
}
template <typename TypeT, typename ContainerT>
auto ArrayDeque<TypeT, ContainerT>::const_view(const_iterator first,
                                               const_iterator last) const noexcept -> const_view_type
{
    auto offset = std::distance(cbegin(), first);
    auto len = std::distance(first, last);
    return const_view_type(data() + offset, len);
}
/**
   @brief Returns a const view of the buffer
   @return const_view_type
 */
template <typename TypeT, typename ContainerT>
auto ArrayDeque<TypeT, ContainerT>::view() const noexcept -> const_view_type
{
    return const_view();
}
/**
   @brief Returns a mutable view of the buffer
   @return view_type
 */
template <typename TypeT, typename ContainerT>
auto ArrayDeque<TypeT, ContainerT>::view() noexcept -> view_type
{
    return view_type(data(), size());
}
/**
   @brief Returns a mutable view of the buffer
   @return view_type
 */
template <typename TypeT, typename ContainerT>
auto ArrayDeque<TypeT, ContainerT>::view(size_type offset,
                                         size_type len) noexcept -> view_type
{
    offset = std::clamp(offset, size_type(0u), size());
    len = std::clamp(len, size_type(0u), size() - offset);
    return view_type(data() + offset, len);
}
/**
    @brief Returns a mutable view of the buffer
    @tparam TypeT Type of the data elements
    @param first beginning of the view
    @param last end of the view
    @return view (std::span) of the buffer
*/
template <typename TypeT, typename ContainerT>
inline auto ArrayDeque<TypeT, ContainerT>::view(iterator first, iterator last) noexcept -> view_type
{
    auto offset = std::distance(begin(), first);
    auto len = std::distance(first, last);
    return view_type(data() + offset, len);
}
/**
   @brief Does either std::move or std::move_backward on the buffer contents depending on which is safe
   @param first First item to move
   @param last  Last item to move
   @param dest  Destination
 */
template <typename TypeT, typename ContainerT>
void ArrayDeque<TypeT, ContainerT>::move_data(const_iterator first, const_iterator last, iterator dest)
{
    if (dest > first)
        std::move_backward(first, last, std::next(dest, std::distance(first, last)));
    else
        std::move(first, last, dest);
}

} // namespace clv

#endif // CLV_CORE_ARRAYDEQUE_H
