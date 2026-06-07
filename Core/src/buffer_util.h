// Copyright (c) 2023- Charlie Vigue. All rights reserved.


#ifndef CLV_CORE_BUFFER_UTIL_H
#define CLV_CORE_BUFFER_UTIL_H

#include <algorithm>

#include "array_deque.h"

namespace clv {

/**
 * @brief Insert the designated data into the designated buffer
 *
 * Example:
 * ...
 * char data[] = "\1\2\3\4\5";
 * auto buffer = ArrayDeque<char>(BufferT::Allocated(), data, sizeof(data) - 1);
 * insert(buffer, data, data + sizeof(data) - 1, buffer.begin() + 3);
 * ...
 * Buffer starts with 12345, then has 12345 inserted before index 3 to end up with 1231234545
 *
 * @tparam TypeT    The type that we are storing in the buffer
 * @tparam ContainerT The container type
 * @tparam InIterT  Input iterator
 * @tparam OutIterT Output iterator
 * @param buffer ArrayDeque<TypeT, ContainerT>, The buffer to work on
 * @param first  start of data to insert
 * @param last   one past the end of data to insert
 * @param insertion_point point before which the data should be inserted
 * @return copy of the modified buffer
 */
template <typename TypeT,
          typename ContainerT,
          typename InIterT,
          typename OutIterT>
auto insert(ArrayDeque<TypeT, ContainerT> &&buffer,
            InIterT first,
            InIterT last,
            OutIterT insertion_point) -> ArrayDeque<TypeT, ContainerT>
{
    std::copy(first, last, buffer.allocate(insertion_point, static_cast<std::size_t>(last - first)));
    return buffer;
}

/**
 * @brief Insert the designated data into the designated buffer
 *
 * Example:
 * ...
 * char data[] = "\1\2\3\4\5";
 * auto buffer = ArrayDeque<char>(BufferT::Allocated(), data, sizeof(data) - 1);
 * insert(buffer, data, data + sizeof(data) - 1, buffer.begin() + 3);
 * ...
 * Buffer starts with 12345, then has 12345 inserted before index 3 to end up with 1231234545
 *
 * @tparam TypeT    The type that we are storing in the buffer
 * @tparam ContainerT The container type
 * @tparam InIterT  Input iterator
 * @tparam OutIterT Output iterator
 * @param buffer ArrayDeque<TypeT, ContainerT>, The buffer to work on
 * @param first  start of data to insert
 * @param last   one past the end of data to insert
 * @param insertion_point point before which the data should be inserted
 * @return reference to the modified buffer
 */
template <typename TypeT,
          typename ContainerT,
          typename InIterT,
          typename OutIterT>
auto insert(ArrayDeque<TypeT, ContainerT> &buffer,
            InIterT first,
            InIterT last,
            OutIterT insertion_point) -> ArrayDeque<TypeT, ContainerT> &
{
    std::copy(first, last, buffer.allocate(insertion_point, static_cast<std::size_t>(last - first)));
    return buffer;
}

/**
 * @brief Prepends the given data to the buffer
 *
 * @tparam TypeT    The type that we are storing in the buffer
 * @tparam ContainerT The container type
 * @tparam InIterT  Input iterator
 * @param buffer ArrayDeque<TypeT, ContainerT>, The buffer to work on
 * @param first  start of data to insert
 * @param last   one past the end of data to insert
 * @return copy of the modified buffer
 */
template <typename TypeT,
          typename ContainerT,
          typename InIterT>
auto prepend(ArrayDeque<TypeT, ContainerT> &&buffer,
             InIterT first,
             InIterT last) -> ArrayDeque<TypeT, ContainerT>
{
    std::copy(first, last, buffer.allocate_head(static_cast<std::size_t>(last - first)));
    return buffer;
}

/**
 * @brief Prepends the given data to the buffer
 *
 * @tparam TypeT    The type that we are storing in the buffer
 * @tparam ContainerT The container type
 * @tparam InIterT  Input iterator
 * @param buffer ArrayDeque<TypeT, ContainerT>, The buffer to work on
 * @param first  start of data to insert
 * @param last   one past the end of data to insert
 * @return reference to the modified buffer
 */
template <typename TypeT,
          typename ContainerT,
          typename InIterT>
auto prepend(ArrayDeque<TypeT, ContainerT> &buffer,
             InIterT first,
             InIterT last) -> ArrayDeque<TypeT, ContainerT> &
{
    std::copy(first, last, buffer.allocate_head(static_cast<std::size_t>(last - first)));
    return buffer;
}

/**
 * @brief Append the specified data to the buffer
 * @tparam TypeT    The type that we are storing in the buffer
 * @tparam ContainerT The container type
 * @tparam InIterT  Input iterator
 * @param buffer ArrayDeque<TypeT, ContainerT>, The buffer to work on
 * @param first  start of data to insert
 * @param last   one past the end of data to insert
 * @return copy of the modified buffer
 */
template <typename TypeT,
          typename ContainerT,
          typename InIterT>
auto append(ArrayDeque<TypeT, ContainerT> &&buffer,
            InIterT first,
            InIterT last) -> ArrayDeque<TypeT, ContainerT>
{
    std::copy(first,
              last,
              buffer.allocate_tail(static_cast<std::size_t>(last - first)).data());
    return buffer;
}

/**
 * @brief Append the specified data to the buffer
 * @tparam TypeT    The type that we are storing in the buffer
 * @tparam ContainerT The container type
 * @tparam InIterT  Input iterator
 * @param buffer ArrayDeque<TypeT, ContainerT>, The buffer to work on
 * @param first  start of data to insert
 * @param last   one past the end of data to insert
 * @return reference to the modified buffer
 */
template <typename TypeT,
          typename ContainerT,
          typename InIterT>
auto append(ArrayDeque<TypeT, ContainerT> &buffer,
            InIterT first,
            InIterT last) -> ArrayDeque<TypeT, ContainerT> &
{
    std::copy(first,
              last,
              buffer.allocate_tail(static_cast<std::size_t>(last - first)).data());
    return buffer;
}

/**
 * @brief Append the specified data to the buffer
 * @tparam TypeT    The type that we are storing in the buffer
 * @tparam Container1T The container type for buffer
 * @tparam Container2T The container type for to_append
 * @param buffer ArrayDeque<TypeT, Container1T>, The buffer to work on
 * @param to_append ArrayDeque<TypeT, Container2T>, The buffer to append
 * @return reference to the modified buffer
 */
template <typename TypeT,
          typename Container1T,
          typename Container2T>
auto append(ArrayDeque<TypeT, Container1T> &buffer,
            const ArrayDeque<TypeT, Container2T> &to_append) -> ArrayDeque<TypeT, Container1T> &
{
    return append(buffer, to_append.begin(), to_append.end());
}
/**
    @brief Append the specified data to the buffer
    @tparam TypeT Type stored in the buffer
    @tparam ContainerT The container type
    @tparam StringLikeT a reference to a string like type
    @param buffer ArrayDeque<TypeT, ContainerT>, The buffer to work on
    @param to_append reference to the source string like object
    @return reference to the modified buffer
*/
template <typename TypeT,
          typename ContainerT,
          typename StringLikeT>
auto append(ArrayDeque<TypeT, ContainerT> &buffer,
            const StringLikeT &to_append) -> ArrayDeque<TypeT, ContainerT> &
{
    return append(buffer, to_append.begin(), to_append.end());
}

/**
   @brief Append the specified data to the buffer
   @tparam TypeT    The type that we are storing in the buffer
   @tparam ContainerT The container type
   @param buffer ArrayDeque<TypeT, ContainerT>, The buffer to work on
   @param data pointer to the source data
   @param len length of data
   @return copy of the modified buffer
*/
template <typename TypeT,
          typename ContainerT>
auto append(ArrayDeque<TypeT, ContainerT> &&buffer,
            const TypeT *data,
            std::size_t len) -> ArrayDeque<TypeT, ContainerT>
{
    std::copy(data, data + len, buffer.allocate_tail(len).data());
    return buffer;
}

/**
   @brief Append the specified data to the buffer
   @tparam TypeT    The type that we are storing in the buffer
   @tparam ContainerT The container type
   @param buffer ArrayDeque<TypeT, ContainerT>, The buffer to work on
   @param data pointer to the source data
   @param len length of data
   @return reference to the modified buffer
*/
template <typename TypeT,
          typename ContainerT>
auto append(ArrayDeque<TypeT, ContainerT> &buffer,
            const TypeT *data,
            std::size_t len) -> ArrayDeque<TypeT, ContainerT> &
{
    std::copy(data, data + len, buffer.allocate_tail(len).data());
    return buffer;
}

/**
   @brief Append the specified data to the buffer
   @tparam TypeT    The type that we are storing in the buffer
   @tparam ContainerT The container type
   @tparam N count of elements in the source array
   @param buffer ArrayDeque<TypeT, ContainerT>, The buffer to work on
   @param data reference to the source array
   @return copy of the modified buffer
*/
template <typename TypeT,
          typename ContainerT,
          std::size_t N>
auto append(ArrayDeque<TypeT, ContainerT> &&buffer,
            const TypeT (&data)[N]) -> ArrayDeque<TypeT, ContainerT>
{
    return append(std::move(buffer), data, N - 1);
}

/**
   @brief Append the specified data to the buffer
   @tparam TypeT    The type that we are storing in the buffer
   @tparam ContainerT The container type
   @tparam N count of elements in the source array
   @param buffer ArrayDeque<TypeT, ContainerT>, The buffer to work on
   @param data reference to the source array
   @return reference to the modified buffer
*/
template <typename TypeT,
          typename ContainerT,
          std::size_t N>
auto append(ArrayDeque<TypeT, ContainerT> &buffer,
            const TypeT (&data)[N]) -> ArrayDeque<TypeT, ContainerT> &
{
    return append(buffer, data, N - 1);
}

/**
 * @brief Fill the entire buffer data allocation with the given value.
 *
 * This function fills the entire data allocation of the buffer with the given value but does
 * not change the logical size of the buffer contents.
 *
 * @tparam TypeT    The type that we are storing in the buffer
 * @tparam ContainerT The container type
 * @param buffer ArrayDeque<TypeT, ContainerT>, The buffer to work on
 * @param value this is the value the buffer allocation will be filled with
 * @return copy of the modified buffer
 */
template <typename TypeT,
          typename ContainerT>
auto fill(ArrayDeque<TypeT, ContainerT> &&buffer,
          TypeT value) -> ArrayDeque<TypeT, ContainerT>
{
    std::fill(buffer.data(), buffer.data() + buffer.capacity(), value);
    return buffer;
}

/**
 * @brief Fill the entire buffer data allocation with the given value.
 *
 * This function fills the entire data allocation of the buffer with the given value but does
 * not change the logical size of the buffer contents.
 *
 * @tparam TypeT    The type that we are storing in the buffer
 * @tparam ContainerT The container type
 * @param buffer ArrayDeque<TypeT, ContainerT>, The buffer to work on
 * @param value this is the value the buffer allocation will be filled with
 * @return reference to the modified buffer
 */
template <typename TypeT,
          typename ContainerT>
auto fill(ArrayDeque<TypeT, ContainerT> &buffer,
          TypeT value) -> ArrayDeque<TypeT, ContainerT> &
{
    std::fill(buffer.data(), buffer.data() + buffer.capacity(), value);
    return buffer;
}

/**
 * @brief Clear the entire buffer storage allocation, filling it with zero'd data
 *
 * @tparam TypeT    The type that we are storing in the buffer
 * @tparam ContainerT The container type
 * @param buffer ArrayDeque<TypeT, ContainerT>, The buffer to work on
 * @return copy of the modified buffer
 */
template <typename TypeT,
          typename ContainerT>
auto clear(ArrayDeque<TypeT, ContainerT> &&buffer) -> ArrayDeque<TypeT, ContainerT>
{
    return fill(std::move(buffer), TypeT(0));
}

/**
 * @brief Clear the entire buffer storage allocation, filling it with zero'd data
 *
 * @tparam TypeT    The type that we are storing in the buffer
 * @tparam ContainerT The container type
 * @param buffer ArrayDeque<TypeT, ContainerT>, The buffer to work on
 * @return reference to the modified buffer
 */
template <typename TypeT,
          typename ContainerT>
auto clear(ArrayDeque<TypeT, ContainerT> &buffer) -> ArrayDeque<TypeT, ContainerT> &
{
    return fill(buffer, TypeT(0));
}

/**
 * @brief Remove all occurrences of 'value' from the buffer.
 *
 * @tparam TypeT    The type that we are storing in the buffer
 * @tparam ContainerT The container type
 * @param buffer ArrayDeque<TypeT, ContainerT>, The buffer to work on
 * @param value the value to find and remove throughout the buffer
 * @return copy of the modified buffer
 */
template <typename TypeT,
          typename ContainerT>
auto remove(ArrayDeque<TypeT, ContainerT> &&buffer, TypeT value) -> ArrayDeque<TypeT, ContainerT>
{
    buffer.free_tail(buffer.end() - std::remove(buffer.begin(), buffer.end(), value));
    return buffer;
}

/**
 * @brief Remove all occurrences of 'value' from the buffer.
 *
 * @tparam TypeT    The type that we are storing in the buffer
 * @tparam ContainerT The container type
 * @param buffer ArrayDeque<TypeT, ContainerT>, The buffer to work on
 * @param value the value to find and remove throughout the buffer
 * @return reference to the modified buffer
 */
template <typename TypeT,
          typename ContainerT>
auto remove(ArrayDeque<TypeT, ContainerT> &buffer, TypeT value) -> ArrayDeque<TypeT, ContainerT> &
{
    buffer.free_tail(buffer.end() - std::remove(buffer.begin(), buffer.end(), value));
    return buffer;
}

} // namespace clv

#endif // CLV_CORE_BUFFER_UTIL_H
