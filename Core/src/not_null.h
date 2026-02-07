// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#pragma once

#include <cstddef>
#include <functional>
#include <stdexcept>
#include <type_traits>

namespace clv {

/// A non-null pointer wrapper with pointer semantics.
/// Throws std::invalid_argument if constructed or assigned with nullptr.
/// Has no default constructor - must be initialized with a valid pointer.
///
/// Usage: not_null<Widget*> ptr(&widget);
///
/// This is equivalent to gsl::not_null<T*> from the C++ Guidelines Support Library.
/// Consider using GSL if you need additional utilities (gsl::span, gsl::narrow, etc.):
///   git submodule add https://github.com/microsoft/GSL.git extern/GSL
template <typename T>
class not_null
{
    static_assert(std::is_pointer_v<T>, "not_null<T> requires T to be a pointer type (e.g., not_null<Widget*>)");

    using element_type = std::remove_pointer_t<T>;

  public:
    // No default constructor - must be initialized with a valid pointer
    not_null() = delete;

    // Construct from raw pointer - throws if null
    explicit not_null(T ptr)
        : ptr_(ptr)
    {
        if (!ptr_)
            throw std::invalid_argument("not_null: cannot be null");
    }

    // Copy constructor
    not_null(const not_null &) = default;

    // Move constructor
    not_null(not_null &&) noexcept = default;

    // Copy assignment
    not_null &operator=(const not_null &) = default;

    // Move assignment
    not_null &operator=(not_null &&) noexcept = default;

    // Assignment from raw pointer - throws if null
    not_null &operator=(T ptr)
    {
        if (!ptr)
            throw std::invalid_argument("not_null: cannot be null");
        ptr_ = ptr;
        return *this;
    }

    // Prevent assignment from nullptr_t
    not_null &operator=(std::nullptr_t) = delete;

    // Pointer semantics
    element_type *operator->() const noexcept
    {
        return ptr_;
    }
    element_type &operator*() const noexcept
    {
        return *ptr_;
    }

    // Get raw pointer
    T get() const noexcept
    {
        return ptr_;
    }

    // Explicit bool conversion (always true for valid not_null)
    explicit operator bool() const noexcept
    {
        return ptr_ != nullptr;
    }

    // Comparison operators (C++20 spaceship)
    auto operator<=>(const not_null &other) const noexcept = default;
    bool operator==(const not_null &other) const noexcept = default;

    // Comparison with raw pointers
    auto operator<=>(T other) const noexcept
    {
        return ptr_ <=> other;
    }
    bool operator==(T other) const noexcept
    {
        return ptr_ == other;
    }

    // Prevent comparison with nullptr
    auto operator<=>(std::nullptr_t) const = delete;
    bool operator==(std::nullptr_t) const = delete;

  private:
    T ptr_;
};

// Deduction guide
template <typename T>
not_null(T) -> not_null<T>;

} // namespace clv

// std::hash specialization for use in unordered containers
template <typename T>
struct std::hash<clv::not_null<T>>
{
    std::size_t operator()(const clv::not_null<T> &p) const noexcept
    {
        return std::hash<T>{}(p.get());
    }
};
