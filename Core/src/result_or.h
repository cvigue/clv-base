// Copyright (c) 2023- Charlie Vigue. All rights reserved.

#ifndef CLV_CORE_RESULT_OR_H
#define CLV_CORE_RESULT_OR_H

#include <utility>
#include <variant>

// Generic result-or-error type similar to std::expected, but small and header-only.
// T is the success value type, E is the error type.
namespace clv {

template <typename T, typename E>
class result_or
{
  public:
    result_or(T value) : value_{std::move(value)}
    {
    }
    result_or(E error) : value_{std::move(error)}
    {
    }

    [[nodiscard]] bool has_value() const noexcept
    {
        return std::holds_alternative<T>(value_);
    }
    [[nodiscard]] explicit operator bool() const noexcept
    {
        return has_value();
    }

    [[nodiscard]] const T &value() const &
    {
        return std::get<T>(value_);
    }
    [[nodiscard]] T &value() &
    {
        return std::get<T>(value_);
    }
    [[nodiscard]] T &&value() &&
    {
        return std::get<T>(std::move(value_));
    }

    [[nodiscard]] const T &operator*() const &
    {
        return value();
    }
    [[nodiscard]] T &operator*() &
    {
        return value();
    }
    [[nodiscard]] T &&operator*() &&
    {
        return std::move(*this).value();
    }

    [[nodiscard]] const T *operator->() const
    {
        return &value();
    }
    [[nodiscard]] T *operator->()
    {
        return &value();
    }

    [[nodiscard]] const E &error() const &
    {
        return std::get<E>(value_);
    }
    [[nodiscard]] E &error() &
    {
        return std::get<E>(value_);
    }

  private:
    std::variant<T, E> value_;
};

} // namespace clv

#endif // CLV_CORE_RESULT_OR_H
