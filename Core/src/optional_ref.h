// Copyright (c) 2023- Charlie Vigue. All rights reserved.


#ifndef CLV_CORE_OPTIONAL_REF_H
#define CLV_CORE_OPTIONAL_REF_H

#include <stdexcept>
#include <utility>
#include <optional>

namespace clv {


template <typename T>
class optional_ref
{
    // sizeof(T) == 0 is always false but depends on T, making this valid pre-C++23.
    // Plain static_assert(false) is ill-formed NDR before C++23 (P2593R1).
    static_assert(sizeof(T) == 0, "optional_ref<T> is only specialized for T& — use optional_ref<T&>");
    optional_ref() = delete;
};

/**
    @brief designed to represent an optional_ref reference to an object of type T
    @tparam T reference type
    @details This code defines a template class called optional_ref<T&> which is designed to
    represent an optional_ref reference to an object of type T. The purpose of this class is
    to provide a way to handle situations where a reference might or might not be
    available, similar to how std::optional_ref works for regular types.

    The class doesn't take any direct inputs, but it can be instantiated with either no
    arguments (creating an empty optional_ref), a reference to an object of type T, or
    another optional_ref object. It produces an object that can either hold a reference to
    a T object or be empty.

    The class achieves its purpose by using a pointer (T *mRef) internally to store the
    address of the referenced object. When the optional_ref is empty, this pointer is set to
    nullptr. The class provides various methods to check if a reference is present,
    access the referenced object, and assign new references or clear the optional_ref.

    The important logic flows in this class include:

    - Constructors and assignment operators that allow creating and modifying the optional_ref
      object. Assigning from T will write thru, modifying the T that is referred to. Assigning
      from another optional_ref will change the target of the reference. Assigning std::nullopt
      will remove the reference target.
    - A boolean conversion operator that checks if the optional_ref contains a valid reference.
    - Dereference operators (* and ->) that provide access to the referenced object, throwing
      an exception if the optional_ref is empty. For example when calling the * operator, a check
      is done if the optional_ref contains a valid reference. If it does, it returns the
      referenced object. If it doesn't, it throws an exception with the message
      "optional_ref<T &>: access error".
    - The value and value_or members behave similarly except they return a copy of the stored
      value and in the case of value_or, the default is returned if the reference is not
      valid. This return by value is a bit idiosyncratic but they are provided for
      compatibility with the std::optional_ref interface. Hopefully the function names serve as
      a reminder that the return is a value.

    This implementation allows programmers to work with optional_ref references in a way
    that's similar to how they would work with optional values. It provides a slightly safer
    alternative to using raw pointers or references when dealing with objects that may or
    may not be available at runtime. The safety improvement is only that:

    - A segfault is prevented if the optional_ref is de-refed while empty, substituting an
      exception that can be caught and handled instead.
    - Makes the code a little more self documenting in that a raw pointer is versatile
      and therefore might be used for may reasons, whereas this class is very specifically
      for representing an optional_ref reference.
*/
template <typename T>
class optional_ref<T &>
{
    T *mRef = nullptr;
    static constexpr char errorMsg[] = "optional_ref<T &>: access error";

  public:
    /**
     * @brief Default constructor. Creates an empty optional_ref.
     */
    constexpr optional_ref() noexcept;

    /**
     * @brief Constructs an empty optional_ref.
     * @param std::nullopt_t Indicates that the optional_ref should be empty.
     */
    constexpr optional_ref(std::nullopt_t) noexcept;

    /**
     * @brief Constructs an optional_ref containing a reference to the given object.
     * @param r Reference to the object to be stored.
     */
    constexpr optional_ref(T &r) noexcept;

    /**
     * @brief Copy constructor.
     */
    constexpr optional_ref(const optional_ref &) noexcept = default;

    /**
     * @brief Move constructor.
     */
    constexpr optional_ref(optional_ref &&) noexcept = default;

    /**
     * @brief Copy assignment operator.
     * @return Reference to this object.
     */
    optional_ref &operator=(const optional_ref &) noexcept = default;

    /**
     * @brief Move assignment operator.
     * @return Reference to this object.
     */
    optional_ref &operator=(optional_ref &&) noexcept = default;

    /**
     * @brief Assigns the optional_ref to be empty.
     * @param std::nullopt_t Indicates that the optional_ref should be empty.
     * @return Reference to this object.
     */
    optional_ref &operator=(std::nullopt_t) noexcept;

    /**
     * @brief Equality operator.
     * @param rhs The optional_ref to compare against.
     * @return true if the optional_ref objects are equal, false otherwise.
     */
    bool operator==(const optional_ref &rhs) const noexcept;

    /**
     * @brief Comparison operator.
     * @param rhs The optional_ref to compare against.
     * @return the std::strong_ordering result of the comparison.
     */
    auto operator<=>(const optional_ref &rhs) const noexcept;

    /**
     * @brief Resets the optional_ref, making it empty.
     */
    void reset() noexcept;

    /**
     * @brief Checks whether the optional_ref contains a value.
     * @return true if the optional_ref contains a value, false otherwise.
     */
    [[nodiscard]] constexpr bool has_value() const noexcept;

    /**
     * @brief Checks whether the optional_ref contains a value.
     * @return true if the optional_ref contains a value, false otherwise.
     */
    [[nodiscard]] constexpr explicit operator bool() const noexcept;

    /**
     * @brief Gets the contained value.
     * @return Copy of the contained value.
     * @throws std::runtime_error if the optional_ref is empty.
     */
    [[nodiscard]] constexpr T &value() const;

    /**
     * @brief Returns the contained value if the optional_ref is not empty, otherwise
     *        returns the provided default value.
     * @param default_value The value to return if the optional_ref is empty.
     * @return Copy of the contained value if the optional_ref is not empty,
     *         otherwise a copy of the default value.
     */
    [[nodiscard]] constexpr T value_or(const T &default_value) const noexcept;

    /**
     * @brief Dereference operator.
     * @return Const reference to the contained value.
     * @throws std::runtime_error if the optional_ref is empty.
     */
    const T &operator*() const;

    /**
     * @brief Dereference operator.
     * @return Reference to the contained value.
     * @throws std::runtime_error if the optional_ref is empty.
     */
    T &operator*();

    /**
     * @brief Arrow operator.
     * @return Const pointer to the contained value.
     * @throws std::runtime_error if the optional_ref is empty.
     */
    const T *operator->() const;

    /**
     * @brief Arrow operator.
     * @return Pointer to the contained value.
     * @throws std::runtime_error if the optional_ref is empty.
     */
    T *operator->();
};

// Implementations below

template <typename T>
inline constexpr optional_ref<T &>::optional_ref() noexcept
    : mRef(nullptr){};

template <typename T>
inline constexpr optional_ref<T &>::optional_ref(std::nullopt_t) noexcept
    : optional_ref(){};

template <typename T>
inline constexpr optional_ref<T &>::optional_ref(T &r) noexcept
    : mRef(&r){};

template <typename T>
inline optional_ref<T &> &optional_ref<T &>::operator=(std::nullopt_t) noexcept
{
    reset();
    return *this;
}

template <typename T>
bool optional_ref<T &>::operator==(const optional_ref &rhs) const noexcept
{
    return mRef == rhs.mRef || (mRef && rhs.mRef && *mRef == *rhs.mRef);
}

template <typename T>
auto optional_ref<T &>::operator<=>(const optional_ref &rhs) const noexcept
{
    if (mRef == rhs.mRef)
        return std::strong_ordering::equal;

    return (!mRef || !rhs.mRef) ? mRef <=> rhs.mRef : *mRef <=> *rhs.mRef;
}

template <typename T>
inline void optional_ref<T &>::reset() noexcept
{
    mRef = nullptr;
}

template <typename T>
inline constexpr bool optional_ref<T &>::has_value() const noexcept
{
    return mRef != nullptr;
}

template <typename T>
inline constexpr optional_ref<T &>::operator bool() const noexcept
{
    return has_value();
}

template <typename T>
inline constexpr T &optional_ref<T &>::value() const
{
    if (!bool(*this))
        throw std::runtime_error(errorMsg);
    return *mRef;
}

template <typename T>
inline constexpr T optional_ref<T &>::value_or(const T &default_value) const noexcept
{
    return bool(*this) ? *mRef : default_value;
}

template <typename T>
inline const T &optional_ref<T &>::operator*() const
{
    return *(*this).operator->();
}

template <typename T>
inline T &optional_ref<T &>::operator*()
{
    return const_cast<T &>(*(std::as_const(*this)));
}

template <typename T>
inline const T *optional_ref<T &>::operator->() const
{
    if (!bool(*this))
        throw std::runtime_error(errorMsg);
    return mRef;
}

template <typename T>
inline T *optional_ref<T &>::operator->()
{
    return const_cast<T *>(std::as_const(*this).operator->());
}

template <typename T, typename... ArgsT>
auto make_optional_ref(ArgsT &&...args)
{
    return optional_ref<T &>(std::forward<ArgsT>(args)...);
}

} // namespace clv

#endif // CLV_CORE_OPTIONAL_REF_H
