// Copyright (c) 2023- Charlie Vigue. All rights reserved.


#ifndef CLV_CORE_IS_CALLABLE_H
#define CLV_CORE_IS_CALLABLE_H

#include <type_traits>
#include <utility>

namespace clv {

/**
    @brief determine if a member function can be called with specific arguments.
    @tparam F The type member function (&T::func)
    @tparam T The type
    @tparam ArgsT Optional list of arguments the function should be checked against
    @param f instance of F
    @param t instance of T
    @param args Instance of ArgsT
    @return decltype((t.*f)(std::forward<ArgsT>(args)...), std::true_type{})
    @details defines a pair of function templates that work together to determine if a member
    function can be called with specific arguments. This is a technique known as SFINAE
    (Substitution Failure Is Not An Error) in C++, which allows the compiler to choose between
    different function overloads based on whether they are valid for the given types.

    The first function template takes three types of inputs: a member function pointer (F), an
    object of a class (T), and any number of additional arguments (ArgsT). Its purpose is to
    check if the member function can be called on the object with the given arguments.

    The second function template is a fallback that takes any arguments (represented by ...)
    and always returns std::false_type. This function will be selected by the compiler if the
    first function template fails to compile due to the member function not being callable
    with the given arguments.

    The output of these functions is either std::true_type or std::false_type, which are
    compile-time constants representing true or false, respectively.

    The way this code achieves its purpose is through the use of decltype and SFINAE. In the
    first function template, the return type uses decltype to attempt to call the member
    function with the given arguments. If this call is valid, the function will compile and
    return std::true_type. If the call is invalid, the compiler will discard this function
    template and fall back to the second one, which always returns std::false_type.

    The important logic flow here is not in the function bodies themselves (which are trivial),
    but in how the compiler chooses between them. This choice happens at compile-time, allowing
    the programmer to check if a member function is callable without actually calling it or
    even having a real instance of the class.

    This code is a building block for more complex template metaprogramming techniques, allowing
    other parts of the program to make decisions based on whether certain member functions exist
    and are callable with specific arguments.
*/
template <typename F, typename T, typename... ArgsT>
constexpr auto is_member_func_callable(F &&f,
                                       T &&t,
                                       ArgsT &&...args) -> decltype((t.*f)(std::forward<ArgsT>(args)...),
                                                                    std::true_type{})
{
    return std::true_type{};
}

template <typename F, typename T, typename... ArgsT>
constexpr std::false_type is_member_func_callable(...)
{
    return std::false_type{};
}

template <typename F, typename T, typename... ArgsT>
constexpr bool is_member_func_callable_v = decltype(is_member_func_callable<F,
                                                                            T,
                                                                            ArgsT...>(std::declval<F>(),
                                                                                      std::declval<T>(),
                                                                                      std::declval<ArgsT>()...))::value;

} // namespace clv

#endif // CLV_CORE_IS_CALLABLE_H
