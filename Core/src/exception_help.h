// Copyright (c) 2023- Charlie Vigue. All rights reserved.



#ifndef CLV_CORE_EXCEPTIONHELP_H
#define CLV_CORE_EXCEPTIONHELP_H

#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <tuple>
#include <variant>

namespace clv {

// ********************************************************************************************************************
// Helpers
// ********************************************************************************************************************

inline auto MsgFromError(std::string_view msg, const std::error_code &error)
{
#ifdef __cpp_lib_format
    return std::format("{} failed with error: {} - {} [{}]",
                       msg,
                       error.category().name(),
                       error.message(),
                       error.value());
#else
    return std::string("MsgFromError: std::format not available");
#endif
}

template <typename ExT, typename... extended>
struct ExtendedException : ExT
{
    template <typename... ArgsT>
    explicit ExtendedException(const std::string &msg, ArgsT &&...args)
        : ExT(msg), extended_info(std::forward<ArgsT>(args)...)
    {
    }

    template <typename ExtT>
    ExtT GetExtendedInfo(ExtT notFoundValue) const noexcept
    {
        if (auto ext = std::get_if<ExtT>(&extended_info); ext)
            return *ext;
        return notFoundValue;
    }

  private:
    std::tuple<extended...> extended_info;
};

template <typename ExT>
auto ExceptionFromError(std::string_view msg, const std::error_code &error)
{
    return ExT(MsgFromError(msg, error));
}

template <typename ExT, typename... ArgsT>
inline auto ExtendedExFromError(std::string_view msg,
                                const std::error_code &error,
                                ArgsT &&...args)
{
    return ExtendedException<ExT, ArgsT...>(MsgFromError(msg, error),
                                            std::forward<ArgsT>(args)...);
}

inline auto RuntimeExFrom(std::string_view msg, const std::error_code &error)
{
    return ExceptionFromError<std::runtime_error>(msg, error);
}


} // namespace clv

#endif // CLV_CORE_EXCEPTIONHELP_H
