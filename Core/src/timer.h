// Copyright (c) 2023- Charlie Vigue. All rights reserved.


#ifndef CLV_CORE_TIMER_H
#define CLV_CORE_TIMER_H

#include <chrono>

namespace clv {

template <typename timer_res = std::chrono::nanoseconds,
          typename clock_arg = std::chrono::steady_clock>
struct Timer
{
    using elapsed = timer_res;
    using clock = clock_arg;

    template <typename result_type = elapsed>
    result_type Start() noexcept
    {
        auto mark = clock::now();
        auto result = Elapsed<result_type>(mark);
        mStart = mark;
        return result;
    }
    template <typename result_type = elapsed>
    result_type Elapsed(typename clock::time_point mark = clock::now()) noexcept
    {
        return std::chrono::duration_cast<result_type>(mark - mStart);
    }

  private:
    typename clock::time_point mStart = clock::now();
};

} // namespace clv

#endif // CLV_CORE_TIMER_H
