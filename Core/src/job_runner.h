// Copyright (c) 2023- Charlie Vigue. All rights reserved.


#ifndef CLVLIB_CORE_JOBRUNNER_H
#define CLVLIB_CORE_JOBRUNNER_H

#include <functional>
#include <vector>
#include <future>

namespace clv {

template <typename ResultT>
struct JobRunner
{
    void run(std::function<ResultT()> fn)
    {
        mJoin.push_back(std::async(std::launch::async, fn));
    }
    void join() noexcept
    {
        mJoin.clear();
    }
    bool prune() noexcept
    {
        for (auto cp = mJoin.begin(); cp != mJoin.end();)
        {
            if (cp->valid() && cp->wait_for(0) == std::future_status::ready)
                mJoin.erase(cp);
            else
                ++cp;
        }
        return mJoin.empty();
    }
    const auto &results() const noexcept
    {
        return mJoin;
    }

  private:
    using JoinListT = std::vector<std::future<ResultT>>;

  private:
    JoinListT mJoin;
};

} // namespace clv

#endif // CLVLIB_CORE_JOBRUNNER_H
