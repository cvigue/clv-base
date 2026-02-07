// Copyright (c) 2023- Charlie Vigue. All rights reserved.



#ifndef CLV_CORE_CANCELLABLE_H
#define CLV_CORE_CANCELLABLE_H

namespace clv {

/**
    @brief for scenarios where cancellation is not needed or desired
    @details The NoCancel class is a simple implementation of a cancellation mechanism that
    effectively does nothing. Its purpose is to provide a "dummy" or placeholder
    implementation for scenarios where cancellation is not needed or desired, but the
    interface requires a cancellation object. This class is zero size and does nothing
    except fill a dependency.
*/
class NoCancel
{
  public:
    void cancel()
    {
    }
    bool is_canceled()
    {
        return false;
    }
};

/**
    @brief a simple implementation of a cancellation mechanism.
    @note Fancier cancel modules might share a reference to a flag or wrap a C++ '20 stop_token
    or do other fancy stuff based on a predicate of some sort. This is why the cancellation
    logic is injected into the task class.
*/
class BasicCancel
{
    bool canceled_ = false;

  public:
    void cancel()
    {
        canceled_ = true;
    }
    bool is_canceled()
    {
        return canceled_;
    }
};

} // namespace clv

#endif // CLV_CORE_CANCELLABLE_H
