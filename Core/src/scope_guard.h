// Copyright (c) 2023- Charlie Vigue. All rights reserved.


#ifndef CLV_CORE_SCOPE_GUARD_H
#define CLV_CORE_SCOPE_GUARD_H

#include <concepts>
#include <exception>
#include <functional>
#include <optional>
#include <type_traits>
#include <utility>

// TODO: Use the std C++ <scope> header instead of this one when it's broadly available

namespace clv {

/**
  @brief The ScopeGuardImpl class is a template class that implements the scope guard pattern
  @tparam ExitConditionFn type of the exit condition callable (function, lambda, functor)
  @tparam UndoFnT type of the undo function
  @class ScopeGuardImpl

  The purpose of this class is to help ensure some cleanup code gets executed when exiting a scope,
  even if an exception is thrown. It takes a cleanup function and executes it only when some exit
  condition is met.

  This class takes two template parameters:

  - ExitConditionFn: A callable that returns a bool indicating if the exit condition is met.
    This determines if the cleanup code should run. Can be a function pointer, lambda, or functor.

  - UndoFnT: The type of the cleanup function.

  When creating a ScopeGuardImpl instance, we pass both the exit condition and cleanup function
  to the constructor. These are saved and will be evaluated/called later in the destructor if needed.
  The constructor uses a try/catch block to make sure the cleanup function is called if constructing
  the ScopeGuardImpl throws an exception.

  The destructor checks the exit condition by invoking the stored callable. If it returns true,
  it will execute the saved cleanup function.

  The release() method allows manually disabling the cleanup if needed.

  The copy operations are deleted to prevent multiple ScopeGuardImpl instances from trying to call
  the same cleanup code.
*/
template <typename ExitConditionFn, typename UndoFnT>
    requires std::invocable<ExitConditionFn>
             && std::same_as<std::invoke_result_t<ExitConditionFn>, bool>
             && std::invocable<UndoFnT>
class [[nodiscard]] ScopeGuardImpl
{
  public:
    ScopeGuardImpl(ExitConditionFn &&exitFn, UndoFnT &&undoFn);
    ScopeGuardImpl(ScopeGuardImpl &&other) noexcept;
    ~ScopeGuardImpl();

    std::optional<UndoFnT> release() noexcept;
    void invoke();

    template <typename NewUndoFnT>
        requires std::invocable<NewUndoFnT> && std::convertible_to<NewUndoFnT, UndoFnT>
    void reset(NewUndoFnT &&newUndoFn) noexcept(std::is_nothrow_constructible_v<UndoFnT, NewUndoFnT>);

    ScopeGuardImpl(const ScopeGuardImpl &) = delete;
    void operator=(const ScopeGuardImpl &) = delete;

  private:
    [[no_unique_address]] ExitConditionFn mExitFn; ///< Exit condition callable (may be stateless)
    std::optional<UndoFnT> mUndoFn;                ///< Undo function (nullopt when released)
};

/**
  @brief Construct a new ScopeGuardImpl object
  @tparam ExitConditionFn type of the exit condition callable
  @tparam UndoFnT type of the undo function
  @param exitFn the exit condition callable to use
  @param undoFn the function to call if undo is appropriate
*/
template <typename ExitConditionFn, typename UndoFnT>
    requires std::invocable<ExitConditionFn>
             && std::same_as<std::invoke_result_t<ExitConditionFn>, bool>
             && std::invocable<UndoFnT>
ScopeGuardImpl<ExitConditionFn, UndoFnT>::ScopeGuardImpl(ExitConditionFn &&exitFn, UndoFnT &&undoFn)
try : mExitFn(std::forward<ExitConditionFn>(exitFn)),
      mUndoFn(std::forward<UndoFnT>(undoFn))
{
}
catch (...)
{
    std::invoke(undoFn);
    throw;
}

/**
  @brief Construct a new ScopeGuardImpl object via move
  @tparam ExitConditionFn type of the exit condition callable
  @tparam UndoFnT type of the undo function
  @param other the donor object
*/
template <typename ExitConditionFn, typename UndoFnT>
    requires std::invocable<ExitConditionFn>
                 && std::same_as<std::invoke_result_t<ExitConditionFn>, bool>
                 && std::invocable<UndoFnT>
ScopeGuardImpl<ExitConditionFn, UndoFnT>::ScopeGuardImpl(ScopeGuardImpl &&other) noexcept
    : mExitFn(std::move(other.mExitFn)),
      mUndoFn(std::move(other.mUndoFn))
{
    other.release();
}

/**
  @brief Destroy the ScopeGuardImpl object, conditionally calling the undo func
  @tparam ExitConditionFn type of the exit condition callable
  @tparam UndoFnT type of the undo function
*/
template <typename ExitConditionFn, typename UndoFnT>
    requires std::invocable<ExitConditionFn>
             && std::same_as<std::invoke_result_t<ExitConditionFn>, bool>
             && std::invocable<UndoFnT>
ScopeGuardImpl<ExitConditionFn, UndoFnT>::~ScopeGuardImpl()
{
    if (mUndoFn && std::invoke(mExitFn))
    {
        std::invoke(*mUndoFn);
    }
}

/**
  @brief Disable calling the undo function and return the callable
  @tparam ExitConditionFn type of the exit condition callable
  @tparam UndoFnT type of the undo function
  @return The undo function if present, nullopt if already released or invoked

  Extracts and returns the stored cleanup function, preventing it from being
  called by the destructor. Useful when you want to take ownership of the
  cleanup function for later manual execution.
*/
template <typename ExitConditionFn, typename UndoFnT>
    requires std::invocable<ExitConditionFn>
             && std::same_as<std::invoke_result_t<ExitConditionFn>, bool>
             && std::invocable<UndoFnT>
std::optional<UndoFnT> ScopeGuardImpl<ExitConditionFn, UndoFnT>::release() noexcept
{
    auto result = std::move(mUndoFn);
    mUndoFn.reset();
    return result;
}

/**
  @brief Execute the undo function immediately and disable the guard
  @tparam ExitConditionFn type of the exit condition callable
  @tparam UndoFnT type of the undo function

  Calls the cleanup function immediately if present, then disables the guard
  so it won't execute again in the destructor. This is useful when you need
  to perform cleanup earlier than scope exit. If the guard is already released
  or invoked, this is a no-op.
*/
template <typename ExitConditionFn, typename UndoFnT>
    requires std::invocable<ExitConditionFn>
             && std::same_as<std::invoke_result_t<ExitConditionFn>, bool>
             && std::invocable<UndoFnT>
void ScopeGuardImpl<ExitConditionFn, UndoFnT>::invoke()
{
    if (mUndoFn)
    {
        std::invoke(*mUndoFn);
        mUndoFn.reset();
    }
}

/**
  @brief Replace the cleanup function with a new one
  @tparam ExitConditionFn type of the exit condition callable
  @tparam UndoFnT type of the undo function
  @tparam NewUndoFnT type of the new cleanup function
  @param newUndoFn the new cleanup function to install

  Replaces the current cleanup function with a new one. If there was an existing
  cleanup function, it is discarded without being called. This allows reusing
  the same guard variable instead of creating multiple guards (g1, g2, g3, etc.).

  Example:
    auto guard = scope_exit([sock1] { close(sock1); });
    // ... some work ...
    guard.reset([sock2] { close(sock2); });  // Reuse guard for new resource
*/
template <typename ExitConditionFn, typename UndoFnT>
    requires std::invocable<ExitConditionFn>
             && std::same_as<std::invoke_result_t<ExitConditionFn>, bool>
             && std::invocable<UndoFnT>
             template <typename NewUndoFnT>
                 requires std::invocable<NewUndoFnT> && std::convertible_to<NewUndoFnT, UndoFnT>
void ScopeGuardImpl<ExitConditionFn, UndoFnT>::reset(NewUndoFnT &&newUndoFn) noexcept(std::is_nothrow_constructible_v<UndoFnT, NewUndoFnT>)
{
    mUndoFn = std::forward<NewUndoFnT>(newUndoFn);
}


// Exit condition callable types
struct always_true
{
    bool operator()() const noexcept
    {
        return true;
    }
};

struct in_exception
{
    bool operator()() const noexcept
    {
        return std::uncaught_exceptions() > 0;
    }
};

struct no_exception
{
    bool operator()() const noexcept
    {
        return std::uncaught_exceptions() == 0;
    }
};


/**
  @brief ensure some cleanup code gets executed when exiting a scope
  @tparam UndoFnT

  The scope_exit struct is a way to ensure some cleanup code gets executed when exiting a scope, even
  if an exception is thrown. It takes as input a function or lambda (UndoFnT) that represents the
  cleanup code we want to run on scope exit.

  When a scope_exit instance is created, it saves this cleanup function and registers it to be called
  later in the destructor. The destructor will execute the saved cleanup function if the scope_exit
  has not been released.

  scope_exit inherits from ScopeGuardImpl, which does most of the work. ScopeGuardImpl takes the
  cleanup function in its constructor and saves it. The destructor checks an exit condition and executes
  the cleanup if needed. scope_exit specializes ScopeGuardImpl by using a callable type always_true
  as the exit condition. This makes it execute the cleanup whenever the destructor is called, which
  happens when exiting the scope.
*/
template <typename UndoFnT>
struct [[nodiscard]] scope_exit : ScopeGuardImpl<always_true, UndoFnT>
{
    /**
      @brief Construct a new scope_exit object with the given undo callable
      @param undoFn the undo callable to use
    */
    scope_exit(UndoFnT &&undoFn)
        : ScopeGuardImpl<always_true, UndoFnT>(always_true{}, std::move(undoFn)) {};
};

/**
  @brief execute cleanup code when an exception occurs
  @tparam UndoFnT

  The scope_fail struct is a way to execute cleanup code when an exception occurs. It is used to ensure
  some action gets done if an error happens in a scope. It takes as input a function or lambda UndoFnT
  that represents the cleanup code we want to run if there is an exception.

  When a scope_fail instance is created, it saves this cleanup function and registers it to be potentially
  called later in the destructor. scope_fail inherits from another class called ScopeGuardImpl.
  ScopeGuardImpl takes the cleanup function in its constructor and saves it. The ScopeGuardImpl destructor
  checks if an exception has occurred by calling the in_exception callable. If it returns true, meaning
  an exception happened, ScopeGuardImpl will execute the saved cleanup function.

  So by inheriting from ScopeGuardImpl and passing it the in_exception callable, scope_fail creates an
  object that will call the given cleanup function if an exception occurs before the scope exits. This
  allows scope_fail to run cleanup code when there is an error, without having to explicitly check for
  and handle exceptions everywhere. The cleanup happens automatically when scope_fail goes out of scope
  if an exception occurred.
*/
template <typename UndoFnT>
struct [[nodiscard]] scope_fail : ScopeGuardImpl<in_exception, UndoFnT>
{
    /**
      @brief Construct a new scope_fail object with the given undo callable
      @param undoFn the undo callable to use
    */
    scope_fail(UndoFnT &&undoFn)
        : ScopeGuardImpl<in_exception, UndoFnT>(in_exception{}, std::move(undoFn)) {};
};

/**
  @brief execute a function when no exception has occurred in a scope
  @tparam UndoFnT
  @note I don't really see a lot of use for this but it's going into <scope> apparently so ...

  The scope_success struct is a way to execute a function when no exception has occurred in a scope. It
  takes a function or lambda UndoFnT as input, which represents the code to execute on success.

  When a scope_success instance is created, it saves the function UndoFnT. It inherits from another
  class called ScopeGuardImpl, which registers the cleanup function to potentially be called later.
  ScopeGuardImpl's destructor checks if an exception has occurred by calling the no_exception callable.
  If it returns true, meaning no exception occurred, ScopeGuardImpl will execute the saved function.

  So by inheriting from ScopeGuardImpl and passing it the no_exception callable, scope_success creates
  an object that will call the given function UndoFnT if no exception occurs before the scope exits.
*/
template <typename UndoFnT>
struct [[nodiscard]] scope_success : ScopeGuardImpl<no_exception, UndoFnT>
{
    /**
      @brief Construct a new scope_success object with the given undo callable
      @param undoFn the undo callable to use
    */
    scope_success(UndoFnT &&undoFn)
        : ScopeGuardImpl<no_exception, UndoFnT>(no_exception{}, std::move(undoFn)) {};
};

/**
    @brief ScopeIncrementGuard class
    @details This class is a simple RAII-style guard that increments a counter when it is created and
    decrements it when it is destroyed.
    @tparam CounterT The type of the counter to be incremented/decremented.
*/
template <typename CounterT>
struct [[nodiscard]] ScopeIncrementGuard
{
  public:
    // Constructor: Takes a reference to the counter and increments it
    explicit ScopeIncrementGuard(CounterT &counter)
        : counter_ref_(counter)
    {
        ++counter_ref_;
    }

    // Destructor: Decrements the counter when the guard goes out of scope
    ~ScopeIncrementGuard()
    {
        --counter_ref_;
    }

    // Delete copy constructor and assignment operator to prevent issues
    ScopeIncrementGuard(const ScopeIncrementGuard &) = delete;
    ScopeIncrementGuard &operator=(const ScopeIncrementGuard &) = delete;

    // Optionally delete move constructor/assignment if moves don't make sense
    // or implement them carefully if they do. For simple usage, deleting is safest.
    ScopeIncrementGuard(ScopeIncrementGuard &&) = delete;
    ScopeIncrementGuard &operator=(ScopeIncrementGuard &&) = delete;

  private:
    CounterT &counter_ref_;
};

} // namespace clv

#endif // CLV_CORE_SCOPE_GUARD_H
