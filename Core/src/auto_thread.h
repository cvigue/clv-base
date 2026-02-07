// Copyright (c) 2023- Charlie Vigue. All rights reserved.


#ifndef CLV_CORE_AUTOTHREAD_H
#define CLV_CORE_AUTOTHREAD_H

#include <thread>
#include <type_traits>

#include "cancellable.h"
namespace clv {

/**
    @brief simplify thread management and add support for cancellation.
    @tparam CancelT
    @details  thread class that aims to simplify thread management and add support
    for cancellation. It is designed to make working with threads easier and safer
    for programmers.

    The purpose of this code is to create a more user-friendly way to work with
    threads. It automatically handles joining threads when they're no longer needed
    and provides a way to cancel running thread functions. This helps prevent common
    programming errors like forgetting to join threads.

    The AutoThread class doesn't take any direct inputs in the traditional sense.
    Instead, it's designed to be used by programmers who want to create and manage
    threads in their programs. When creating an AutoThread object, the programmer
    provides a function (and optionally, arguments for that function) that the thread
    will execute.

    The main output of AutoThread is the thread itself, which runs the provided
    function. It doesn't produce any specific data output, but rather manages the
    lifecycle of the thread and provides methods to interact with it.

    To achieve its purpose, AutoThread uses inheritance from the standard thread
    class and adds some additional features:

    - It includes a cancel_ member, which can be used to signal the thread function
      to stop running.
    - It provides a cancel() method that can be called to request the thread function
      to stop.
    - The destructor automatically joins the thread if it's still joinable, preventing
      resource leaks.
    - It offers two constructors that can handle different types of functions, including
      those that accept a cancellation token.
    - It uses move semantics to allow efficient transfer of thread ownership while
      preventing accidental copies.
    - The class also delegates several methods from the standard thread class, like
      detach(), get_id(), and join(), allowing users to work with it much like they
      would with a regular std::thread.

    An important aspect of the AutoThread class is its use of template programming.
    This allows it to work with different types of cancellation tokens (specified by
    the CancelT template parameter) and to accept various types of functions and
    arguments for thread execution.

    In summary, AutoThread provides a safer and more convenient way to work with
    threads in C++, automatically handling some common thread management tasks and
    adding support for thread cancellation.
*/

template <typename CancelT = NoCancel>
class AutoThread final : std::thread
{
    CancelT cancel_;

  public:
    /**
     * Cancels the current AutoThread.
     */
    void cancel()
    {
        cancel_.cancel();
    }

    /**
     * Destructor for AutoThread. Automatically joins the thread if it is still joinable,
     * preventing resource leaks.
     */
    ~AutoThread()
    {
        if (joinable())
            join();
    }

    /**
     * @brief executes function `f` with the given arguments `args`.
     * @details Constructs an AutoThread that executes the provided function `f` with
     * the given arguments `args`. The function `f` must be invocable with the provided
     * arguments.
     * @tparam FuncT The type of the function to be executed.
     * @tparam ArgsT The types of the arguments to be passed to the function.
     * @param f The function to be executed by the thread.
     * @param args The arguments to be passed to the function.
     */
    template <typename FuncT, typename... ArgsT>
    [[nodiscard]] AutoThread(FuncT &&f, ArgsT &&...args)
        requires std::is_invocable_v<FuncT, ArgsT...>
        : std::thread(std::forward<FuncT>(f), std::forward<ArgsT>(args)...){};

    /**
     * @brief executes function `f` with the given arguments `args` and a cancellation
     * token reference.
     * @details Constructs an AutoThread that executes the provided function `f` with the
     * given arguments `args` and a reference to the cancellation token `cancel_`. The
     * function `f` must be invocable with the cancellation token and the provided arguments.
     * @tparam FuncT The type of the function to be executed.
     * @tparam ArgsT The types of the arguments to be passed to the function.
     * @param f The function to be executed by the thread.
     * @param args The arguments to be passed to the function.
     */
    template <typename FuncT, typename... ArgsT>
    [[nodiscard]] AutoThread(FuncT &&f, ArgsT &&...args)
        requires std::is_invocable_v<FuncT, ArgsT..., CancelT &>
        : std::thread(std::forward<FuncT>(f), std::forward<ArgsT>(args)..., std::ref(cancel_)){};

    AutoThread(AutoThread &&) = default;
    AutoThread(const AutoThread &) = delete;
    AutoThread &operator=(AutoThread &&) = default;
    AutoThread &operator=(const AutoThread &) = delete;

    // Delegated API
    using std::thread::detach;
    using std::thread::get_id;
    using std::thread::hardware_concurrency;
    using std::thread::join;
    using std::thread::joinable;

    void swap(AutoThread &other)
    {
        std::swap(*this, other);
    }
};


} // namespace clv

#endif // CLV_CORE_AUTOTHREAD_H
