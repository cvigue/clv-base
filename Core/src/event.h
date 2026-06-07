// Copyright (c) 2023- Charlie Vigue. All rights reserved.


#ifndef CLV_CORE_EVENT_H
#define CLV_CORE_EVENT_H

#include <mutex>
#include <condition_variable>
#include <chrono>

namespace clv {
/**
    @brief a mechanism for one thread to signal an event to (an)other thread(s)
    @struct Event
    The purpose of the Event class is to provide a mechanism for one thread to signal an event to (an)other
    thread(s), and allow the receiving thread(s) to wait for the event to occur. The Event class does not take
    any explicit inputs. It relies on its member functions being called to trigger events and waiting.

    The main outputs of the Event class are:

    - Notifying other threads that an event has occurred, via the Notify() method
    - Allowing one or more threads to wait for an event, via the Wait() and Wait(WaitPredT) methods

    The key logic and algorithms are:

    The Event contains a condition variable (mCv) and mutex (mMutex) as internal state. These are used to
    synchronize the event signaling between threads. When Notify() is called on the Event, it calls notify_one()
    on the internal condition variable mCv. This signals any thread waiting on mCv that the event has occurred.
    The Wait() and Wait(WaitPredT) methods lock the internal mutex, then call wait() on the condition variable
    mCv. This causes the calling thread to wait until Notify() is called on the event and unlocks the mutex
    while the thread is blocked.

    By synchronizing on the same mutex and condition variable, Notify() and Wait() allow signaling the event
    between threads properly. The Wait() methods return a unique_lock object to hold the lock on the mutex
    after the wait is finished. Since returning from wait reacquires the mutex, this allows the caller of
    wait to hold the lock on the mutex as long as the returned unique_lock object stays in scope.

    In summary, the Event class provides inter-thread event signaling and waiting using a condition variable
    and mutex to synchronize the state. One thread can call Notify() to signal an event has occurred, while
    other threads can call Wait() to wait for the event to be notified.

    - Cody
*/
class Event
{
  public:
    auto Wait() noexcept;
    template <class WaitPredT>
    auto Wait(WaitPredT wp) noexcept(noexcept(wp()));
    template <class Rep, class Period>
    auto WaitFor(const std::chrono::duration<Rep, Period> &) noexcept;
    template <class Rep, class Period, class WaitPredT>
    auto WaitFor(const std::chrono::duration<Rep, Period> &, WaitPredT wp) noexcept(noexcept(wp()));

    void Notify() noexcept;
    void NotifyAll() noexcept;

    std::mutex &GetMutex() noexcept;
    template <typename LockT>
    auto Lock();

  private:
    std::condition_variable mCv;
    std::mutex mMutex;
};

/**
    @brief Waits for the notification to be signaled.
    @return unique_lock Holding the lock
    @details Locks the mutex, waits on the condition variable, and returns a unique_lock holding the
             lock. If the returned object is assigned to a local variable, the mutex lock will be held
             until that variable goes out of scope or until it is manually unlocked.

    During the wait the mutex is unlocked, see the CPP reference condition_variable docs for details.
 */
inline auto Event::Wait() noexcept
{
    auto lock = std::unique_lock(mMutex);
    mCv.wait(lock);
    return lock;
}

/**
    @brief Waits for the notification
    @param wp - The predicate to evaluate.
    @return unique_lock Holding the lock
    @throws will pass any exception from 'wp' up to caller. Is noexcept if 'wp' is noexcept.
    @details Locks the mutex, waits on the condition variable, and returns a unique_lock holding the lock.
             If the returned object is assigned to a local variable, the mutex lock will be held until that
             variable goes out of scope or until it is manually unlocked. If the predicate evaluates true
             the wait is not started. Once started the wait continues until the notification is set. If
             the predicate evaluates false the notification will be ignored and the wait resumed.

    During the wait the mutex is unlocked, see the CPP reference condition_variable docs for details.
 */
template <class WaitPredT>
auto Event::Wait(WaitPredT wp) noexcept(noexcept(wp()))
{
    auto lock = std::unique_lock(mMutex);
    mCv.wait(lock, wp);
    return lock;
}

/**
    @brief Waits for the notification or until timeout expires.
    @param wait_time - The timeout duration to wait.
    @return unique_lock holding the lock if wait succeeded
    @details Locks the mutex, waits on the condition variable and the time limit, and returns a unique_lock.
             The unique_lock will hold the lock if the wait was signaled, otherwise if the wait timed out
             the unique_lock refers to the mutex but does not hold the lock. It is possible to call owns_lock,
             lock, etc on the unique_lock to determine the state and potentially lock the mutex if it is not
             locked already.

    If the unique_lock is not assigned to a local or goes out of scope, the lock, if held, is unlocked.

    During the wait the mutex is unlocked, see the CPP reference condition_variable docs for details.
 */
template <class Rep, class Period>
auto Event::WaitFor(const std::chrono::duration<Rep, Period> &wait_time) noexcept
{
    auto lock = std::unique_lock(mMutex);
    auto wait_result = mCv.wait_for(lock, wait_time);
    if (wait_result == std::cv_status::timeout)
        lock.unlock();
    return lock;
}

/**
    @brief Waits for the notification or timeout.
    @tparam Rep Type used for time representations
    @tparam Period Period type used for time representations
    @tparam WaitPredT Callable predicate type
    @param wait_time Maximum time to wait
    @param wp Predicate to evaluate
    @return unique_lock Holding the lock if wait succeeded or predicate returned true
    @throws will pass any exception from 'wp' up to caller. Is noexcept if 'wp' is noexcept.
    @details Locks the mutex, waits on the condition variable and the time limit, and returns a unique_lock.
             The unique_lock will hold the lock if the predicate evaluated true when the wait ended, otherwise
             if the wait timed out before the predicate was true, the unique_lock refers to the mutex but does
             not hold the lock. It is possible to call owns_lock, lock, etc on the unique_lock to determine
             the state and potentially lock the mutex if it is not locked already.

    If the predicate evaluates true the wait is not started. Once started the wait continues until the notification
    is set or the wait times out. If the predicate evaluates false the returned lock will not hold a lock on the
    mutex.

    If the unique_lock is not assigned to a local or goes out of scope, the lock, if held, is unlocked.

    During the wait the mutex is unlocked, see the CPP reference condition_variable docs for details.
 */
template <class Rep, class Period, class WaitPredT>
auto Event::WaitFor(const std::chrono::duration<Rep, Period> &wait_time, WaitPredT wp) noexcept(noexcept(wp()))
{
    auto lock = std::unique_lock(mMutex);
    auto wait_result = mCv.wait_for(lock, wait_time, wp);
    if (!wait_result)
        lock.unlock();
    return lock;
}

/**
 * @brief Locks the internal mutex using the specified lock type.
 * @tparam LockT The lock type to be used (e.g., std::unique_lock, std::lock_guard).
 * @return An instance of the specified lock type, locked on the internal mutex.
 * @details This function allows you to lock the internal mutex using a specific lock
 *          type. It is useful when you need to acquire the lock and perform additional
 *          operations before releasing it.
 */
template <typename LockT>
inline auto Event::Lock()
{
    return LockT(mMutex);
}

/**
    @brief Notifies one thread waiting on the event
 */
inline void Event::Notify() noexcept
{
    mCv.notify_one();
}

/**
 @brief Notifies all threads waiting on the event
 */
inline void Event::NotifyAll() noexcept
{
    mCv.notify_all();
}

/**
    @brief Returns a reference to the mutex used by this event.
    @return Reference to the internal mutex.
    @details This allows external locking of the mutex for use cases such as a producer / consumer where
             the producer locks, writes, and notifies and the consumer waits and reads.
 */
inline std::mutex &Event::GetMutex() noexcept
{
    return mMutex;
}

} // namespace clv

#endif // CLV_CORE_EVENT_H
