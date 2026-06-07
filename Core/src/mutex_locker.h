// Copyright (c) 2023- Charlie Vigue. All rights reserved.


#ifndef CLV_MUTEXLOCKER_H
#define CLV_MUTEXLOCKER_H

#include "optional_ref.h"

namespace clv {
/**
 * @brief Proxy object for mutex protected access
 *
 * This defines a template struct called MutexLocker, which acts as a wrapper for an object of type
 * TYPE and a mutex object of type LOCK. It provides a convenient way to lock and unlock the mutex while
 * accessing or modifying the underlying object. It is not meant to be foolproof or impregnable. It IS
 * meant to be a forced reminder to lock before access.
 *
 * Provides a handle allowing access to a mutex protected object. Mutex is unlocked when this handle
 * goes out of scope. Access is possible but not recommended without locking in cases where try fails
 * or defer is used.
 *
 * The constructor:
 *
 * The constructor of MutexLocker takes a reference to an object of type TYPE and forwards any additional
 * arguments (ArgsT &&...args) to construct the LOCK object. It initializes mObj with the provided object
 * reference (mObj(m)), and mLocker with the forwarded arguments (mLocker(std::forward<ArgsT>(args)...)).
 *
 * The public member functions:
 *
 * lock(), unlock(), try_lock(), and owns_lock(): These functions provide access to the corresponding
 * functions of the LOCK object. They allow locking, unlocking, and checking the lock status of the
 * associated mutex.
 *
 * get(): Returns a reference to the underlying object of type TYPE.
 *
 * operator->(): Overloads the arrow operator (->) to provide a pointer-like access to the underlying object.
 *
 * operator*(): Overloads the dereference operator (*) to provide access to the underlying object.
 *
 * operator bool(): Returns true if the mutex is locked by us
 *
 * The private members:
 *
 * mObj: Holds a reference to the wrapped object of type TYPE.
 * mLocker: Represents the locker object of type LOCK associated with the mutex.
 *
 * The MutexLocker struct acts as a bridge between the mutex and the wrapped object, allowing for easy
 * synchronization and controlled access to the object. By locking the mutex using the lock() function, the
 * wrapped object can be safely accessed or modified. Once the lock is no longer needed, it can be released
 * using the unlock() function.
 *
 * This code can be particularly useful in scenarios where multiple threads need synchronized access to a
 * shared resource while providing a concise and easy-to-use interface for managing the locking mechanism.
 *
 * @tparam TYPE  Type of the protected object.
 * @tparam MUTEX Mutex type that should be used for protection.
 * @tparam LOCK  Scoped lock type
 * @note A clever person can get around this mutex. If you're being clever be sure you're clever enough.
 */
template <typename TYPE, typename MUTEX, typename LOCK>
struct MutexLocker
{
    using value_type = TYPE;
    using mutex_type = MUTEX;
    using lock_type = LOCK;

    ~MutexLocker() = default;

    template <typename... ArgsT>
    MutexLocker(TYPE &m, ArgsT &&...args) noexcept;

    MutexLocker(const MutexLocker &) = delete;
    MutexLocker(MutexLocker &&) = default;
    MutexLocker &operator=(const MutexLocker &) = delete;
    MutexLocker &operator=(MutexLocker &&) = default;

    explicit operator bool() const noexcept;

    void lock() noexcept;
    void unlock() noexcept;
    bool try_lock() noexcept;
    bool owns_lock() const noexcept;
    TYPE &get() noexcept;
    const TYPE &get() const noexcept;
    optional_ref<TYPE &> try_get() noexcept;
    optional_ref<const TYPE &> try_get() const noexcept;
    TYPE *operator->() noexcept;
    const TYPE *operator->() const noexcept;
    TYPE &operator*() noexcept;
    const TYPE &operator*() const noexcept;

  private:
    TYPE &mObj;
    LOCK mLocker;
};

/**
 * @brief Constructor for MutexLocker.
 * @note Forwards args, if any, to the type being instantiated.
 * @tparam TYPE     The underlying value type
 * @tparam MUTEX    Type of the mutex in use
 * @tparam LOCK     Type of locking object to use
 * @tparam ArgsT Variadic template parameter pack for constructor arguments.
 * @param m Reference to the object to be locked.
 * @param args Constructor arguments for the lock object.
 */
template <typename TYPE, typename MUTEX, typename LOCK>
template <typename... ArgsT>
MutexLocker<TYPE, MUTEX, LOCK>::MutexLocker(TYPE &m, ArgsT &&...args) noexcept
    : mObj(m), mLocker(std::forward<ArgsT>(args)...)
{
}
/**
 * @brief Evaluates to true if the mutex is owned by us.
 * @tparam TYPE     The underlying value type
 * @tparam MUTEX    Type of the mutex in use
 * @tparam LOCK     Type of locking object to use
 * @return true     If the mutex is locked by us
 * @return false    If the mutex is not locked by us
 */
template <typename TYPE, typename MUTEX, typename LOCK>
MutexLocker<TYPE, MUTEX, LOCK>::operator bool() const noexcept
{
    return owns_lock();
}

/**
 * @brief Locks the associated mutex.
 * @tparam TYPE     The underlying value type
 * @tparam MUTEX    Type of the mutex in use
 * @tparam LOCK     Type of locking object to use
 */
template <typename TYPE, typename MUTEX, typename LOCK>
void MutexLocker<TYPE, MUTEX, LOCK>::lock() noexcept
{
    mLocker.lock();
}

/**
 * @brief Unlocks the associated mutex.
 * @tparam TYPE     The underlying value type
 * @tparam MUTEX    Type of the mutex in use
 * @tparam LOCK     Type of locking object to use
 */
template <typename TYPE, typename MUTEX, typename LOCK>
void MutexLocker<TYPE, MUTEX, LOCK>::unlock() noexcept
{
    mLocker.unlock();
}

/**
 * @brief Attempts to acquire a lock on the associated mutex.
 * @tparam TYPE     The underlying value type
 * @tparam MUTEX    Type of the mutex in use
 * @tparam LOCK     Type of locking object to use
 * @return True if the lock was acquired successfully, false otherwise.
 */
template <typename TYPE, typename MUTEX, typename LOCK>
bool MutexLocker<TYPE, MUTEX, LOCK>::try_lock() noexcept
{
    return mLocker.try_lock();
}

/**
 * @brief Checks if the MutexLocker owns the lock.
 * @tparam TYPE     The underlying value type
 * @tparam MUTEX    Type of the mutex in use
 * @tparam LOCK     Type of locking object to use
 * @return True if the MutexLocker owns the lock, false otherwise.
 */
template <typename TYPE, typename MUTEX, typename LOCK>
bool MutexLocker<TYPE, MUTEX, LOCK>::owns_lock() const noexcept
{
    return mLocker.owns_lock();
}

/**
 * @brief Returns a reference to the object being locked.
 * @tparam TYPE     The underlying value type
 * @tparam MUTEX    Type of the mutex in use
 * @tparam LOCK     Type of locking object to use
 * @return Reference to the object being locked.
 * @note Ensures the lock is owned by calling lock if not already locked.
 */
template <typename TYPE, typename MUTEX, typename LOCK>
TYPE &MutexLocker<TYPE, MUTEX, LOCK>::get() noexcept
{
    if (!owns_lock())
        lock();
    return mObj;
}

/**
 * @brief Returns a const reference to the object being locked.
 * @tparam TYPE     The underlying value type
 * @tparam MUTEX    Type of the mutex in use
 * @tparam LOCK     Type of locking object to use
 * @return Const reference to the object being locked.
 * @note Ensures the lock is owned by calling lock if not already locked.
 */
template <typename TYPE, typename MUTEX, typename LOCK>
const TYPE &MutexLocker<TYPE, MUTEX, LOCK>::get() const noexcept
{
    if (!owns_lock())
        lock();
    return mObj;
}

/**
 * @brief Provides access to the object being locked through the arrow operator.
 * @tparam TYPE     The underlying value type
 * @tparam MUTEX    Type of the mutex in use
 * @tparam LOCK     Type of locking object to use
 * @return Pointer to the object being locked.
 * @note Ensures the lock is owned by calling lock if not already locked.
 */
template <typename TYPE, typename MUTEX, typename LOCK>
TYPE *MutexLocker<TYPE, MUTEX, LOCK>::operator->() noexcept
{
    if (!owns_lock())
        lock();
    return &mObj;
}

/**
 * @brief Provides const access to the object being locked through the arrow operator.
 * @tparam TYPE     The underlying value type
 * @tparam MUTEX    Type of the mutex in use
 * @tparam LOCK     Type of locking object to use
 * @return Const pointer to the object being locked.
 * @note Ensures the lock is owned by calling lock if not already locked.
 */
template <typename TYPE, typename MUTEX, typename LOCK>
const TYPE *MutexLocker<TYPE, MUTEX, LOCK>::operator->() const noexcept
{
    if (!owns_lock())
        lock();
    return &mObj;
}

/**
 * @brief Dereferences the object being locked.
 * @tparam TYPE     The underlying value type
 * @tparam MUTEX    Type of the mutex in use
 * @tparam LOCK     Type of locking object to use
 * @return Reference to the object being locked.
 * @note Ensures the lock is owned by calling lock if not already locked.
 */
template <typename TYPE, typename MUTEX, typename LOCK>
TYPE &MutexLocker<TYPE, MUTEX, LOCK>::operator*() noexcept
{
    return get();
}

/**
 * @brief Dereferences the object being locked (const version).
 * @tparam TYPE     The underlying value type
 * @tparam MUTEX    Type of the mutex in use
 * @tparam LOCK     Type of locking object to use
 * @return Const reference to the object being locked.
 * @note Ensures the lock is owned by calling lock if not already locked.
 */
template <typename TYPE, typename MUTEX, typename LOCK>
const TYPE &MutexLocker<TYPE, MUTEX, LOCK>::operator*() const noexcept
{
    return get();
}

/**
 * @brief Attempts to get a reference to the object being locked.
 * @tparam TYPE     The underlying value type
 * @tparam MUTEX    Type of the mutex in use
 * @tparam LOCK     Type of locking object to use
 * @return Optional reference to the object being locked.
 * @note Returns std::nullopt if the lock cannot be acquired.
 */
template <typename TYPE, typename MUTEX, typename LOCK>
optional_ref<TYPE &> MutexLocker<TYPE, MUTEX, LOCK>::try_get() noexcept
{
    return owns_lock() || try_lock() ? optional_ref<TYPE &>(mObj)
                                     : optional_ref<TYPE &>(std::nullopt);
}

/**
 * @brief Attempts to get a const reference to the object being locked.
 * @tparam TYPE     The underlying value type
 * @tparam MUTEX    Type of the mutex in use
 * @tparam LOCK     Type of locking object to use
 * @return Optional const reference to the object being locked.
 * @note Returns std::nullopt if the lock cannot be acquired, value reference if
 *
 */
template <typename TYPE, typename MUTEX, typename LOCK>
optional_ref<const TYPE &> MutexLocker<TYPE, MUTEX, LOCK>::try_get() const noexcept
{
    return owns_lock() || try_lock() ? optional_ref<const TYPE &>(mObj)
                                     : optional_ref<const TYPE &>(std::nullopt);
}

} // namespace clv

#endif // CLV_MUTEXLOCKER_H