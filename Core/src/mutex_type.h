// Copyright (c) 2023- Charlie Vigue. All rights reserved.


#ifndef CLV_CORE_MUTEXTYPE_H
#define CLV_CORE_MUTEXTYPE_H

#include "mutex_locker.h"

#include <mutex>
#include <shared_mutex>

#include "spinlock.h"

namespace clv {
/**
    @brief A templated struct that provides mutex-protected access to an object of type TYPE.
    @tparam TYPE The type of the object to be protected by the mutex.
    @tparam MUTEX The type of the mutex to be used for protecting the object.
    @tparam RO_LOCK The type of the read-only lock to be used for read-only access.
    @tparam RW_LOCK The type of the read-write lock to be used for read-write access.
    @details defines several member functions for the MutexType struct. The purpose of these
             functions is to provide different ways to acquire locks on the underlying object
             (mObj) protected by the mutex (mMutex). These locks ensure thread-safe access
             to the shared resource.

    The output of these functions is an instance of the MutexLocker struct, which represents the
    acquired lock. This MutexLocker object can be used to safely access the protected object
    within its scope.

    The logic flow for these functions is straightforward. They create instances of the
    MutexLocker struct, passing the protected object (mObj) and the mutex (mMutex) as arguments,
    along with the appropriate lock type (read-only or read-write). The MutexLocker instances
    manage the acquisition and release of the locks, ensuring thread safety when accessing the
    protected object.

    No significant data transformations occur within these functions. They primarily serve as
    convenient wrappers around the locking mechanisms provided by the MutexLocker struct,
    allowing developers to easily acquire locks on the protected object in a thread-safe manner.
*/
template <typename TYPE, typename MUTEX, typename RO_LOCK, typename RW_LOCK>
struct MutexType
{
    using LockTypeRW = MutexLocker<TYPE, MUTEX, RW_LOCK>;
    using LockTypeRO = MutexLocker<const TYPE, MUTEX, RO_LOCK>;

  public:
    template <typename... ArgsT>
    MutexType(ArgsT &&...args) noexcept(noexcept(TYPE(std::forward<ArgsT>(args)...)));

  public:
    [[nodiscard]] auto Lock() noexcept;
    [[nodiscard]] auto LockRW() noexcept;
    [[nodiscard]] auto Lock() const noexcept;
    [[nodiscard]] auto LockRO() const noexcept;
    [[nodiscard]] auto Try() noexcept;
    [[nodiscard]] auto TryRW() noexcept;
    [[nodiscard]] auto Try() const noexcept;
    [[nodiscard]] auto TryRO() const noexcept;
    [[nodiscard]] auto Defer() noexcept;
    [[nodiscard]] auto DeferRW() noexcept;
    [[nodiscard]] auto Defer() const noexcept;
    [[nodiscard]] auto DeferRO() const noexcept;

  private:
    TYPE mObj;
    mutable MUTEX mMutex;
};

// *********************************************************************
//      Inlines for struct MutexType

/**
 @brief Constructs a MutexType object with the given arguments.
 @tparam ArgsT The types of the arguments to be forwarded to the constructor of TYPE.
 @param args The arguments to be forwarded to the constructor of TYPE.
 @throws Any exception thrown by the constructor of TYPE.
 @details The constructor forwards the given arguments to the constructor of TYPE and
          initializes the mutex member variable.
 */
template <typename TYPE, typename MUTEX, typename RO_LOCK, typename RW_LOCK>
template <typename... ArgsT>
inline MutexType<TYPE, MUTEX, RO_LOCK, RW_LOCK>::MutexType(ArgsT &&...args) noexcept(noexcept(TYPE(std::forward<ArgsT>(args)...)))
    : mObj(std::forward<ArgsT>(args)...), mMutex()
{
}

/** @brief Returns a read-write lock for the object.
    @tparam TYPE The type of the object being locked.
    @tparam MUTEX The type of the mutex used for locking.
    @tparam RO_LOCK The type of the read-only lock.
    @tparam RW_LOCK The type of the read-write lock.
    @return A MutexLocker object that holds a read-write lock on the object.
    @throws Nothing.
    @details Acquires a read-write lock on the mutex, allowing both read and write
             access to the protected object. It creates a MutexLocker instance
             with the appropriate lock type and returns it.
 */
template <typename TYPE, typename MUTEX, typename RO_LOCK, typename RW_LOCK>
[[nodiscard]] inline auto MutexType<TYPE, MUTEX, RO_LOCK, RW_LOCK>::LockRW() noexcept
{
    return MutexLocker<TYPE, MUTEX, RW_LOCK>(mObj, mMutex);
}

/** @brief Returns a lock for the object, either read-only or read-write depending on the const-ness of TYPE.
    @tparam TYPE The type of the object being locked.
    @tparam MUTEX The type of the mutex used for locking.
    @tparam RO_LOCK The type of the read-only lock.
    @tparam RW_LOCK The type of the read-write lock.
    @return A MutexLocker object that holds a lock on the object.
    @throws Nothing.
    @details Determines whether to acquire a read-only or read-write lock based on the
             constness of the protected object's type (TYPE). If TYPE is const, it calls
             LockRO() to acquire a read-only lock; otherwise, it calls LockRW() to
             acquire a read-write lock.
 */
template <typename TYPE, typename MUTEX, typename RO_LOCK, typename RW_LOCK>
[[nodiscard]] inline auto MutexType<TYPE, MUTEX, RO_LOCK, RW_LOCK>::Lock() noexcept
{
    if constexpr (std::is_const_v<TYPE>)
        return LockRO();
    else
        return LockRW();
}

/** @brief Returns a read-only lock for the object.
    @tparam TYPE The type of the object being locked.
    @tparam MUTEX The type of the mutex used for locking.
    @tparam RO_LOCK The type of the read-only lock.
    @tparam RW_LOCK The type of the read-write lock.
    @return A MutexLocker object that holds a read-only lock on the object.
    @throws Nothing.
    @details Acquires a read-only lock on the mutex, allowing read access to the protected
             object. It creates a MutexLocker instance with a const reference to the
             protected object and the appropriate read-only lock type, and returns it.
 */
template <typename TYPE, typename MUTEX, typename RO_LOCK, typename RW_LOCK>
[[nodiscard]] inline auto MutexType<TYPE, MUTEX, RO_LOCK, RW_LOCK>::LockRO() const noexcept
{
    return LockTypeRO(mObj, mMutex);
}

/** @brief Returns a read-only lock for the object.
    @tparam TYPE The type of the object being locked.
    @tparam MUTEX The type of the mutex used for locking.
    @tparam RO_LOCK The type of the read-only lock.
    @tparam RW_LOCK The type of the read-write lock.
    @return A MutexLocker object that holds a read-only lock on the object.
    @throws Nothing.
 */
template <typename TYPE, typename MUTEX, typename RO_LOCK, typename RW_LOCK>
[[nodiscard]] inline auto MutexType<TYPE, MUTEX, RO_LOCK, RW_LOCK>::Lock() const noexcept
{
    return LockRO();
}

/** @brief Attempts to acquire a read-write lock for the object.
    @tparam TYPE The type of the object being locked.
    @tparam MUTEX The type of the mutex used for locking.
    @tparam RO_LOCK The type of the read-only lock.
    @tparam RW_LOCK The type of the read-write lock.
    @return A MutexLocker object that holds a read-write lock on the object if
            successful, otherwise an empty MutexLocker.
    @throws Nothing.
    @details Attempts to acquire a read-write lock on the mutex without blocking. If
             the lock is successfully acquired, it returns a MutexLocker instance
             with the read-write lock; otherwise, it returns an empty MutexLocker
             instance.
 */
template <typename TYPE, typename MUTEX, typename RO_LOCK, typename RW_LOCK>
[[nodiscard]] inline auto MutexType<TYPE, MUTEX, RO_LOCK, RW_LOCK>::TryRW() noexcept
{
    return LockTypeRW(mObj, mMutex, std::try_to_lock_t());
}

/** @brief Attempts to acquire a lock for the object, either read-only or read-write depending on the const-ness of TYPE.
    @tparam TYPE The type of the object being locked.
    @tparam MUTEX The type of the mutex used for locking.
    @tparam RO_LOCK The type of the read-only lock.
    @tparam RW_LOCK The type of the read-write lock.
    @return A MutexLocker object that holds a lock on the object if successful, otherwise an empty MutexLocker.
    @throws Nothing.
    @details Determines whether to attempt acquiring a read-only or read-write lock based
             on the constness of the protected object's type (TYPE). If TYPE is const, it
             calls TryRO() to attempt acquiring a read-only lock; otherwise, it calls
             TryRW() to attempt acquiring a read-write lock.
 */
template <typename TYPE, typename MUTEX, typename RO_LOCK, typename RW_LOCK>
[[nodiscard]] inline auto MutexType<TYPE, MUTEX, RO_LOCK, RW_LOCK>::Try() noexcept
{
    if constexpr (std::is_const_v<TYPE>)
        return TryRO();
    else
        return TryRW();
}

/** @brief Try to acquire a read-only lock on the object.
    @tparam TYPE The type of the object being locked.
    @tparam MUTEX The type of the mutex used for locking.
    @tparam RO_LOCK The type of the read-only lock used.
    @tparam RW_LOCK The type of the read-write lock used.
    @return A MutexLocker object that holds the read-only lock on the object.
    @throws Nothing.
    @details This function attempts to acquire a read-only lock on the object using the
             specified mutex and lock types. If the lock is successfully acquired, a
             MutexLocker object is returned that holds the lock until it goes out of scope.
*/
template <typename TYPE, typename MUTEX, typename RO_LOCK, typename RW_LOCK>
[[nodiscard]] inline auto MutexType<TYPE, MUTEX, RO_LOCK, RW_LOCK>::TryRO() const noexcept
{
    return LockTypeRO(mObj, mMutex, std::try_to_lock_t());
}

/** @brief Try to acquire a read-only lock on the object.
    @tparam TYPE The type of the object being locked.
    @tparam MUTEX The type of the mutex used for locking.
    @tparam RO_LOCK The type of the read-only lock used.
    @tparam RW_LOCK The type of the read-write lock used.
    @return A MutexLocker object that holds the read-only lock on the object.
    @throws Nothing.
    @details This function is an alias for TryRO() and attempts to acquire a read-only lock
             on the object using the specified mutex and lock types. If the lock is
             successfully acquired, a MutexLocker object is returned that holds the lock
             until it goes out of scope.
*/
template <typename TYPE, typename MUTEX, typename RO_LOCK, typename RW_LOCK>
[[nodiscard]] inline auto MutexType<TYPE, MUTEX, RO_LOCK, RW_LOCK>::Try() const noexcept
{
    return TryRO();
}

/**
    @brief Defers acquiring a read-write lock on the mutex for the object.
    @tparam TYPE The type of the object to be locked.
    @tparam MUTEX The type of the mutex used for locking.
    @tparam RO_LOCK The type of the read-only lock used for locking.
    @tparam RW_LOCK The type of the read-write lock used for locking.
    @return A MutexLocker object that can be used to acquire the read-write lock later.
    @throws Nothing.
    @details This function creates a MutexLocker object with the std::defer_lock_t flag,
             which means that the lock is not acquired immediately. The lock can be acquired
             later by calling the lock() member function on the returned MutexLocker object.
 */
template <typename TYPE, typename MUTEX, typename RO_LOCK, typename RW_LOCK>
[[nodiscard]] inline auto MutexType<TYPE, MUTEX, RO_LOCK, RW_LOCK>::DeferRW() noexcept
{
    return LockTypeRW(mObj, mMutex, std::defer_lock_t());
}
/**
     @brief Defers access to the underlying data structure based on the constness of TYPE.
     @tparam TYPE The type of the underlying data structure.
     @tparam MUTEX The type of the mutex used for synchronization.
     @tparam RO_LOCK The type of the read-only lock used for synchronization.
     @tparam RW_LOCK The type of the read-write lock used for synchronization.
     @return A read-only or read-write lock guard, depending on the constness of TYPE.
     @throws Nothing.
     @details If TYPE is const, a read-only lock guard is returned. Otherwise, a read-write lock
              guard is returned. This allows for efficient synchronization based on the intended
              usage of the underlying data structure.
     */
template <typename TYPE, typename MUTEX, typename RO_LOCK, typename RW_LOCK>
[[nodiscard]] inline auto MutexType<TYPE, MUTEX, RO_LOCK, RW_LOCK>::Defer() noexcept
{
    if constexpr (std::is_const_v<TYPE>)
        return DeferRO();
    else
        return DeferRW();
}

/**
    @brief Defers read-only lock acquisition for the underlying object.
    @tparam TYPE The type of the underlying object.
    @tparam MUTEX The type of the mutex used for locking.
    @tparam RO_LOCK The type of the shared lock used for read-only access.
    @tparam RW_LOCK The type of the unique lock used for read-write access.
    @return A MutexLocker object that represents a deferred read-only lock on the underlying object.
    @throws Nothing.
    @details This function returns a MutexLocker object that represents a deferred read-only lock
             on the underlying object. The lock is not acquired until the MutexLocker object is
             used in a lock guard or explicitly locked.
*/
template <typename TYPE, typename MUTEX, typename RO_LOCK, typename RW_LOCK>
[[nodiscard]] inline auto MutexType<TYPE, MUTEX, RO_LOCK, RW_LOCK>::DeferRO() const noexcept
{
    return LockTypeRO(mObj, mMutex, std::defer_lock_t());
}

/**
     @brief Defers read-only access to the underlying data.
     @tparam TYPE The type of the underlying data.
     @tparam MUTEX The mutex type used for synchronization.
     @tparam RO_LOCK The read-only lock type used for synchronization.
     @tparam RW_LOCK The read-write lock type used for synchronization.
     @return A read-only lock guard that provides deferred access to the underlying data.
     @throws Nothing.
     @details This function returns a read-only lock guard that provides deferred access to the
              underlying data. The lock guard is acquired when the returned object is constructed,
              and released when the object is destroyed.
*/
template <typename TYPE, typename MUTEX, typename RO_LOCK, typename RW_LOCK>
[[nodiscard]] inline auto MutexType<TYPE, MUTEX, RO_LOCK, RW_LOCK>::Defer() const noexcept
{
    return DeferRO();
}
/**
    @brief Alias for MutexType using std::shared_mutex for mutual exclusion
    @tparam TYPE The type to be protected by the mutex
*/
template <typename TYPE>
using SharedMutexType = MutexType<TYPE, std::shared_mutex, std::shared_lock<std::shared_mutex>, std::unique_lock<std::shared_mutex>>;

/**
    @brief Alias for MutexType using std::mutex, std::unique_lock<std::mutex>, and
           std::unique_lock<std::mutex>
    @tparam TYPE The type to be used for the mutex
*/
template <typename TYPE>
using UniqueMutexType = MutexType<TYPE, std::mutex, std::unique_lock<std::mutex>, std::unique_lock<std::mutex>>;

/**
    @brief Alias for MutexType instantiated with spinlock and std::unique_lock
    @tparam TYPE The data type to be protected by the mutex
*/
template <typename TYPE>
using SpinlockType = MutexType<TYPE, spinlock, std::unique_lock<spinlock>, std::unique_lock<spinlock>>;


} // namespace clv

#endif // CLV_CORE_MUTEXTYPE_H
