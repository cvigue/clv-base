// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLVLIB_CORE_QSBRTYPE_H
#define CLVLIB_CORE_QSBRTYPE_H

#include <atomic>
#include <type_traits>
#include <utility>
#include <vector>
#include <cstdint>
#include <memory>
#include <algorithm>
#include <unordered_set>
#include <concepts>

#include <qsbr.h> // the QSBR core - libqsbr

/**
 * @file QsbrType.h
 * @brief QsbrType: A QSBR-protected pointer type for concurrent read-mostly access.
 * @details Provides a template class for managing pointers with QSBR (Quiescent State Based Reclamation)
 * protection, enabling safe concurrent read-mostly access patterns. It includes mechanisms for registering
 * threads, performing reads with quiescent state tracking, and updating the protected pointer with safe
 * reclamation of old versions.
 * @note This implementation relies on the libqsbr library for the underlying QSBR mechanics.
 * @note Mostly for educational use so far.
 */

namespace clv {

/**
 * @class QsbrCore
 * @brief Wrapper around the libqsbr core functionality.
 * @details Manages the lifecycle of a qsbr_t instance, providing methods for thread
 * registration, quiescent state indication, and grace period management.
 */
class QsbrCore
{
  public:
    QsbrCore();
    ~QsbrCore();

    void quiescent_state();
    uint64_t begin_grace_period();
    bool can_reclaim(uint64_t epoch);

    void register_thread();
    void unregister_thread();

  private:
    qsbr_t *qsbr_ = nullptr;
};

/**
 * @class QsbrType
 * @brief A QSBR-protected pointer type for concurrent read-mostly access.
 * @tparam T The type of the object being protected.
 * @details This class provides a pointer type that allows multiple threads to read
 * concurrently while enabling safe updates and reclamation of old versions using
 * Quiescent State Based Reclamation (QSBR). It leverages the QsbrCore class for QSBR
 * management and includes per-thread limbo lists for retired objects.
 */
template <typename T>
class QsbrType
{
  private:
    /**
     * @struct RetiredPtr
     * @brief Represents a retired pointer along with its associated epoch and QsbrCore reference.
     * @details Used to track pointers that have been replaced and are pending reclamation.
     */
    struct RetiredPtr
    {
        T *ptr;
        uint64_t epoch;
        std::shared_ptr<QsbrCore> core; // track which core this belongs to
    };

  private:
    // Per-thread list of retired pointers pending reclamation.
    thread_local static inline std::vector<RetiredPtr> retired_list;

    // Per-thread set of instances this thread has registered with.
    thread_local static inline std::unordered_set<QsbrCore *> registered_instances;

  private:
    void retire(T *old);

    // Call this periodically (background thread, per-request, etc.)
    static void reclaim();

    // The actual protected pointer
    alignas(64) std::atomic<T *> current_{nullptr};

    // Shared QSBR core instance
    std::shared_ptr<QsbrCore> core_{std::make_shared<QsbrCore>()};

  public:
    /**
     * @brief Constructs a QsbrType with an initial value and its own QsbrCore.
     * @tparam Args Variadic template parameters for constructing the initial value.
     * @param args Arguments forwarded to the constructor of T.
     * @note This constructor is disabled if a single argument of type QsbrType is passed,
     *       to prevent accidental copy/move construction.
     */
    template <typename... Args>
        requires(!(sizeof...(Args) == 1 && (std::same_as<std::decay_t<Args>, QsbrType> && ...)))
    explicit QsbrType(Args &&...args);

    /**
     * @brief Constructs a QsbrType with an initial value and an externally-supplied QsbrCore.
     * @param core Shared QsbrCore instance — multiple QsbrType objects may share the same
     *             core so that a single quiescent checkpoint advances all their epochs.
     * @param args Arguments forwarded to the constructor of T.
     */
    template <typename... Args>
    explicit QsbrType(std::shared_ptr<QsbrCore> core, Args &&...args);

    // Non-copyable, non-movable
    QsbrType(const QsbrType &) = delete;
    QsbrType &operator=(const QsbrType &) = delete;
    QsbrType(QsbrType &&) = delete;
    QsbrType &operator=(QsbrType &&) = delete;

    ~QsbrType();

    /**
     * @class ReadView
     * @brief A read-only view into the QsbrType.
     * @details This class provides a way to access the underlying object
     * without allowing modifications. It ensures that the QSBR core is
     * properly engaged during the read operation.
     */
    class ReadView;

    /**
     * @class QuiescedView
     * @brief A zero-overhead, const, read-only snapshot of the QSBR-protected value.
     * @details Returned by read_quiesced(). Holds only a raw pointer — no atomic
     *          ref-count, no destructor side-effects. Trivially destructible.
     *
     *          **Epoch contract:** The pointed-to object is safe to dereference only
     *          within the current QSBR epoch — i.e. before the reading thread's next
     *          call to quiescent_state() or read(). After a quiescent checkpoint the
     *          writer is permitted to reclaim the old value, so any QuiescedView
     *          obtained before the checkpoint must not be dereferenced afterwards.
     *
     *          In practice this means: obtain the view, use it within a batch
     *          iteration, let it go out of scope, then checkpoint between batches.
     *          Do **not** stash a QuiescedView in a member variable across
     *          quiescent boundaries.
     */
    class QuiescedView;

    /**
     * @brief Normal read — enforces QsbrCore participation
     * @details This function provides a way to access the underlying object
     * without allowing modifications. It ensures that the QSBR core is
     * properly engaged during the read operation.
     */
    [[nodiscard]] ReadView read() const;

    /**
     * @brief Hot path read — assumes QsbrCore participation.
     * @details Returns a zero-overhead const QuiescedView. The caller must ensure:
     *          - The current thread is registered with the QsbrCore.
     *          - Quiescent states are signalled at appropriate boundaries
     *            (e.g. between batches via core->quiescent_state()).
     *          - The returned QuiescedView is **not** held across a quiescent
     *            checkpoint — after a checkpoint the underlying object may be
     *            reclaimed by the writer.
     * @return A trivially-destructible, const-only view of the current value.
     */
    [[nodiscard]] QuiescedView read_quiesced() const;

    /**
     * @brief Updates the current value with a new one.
     * @details This function replaces the current value with a new one,
     * ensuring that the QSBR core is properly engaged during the update.
     */
    void write(T new_value);

    /**
     * @brief Reclaims some retired objects.
     * @details This function attempts to reclaim retired objects that are no longer
     * in use.
     */
    void reclaim_some();

    /**
     * @brief Reclaims all retired objects.
     * @details This function attempts to reclaim all retired objects that are no longer
     * in use.
     */
    void global_reclaim_pass();

    /**
     * @brief Unregisters the current thread from this instance.
     * @details This function allows a thread to explicitly unregister from this
     * instance, preventing any dangling TLS pointers.
     */
    void unregister_current_thread();

    /**
     * @brief Force-deletes all retired pointers belonging to this instance's core.
     * @details Iterates the calling thread's retired_list and immediately frees
     *          every entry whose core matches this instance, without checking epochs.
     *          Safe to call only after all readers have stopped (i.e. during shutdown).
     *          Must be called from the same thread that performed write() operations.
     */
    void force_reclaim_for_core();

    /// Returns the QsbrCore used by this instance (for sharing with other instances).
    std::shared_ptr<QsbrCore> core() const noexcept
    {
        return core_;
    }
};

// ------------------------------------------------------------------
// QuiescedView
// ------------------------------------------------------------------
/**
 * @class QsbrType<T>::QuiescedView
 * @brief Zero-overhead, const-only snapshot returned by read_quiesced().
 * @details Holds a bare pointer — no shared_ptr copy, no atomic ref-count,
 *          no destructor side-effects. Trivially destructible.
 *
 *          **Epoch contract:** Valid only within the current QSBR epoch.
 *          Once the reading thread calls quiescent_state() or read(), the
 *          writer may reclaim the underlying object. Do not hold a
 *          QuiescedView across quiescent boundaries.
 *
 * @see QsbrType::read_quiesced()
 */
template <typename T>
class QsbrType<T>::QuiescedView
{
    const T *ptr;

    friend class QsbrType;
    explicit QuiescedView(const T *p) noexcept : ptr(p)
    {
    }

  public:
    QuiescedView(const QuiescedView &) = default;
    QuiescedView &operator=(const QuiescedView &) = default;

    const T *operator->() const noexcept
    {
        return ptr;
    }
    const T &operator*() const noexcept
    {
        return *ptr;
    }
};

static_assert(std::is_trivially_destructible_v<QsbrType<int>::QuiescedView>,
              "QuiescedView must be trivially destructible");

// ------------------------------------------------------------------
// ReadView
// ------------------------------------------------------------------
/**
 * @class QsbrType<T>::ReadView
 * @brief A read-only view into the QsbrType.
 * @details This class provides a way to access the underlying object
 * without allowing modifications. It ensures that the QSBR core is
 * properly engaged during the read operation.
 */
template <typename T>
class QsbrType<T>::ReadView
{
    T *ptr;
    bool need_quiescent_on_exit;
    std::shared_ptr<QsbrCore> core_ref;

    friend class QsbrType;
    ReadView(T *p, bool need_exit, std::shared_ptr<QsbrCore> core) noexcept;

  public:
    ~ReadView();
    ReadView(const ReadView &) = delete;
    ReadView &operator=(const ReadView &) = delete;

    // Access
    const T *operator->() const noexcept;
    T *operator->() noexcept;
    const T &operator*() const noexcept;
    T &operator*() noexcept;

    // Optional: allow implicit conversion if you want
    // operator const T&() const noexcept { return *ptr; }
};

// ------------------------------------------------------------------
// ReadView member function definitions
// ------------------------------------------------------------------

template <typename T>
QsbrType<T>::ReadView::ReadView(T *p, bool need_exit, std::shared_ptr<QsbrCore> core) noexcept
    : ptr(p), need_quiescent_on_exit(need_exit), core_ref(core)
{
}

template <typename T>
QsbrType<T>::ReadView::~ReadView()
{
    if (need_quiescent_on_exit)
        core_ref->quiescent_state();
}

template <typename T>
const T *QsbrType<T>::ReadView::operator->() const noexcept
{
    return ptr;
}

template <typename T>
T *QsbrType<T>::ReadView::operator->() noexcept
{
    return ptr;
}

template <typename T>
const T &QsbrType<T>::ReadView::operator*() const noexcept
{
    return *ptr;
}

template <typename T>
T &QsbrType<T>::ReadView::operator*() noexcept
{
    return *ptr;
}

// ------------------------------------------------------------------
// QsbrType member function definitions
// ------------------------------------------------------------------

template <typename T>
template <typename... Args>
    requires(!(sizeof...(Args) == 1 && (std::same_as<std::decay_t<Args>, QsbrType<T>> && ...)))
QsbrType<T>::QsbrType(Args &&...args)
{
    current_.store(new T(std::forward<Args>(args)...), std::memory_order_release);
}

template <typename T>
template <typename... Args>
QsbrType<T>::QsbrType(std::shared_ptr<QsbrCore> core, Args &&...args)
    : core_(std::move(core))
{
    current_.store(new T(std::forward<Args>(args)...), std::memory_order_release);
}

template <typename T>
QsbrType<T>::~QsbrType()
{
    T *p = current_.load(std::memory_order_relaxed);
    delete p; // final version is never retired

    // Force reclamation of all retired pointers for this core before unregistering.
    // In destructor, we don't care about epochs - we must clean up everything.
    auto &list = retired_list;
    for (auto it = list.begin(); it != list.end();)
    {
        if (it->core == core_)
        {
            delete it->ptr;
            it = list.erase(it);
        }
        else
        {
            ++it;
        }
    }

    // If this thread registered itself with this instance, unregister
    // so that the underlying qsbr_t does not have dangling TLS pointer
    // to this thread after we destroy it.
    if (registered_instances.find(core_.get()) != registered_instances.end())
    {
        core_->unregister_thread();
        registered_instances.erase(core_.get());
    }
}

template <typename T>
[[nodiscard]] typename QsbrType<T>::ReadView QsbrType<T>::read() const
{
    // Ensure the current thread is registered with this instance.
    if (registered_instances.find(core_.get()) == registered_instances.end())
    {
        core_->register_thread();
        registered_instances.insert(core_.get());
    }
    core_->quiescent_state(); // enter read-side critical section
    T *p = current_.load(std::memory_order_acquire);
    return ReadView{p, true, core_}; // need to call again on scope exit
}

template <typename T>
[[nodiscard]] typename QsbrType<T>::QuiescedView QsbrType<T>::read_quiesced() const
{
    const T *p = current_.load(std::memory_order_acquire);
    return QuiescedView{p};
}

template <typename T>
void QsbrType<T>::write(T new_value)
{
    T *nv = new T(std::move(new_value));
    T *old = current_.exchange(nv, std::memory_order_acq_rel);
    retire(old); // old version goes to per-thread limbo
}

template <typename T>
void QsbrType<T>::reclaim_some()
{
    reclaim();
}

template <typename T>
void QsbrType<T>::global_reclaim_pass()
{
    // In real code you’d iterate over all threads or use a lock-free queue.
    // For simplicity we just drain the current thread’s list.
    reclaim();
}

template <typename T>
void QsbrType<T>::unregister_current_thread()
{
    if (registered_instances.find(core_.get()) != registered_instances.end())
    {
        core_->unregister_thread();
        registered_instances.erase(core_.get());
    }
}

template <typename T>
void QsbrType<T>::force_reclaim_for_core()
{
    auto &list = retired_list;
    list.erase(
        std::remove_if(list.begin(), list.end(), [this](const RetiredPtr &rp)
    {
        if (rp.core == core_)
        {
            delete rp.ptr;
            return true;
        }
        return false;
    }),
        list.end());
}

template <typename T>
void QsbrType<T>::retire(T *old)
{
    if (!old)
        return;
    retired_list.push_back({old, core_->begin_grace_period(), core_});
}

template <typename T>
void QsbrType<T>::reclaim()
{
    auto &list = retired_list;
    if (list.empty())
        return;

    list.erase(
        std::remove_if(list.begin(), list.end(), [](const RetiredPtr &rp)
    {
        // qsbr_sync (called by can_reclaim) internally calls qsbr_checkpoint,
        // which requires the thread to be registered. Skip if not registered.
        if (registered_instances.find(rp.core.get()) == registered_instances.end())
            return false;

        if (rp.core->can_reclaim(rp.epoch))
        {
            delete rp.ptr;
            return true;
        }
        return false;
    }),
        list.end());
}

// ------------------------------------------------------------------
// QsbrCore member function definitions
// ------------------------------------------------------------------

inline QsbrCore::QsbrCore()
{
    qsbr_ = qsbr_create();
}

inline QsbrCore::~QsbrCore()
{
    qsbr_destroy(qsbr_);
}

inline void QsbrCore::quiescent_state()
{
    qsbr_checkpoint(qsbr_);
}

inline uint64_t QsbrCore::begin_grace_period()
{
    return static_cast<uint64_t>(qsbr_barrier(qsbr_));
}

inline bool QsbrCore::can_reclaim(uint64_t epoch)
{
    return qsbr_sync(qsbr_, static_cast<qsbr_epoch_t>(epoch));
}

inline void QsbrCore::register_thread()
{
    qsbr_register(qsbr_);
}

inline void QsbrCore::unregister_thread()
{
    qsbr_unregister(qsbr_);
}

} // namespace clv

#endif // CLVLIB_CORE_QSBRTYPE_H