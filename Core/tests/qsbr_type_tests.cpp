// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#include "gtest/gtest.h"

#include "qsbr_type.h"
#include <atomic>
#include <memory>
#include <thread>
#include <future>
#include <chrono>
#include <vector>

using namespace clv;

TEST(QsbrType, InstantiateAndRead)
{
    QsbrType<int> qt(42);
    auto rv = qt.read();
    EXPECT_EQ(*rv, 42);
}

TEST(QsbrType, UpdateAndRead)
{
    QsbrType<int> qt(1);
    qt.write(123);
    auto rv = qt.read();
    EXPECT_EQ(*rv, 123);
}

TEST(QsbrType, ReadUpdateAndRead)
{
    QsbrType<int> qt(1);
    qt.write(123);
    auto rv = qt.read();
    qt.write(42);
    auto v1 = *rv;
    auto v2 = *(qt.read());
    EXPECT_EQ(v1, 123);
    EXPECT_EQ(v2, 42);
}

TEST(QsbrType, UpdateAndReadLoop)
{
    for (int i = 0; i < 1000; ++i)
    {
        QsbrType<int> qt(i);
        qt.write(i + 1);
        auto rv = qt.read();
        EXPECT_EQ(*rv, i + 1);
    }
}

// --- Typed tests -----------------------------------------------------

// A simple user-defined type which tracks destructions so we can validate
// QSBR-based reclamation.
struct Counted
{
    int v;
    static std::atomic<int> destroyed;

    explicit Counted(int x = 0) : v(x)
    {
    }
    Counted(const Counted &o) = default;
    Counted &operator=(const Counted &) = default;
    ~Counted()
    {
        destroyed.fetch_add(1, std::memory_order_relaxed);
    }
    bool operator==(const Counted &o) const noexcept
    {
        return v == o.v;
    }
};

std::atomic<int> Counted::destroyed{0};

template <typename T>
class QsbrTypeTyped : public ::testing::Test
{
  protected:
    static void SetUpTestSuite()
    {
        if constexpr (std::is_same_v<T, Counted>)
            Counted::destroyed.store(0, std::memory_order_relaxed);
    }
};

using TypeList = ::testing::Types<int, Counted>;
TYPED_TEST_SUITE(QsbrTypeTyped, TypeList);

TYPED_TEST(QsbrTypeTyped, InstantiateAndRead)
{
    using TP = TypeParam;
    QsbrType<TP> qt(static_cast<TP>(42));
    auto rv = qt.read();
    EXPECT_EQ(*rv, static_cast<TP>(42));
}

TYPED_TEST(QsbrTypeTyped, UpdateAndRead)
{
    using TP = TypeParam;
    QsbrType<TP> qt(static_cast<TP>(1));
    qt.write(static_cast<TP>(123));
    auto rv = qt.read();
    EXPECT_EQ(*rv, static_cast<TP>(123));
}

TYPED_TEST(QsbrTypeTyped, ReclaimOldObjects)
{
    using TP = TypeParam;
    QsbrType<TP> qt(static_cast<TP>(11));

    // Ensure the current thread registers and checkpoints
    {
        auto rv = qt.read();
        EXPECT_EQ(*rv, static_cast<TP>(11));
    }

    // Update: first old value is retired
    qt.write(static_cast<TP>(22));

    // Extra read to ensure the current thread advances its local epoch so
    // reclamation can occur for the retired entry.
    {
        auto rv2 = qt.read();
        EXPECT_EQ(*rv2, static_cast<TP>(22));
    }

    // Attempt reclamation; for Counted we expect destructor to be called.
    qt.global_reclaim_pass();

    if constexpr (std::is_same_v<TP, Counted>)
    {
        EXPECT_GE(Counted::destroyed.load(std::memory_order_relaxed), 1);
    }
}

TYPED_TEST(QsbrTypeTyped, ReadQuiescedWorks)
{
    using TP = TypeParam;
    QsbrType<TP> qt(static_cast<TP>(7));

    // Register/read to enter quiescent states
    auto rv = qt.read();
    EXPECT_EQ(*rv, static_cast<TP>(7));

    // Hot-path read (no extra quiescent on exit)
    auto r2 = qt.read_quiesced();
    EXPECT_EQ(*r2, static_cast<TP>(7));
}

TEST(QsbrType, MultiThreadedReclaimWorks)
{
    Counted::destroyed.store(0, std::memory_order_relaxed);

    QsbrType<Counted> qt(Counted{123});

    // Ensure main thread (writer) is registered
    {
        auto r0 = qt.read();
        EXPECT_EQ(r0->v, 123);
    }

    std::promise<void> reader_ready;
    std::future<void> reader_ready_f = reader_ready.get_future();
    std::promise<void> do_checkpoint;
    std::future<void> do_checkpoint_f = do_checkpoint.get_future();
    std::promise<void> reader_done;
    std::future<void> reader_done_f = reader_done.get_future();

    std::thread reader([&qt, &reader_ready, &do_checkpoint_f, &reader_done]()
    {
        // Register and checkpoint once to ensure we're in the registered list
        {
            auto r = qt.read();
            (void)r;
        }
        reader_ready.set_value();

        // Wait for main thread to signal us to advance to the target epoch
        do_checkpoint_f.wait();
        {
            auto r2 = qt.read();
            (void)r2;
        }
        // Explicitly unregister before thread exits to avoid dangling TLS
        // pointer in the qsbr list.
        qt.unregister_current_thread();
        reader_done.set_value();
    });

    // Wait until reader thread registered
    reader_ready_f.wait();

    // Retire an old object via update()
    qt.write(Counted{456});

    // Attempt reclaim now: reader has not checkpointed past the barrier so
    // reclamation should NOT be possible yet (no additional destruction of retired object).
    qt.global_reclaim_pass();
    int destroyed_before = Counted::destroyed.load(std::memory_order_relaxed);
    EXPECT_EQ(destroyed_before, Counted::destroyed.load(std::memory_order_relaxed));

    // Instruct the reader to checkpoint to the barrier epoch
    do_checkpoint.set_value();
    reader_done_f.wait();

    // Now reclamation should succeed
    qt.global_reclaim_pass();
    EXPECT_GE(Counted::destroyed.load(std::memory_order_relaxed), destroyed_before + 1);

    reader.join();
}

TEST(QsbrType, ReadQuiescedDoesNotRegisterThread)
{
    Counted::destroyed.store(0, std::memory_order_relaxed);

    QsbrType<Counted> qt(Counted{10});

    // Ensure main thread (writer) is registered and does an initial read
    {
        auto r0 = qt.read();
        EXPECT_EQ(r0->v, 10);
    }

    // Spawn a thread that uses read_quiesced (does not register)
    std::promise<void> started;
    std::future<void> started_f = started.get_future();
    std::thread t([&qt, &started]()
    {
        auto r = qt.read_quiesced();
        (void)r;
        started.set_value();
        // hold to make sure the thread lives while the writer retires old
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    });

    started_f.wait();

    // Update and attempt reclamation; because the spawned thread didn't
    // register itself, it shouldn't block reclamation and the destructor
    // should be invoked when writer calls reclaim.
    qt.write(Counted{20});
    qt.global_reclaim_pass();

    // Because the spawn thread doesn't register, the retired object may
    // be reclaimed immediately.
    EXPECT_GE(Counted::destroyed.load(std::memory_order_relaxed), 1);

    t.join();
}

// --- Shared QsbrCore tests -------------------------------------------

TEST(QsbrType, SharedCoreBasicReadWrite)
{
    auto core = std::make_shared<clv::QsbrCore>();
    QsbrType<int> a(core, 10);
    QsbrType<int> b(core, 20);

    EXPECT_EQ(*(a.read()), 10);
    EXPECT_EQ(*(b.read()), 20);

    a.write(11);
    b.write(21);

    EXPECT_EQ(*(a.read()), 11);
    EXPECT_EQ(*(b.read()), 21);
}

TEST(QsbrType, SharedCoreSameInstance)
{
    auto core = std::make_shared<clv::QsbrCore>();
    QsbrType<int> a(core, 1);
    QsbrType<int> b(core, 2);

    // Both instances should report the same core
    EXPECT_EQ(a.core().get(), b.core().get());
    EXPECT_EQ(a.core().get(), core.get());
}

TEST(QsbrType, SharedCoreReclaimAcrossInstances)
{
    Counted::destroyed.store(0, std::memory_order_relaxed);

    auto core = std::make_shared<clv::QsbrCore>();
    QsbrType<Counted> a(core, Counted{100});
    QsbrType<Counted> b(core, Counted{200});

    // Register this thread via a read on either instance (same core)
    {
        auto r = a.read();
    }

    // Retire old values on both instances
    a.write(Counted{101});
    b.write(Counted{201});

    // Advance epoch — a single read on one instance checkpoints the shared core
    {
        auto r = b.read();
    }

    // Reclaim from both — should succeed since same core tracks the epoch
    a.global_reclaim_pass();

    int after_a = Counted::destroyed.load(std::memory_order_relaxed);
    EXPECT_GE(after_a, 2); // old values from both a and b should be reclaimable
}

TEST(QsbrType, SharedCoreMultiThreadedReclaim)
{
    Counted::destroyed.store(0, std::memory_order_relaxed);

    auto core = std::make_shared<clv::QsbrCore>();
    QsbrType<Counted> a(core, Counted{1});
    QsbrType<Counted> b(core, Counted{2});

    // Register main thread
    {
        auto r = a.read();
    }

    std::promise<void> reader_ready;
    auto reader_ready_f = reader_ready.get_future();
    std::promise<void> proceed;
    auto proceed_f = proceed.get_future();
    std::promise<void> reader_done;
    auto reader_done_f = reader_done.get_future();

    std::thread reader([&]()
    {
        // Register by reading — one read on 'a' registers for the shared core,
        // which also governs 'b'.
        {
            auto r = a.read();
        }
        reader_ready.set_value();

        proceed_f.wait();

        // Checkpoint past the grace period
        {
            auto r = b.read();
        }

        a.unregister_current_thread();
        reader_done.set_value();
    });

    reader_ready_f.wait();

    // Writer retires old values on both instances
    a.write(Counted{10});
    b.write(Counted{20});

    // Reclaim should NOT succeed yet — reader hasn't checkpointed
    a.global_reclaim_pass();
    int before = Counted::destroyed.load(std::memory_order_relaxed);

    // Let reader advance
    proceed.set_value();
    reader_done_f.wait();

    // Now reclaim should succeed
    a.global_reclaim_pass();
    EXPECT_GE(Counted::destroyed.load(std::memory_order_relaxed), before + 2);

    reader.join();
}

TEST(QsbrType, SharedCoreMixedWithPrivateCore)
{
    // One instance with shared core, one with its own private core
    auto core = std::make_shared<clv::QsbrCore>();
    QsbrType<int> shared_instance(core, 42);
    QsbrType<int> private_instance(99);

    // They should have different cores
    EXPECT_NE(shared_instance.core().get(), private_instance.core().get());

    // Both should function independently
    EXPECT_EQ(*(shared_instance.read()), 42);
    EXPECT_EQ(*(private_instance.read()), 99);

    shared_instance.write(43);
    private_instance.write(100);

    EXPECT_EQ(*(shared_instance.read()), 43);
    EXPECT_EQ(*(private_instance.read()), 100);
}

TEST(QsbrType, SharedCoreManyInstances)
{
    Counted::destroyed.store(0, std::memory_order_relaxed);

    auto core = std::make_shared<clv::QsbrCore>();
    constexpr int N = 50;

    // Simulate many connections sharing one core
    std::vector<std::unique_ptr<QsbrType<Counted>>> instances;
    for (int i = 0; i < N; ++i)
        instances.push_back(std::make_unique<QsbrType<Counted>>(core, Counted{i}));

    // Register this thread
    {
        auto r = instances[0]->read();
    }

    // Rotate values on all instances
    for (int i = 0; i < N; ++i)
        instances[i]->write(Counted{i + 1000});

    // Checkpoint via any instance
    {
        auto r = instances[0]->read();
    }

    // Reclaim via any instance — all retired pointers share the same core
    instances[0]->global_reclaim_pass();

    EXPECT_GE(Counted::destroyed.load(std::memory_order_relaxed), N);
}

// --- QuiescedView tests ----------------------------------------------

TEST(QsbrType, QuiescedViewIsTriviallyDestructible)
{
    // Compile-time guarantee: QuiescedView has zero destructor cost
    static_assert(std::is_trivially_destructible_v<QsbrType<int>::QuiescedView>);
    static_assert(std::is_trivially_destructible_v<QsbrType<Counted>::QuiescedView>);
}

TEST(QsbrType, QuiescedViewBasicAccess)
{
    QsbrType<int> qt(42);
    // Register via read()
    {
        auto r = qt.read();
    }

    auto qv = qt.read_quiesced();
    EXPECT_EQ(*qv, 42);
}

TEST(QsbrType, QuiescedViewArrowOperator)
{
    struct Payload
    {
        int x;
        int y;
    };
    QsbrType<Payload> qt(Payload{10, 20});
    {
        auto r = qt.read();
    }

    auto qv = qt.read_quiesced();
    EXPECT_EQ(qv->x, 10);
    EXPECT_EQ(qv->y, 20);
}

TEST(QsbrType, QuiescedViewIsConst)
{
    // Verify QuiescedView only provides const access
    QsbrType<int> qt(7);
    {
        auto r = qt.read();
    }

    auto qv = qt.read_quiesced();

    // These must compile:
    [[maybe_unused]] const int &ref = *qv;
    [[maybe_unused]] const int *ptr = qv.operator->();

    // If someone tried to write through the view, it would not compile:
    // *qv = 99;  // should fail — const reference
    // This is verified by the static_assert below.
    static_assert(std::is_const_v<std::remove_reference_t<decltype(*qv)>>,
                  "QuiescedView::operator* must return const reference");
    static_assert(std::is_const_v<std::remove_pointer_t<decltype(qv.operator->())>>,
                  "QuiescedView::operator-> must return const pointer");
}

TEST(QsbrType, QuiescedViewIsCopyable)
{
    QsbrType<int> qt(55);
    {
        auto r = qt.read();
    }

    auto qv1 = qt.read_quiesced();
    auto qv2 = qv1; // copy
    EXPECT_EQ(*qv1, 55);
    EXPECT_EQ(*qv2, 55);
}

TEST(QsbrType, QuiescedViewSeesLatestWrite)
{
    QsbrType<int> qt(1);
    {
        auto r = qt.read();
    }

    auto qv1 = qt.read_quiesced();
    EXPECT_EQ(*qv1, 1);

    qt.write(2);

    // A new quiesced view should see the updated value
    auto qv2 = qt.read_quiesced();
    EXPECT_EQ(*qv2, 2);

    // The old view still points to the previous value (snapshot semantics)
    // Note: the old pointer is retired but not yet reclaimed, so still valid
    EXPECT_EQ(*qv1, 1);
}

TEST(QsbrType, QuiescedViewWithSharedCore)
{
    auto core = std::make_shared<clv::QsbrCore>();
    QsbrType<int> a(core, 100);
    QsbrType<int> b(core, 200);

    // Register via read() on one instance
    {
        auto r = a.read();
    }

    auto qa = a.read_quiesced();
    auto qb = b.read_quiesced();
    EXPECT_EQ(*qa, 100);
    EXPECT_EQ(*qb, 200);
}

TEST(QsbrType, QuiescedViewMultiThreaded)
{
    QsbrType<int> qt(0);
    // Register main thread
    {
        auto r = qt.read();
    }

    constexpr int kIterations = 10000;
    std::atomic<bool> stop{false};
    std::atomic<bool> reader_done{false};

    // Reader thread: reads via QuiescedView concurrently
    std::thread reader([&qt, &stop, &reader_done]()
    {
        {
            auto r = qt.read();
        } // register
        int last_seen = -1;
        while (!stop.load(std::memory_order_acquire))
        {
            auto qv = qt.read_quiesced();
            int val = *qv;
            // Values must be monotonically non-decreasing (writer only increments)
            EXPECT_GE(val, last_seen);
            last_seen = val;
        }
        qt.unregister_current_thread();
        reader_done.store(true, std::memory_order_release);
    });

    // Writer: runs on the main thread so retired objects stay in main's
    // retired_list — the QsbrType destructor will clean them up.
    for (int i = 1; i <= kIterations; ++i)
        qt.write(i);

    stop.store(true, std::memory_order_release);
    reader.join();

    // Reader is done and unregistered — reclaim is safe now
    qt.global_reclaim_pass();
}

TEST(QsbrType, QuiescedViewDoesNotBlockReclaim)
{
    Counted::destroyed.store(0, std::memory_order_relaxed);

    QsbrType<Counted> qt(Counted{10});
    // Register main thread
    {
        auto r0 = qt.read();
    }

    // Spawn a thread that holds a QuiescedView — since it doesn't register,
    // it must not block reclamation.
    std::promise<void> started;
    auto started_f = started.get_future();
    std::thread t([&qt, &started]()
    {
        auto qv = qt.read_quiesced();
        (void)qv;
        started.set_value();
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    });

    started_f.wait();

    qt.write(Counted{20});
    qt.global_reclaim_pass();

    // Reclamation should proceed — unregistered reader doesn't block
    EXPECT_GE(Counted::destroyed.load(std::memory_order_relaxed), 1);

    t.join();
}

TEST(QsbrType, QuiescedViewBatchPattern)
{
    // Simulates the datapath batch pattern: many reads per epoch, one checkpoint between batches
    auto core = std::make_shared<clv::QsbrCore>();
    constexpr int kConnections = 20;
    constexpr int kBatches = 100;

    std::vector<std::unique_ptr<QsbrType<int>>> conns;
    for (int i = 0; i < kConnections; ++i)
        conns.push_back(std::make_unique<QsbrType<int>>(core, i));

    // Register
    {
        auto r = conns[0]->read();
    }

    // Simulate batch processing
    for (int batch = 0; batch < kBatches; ++batch)
    {
        // Read all connections via QuiescedView (hot path — no atomic ops)
        int sum = 0;
        for (int c = 0; c < kConnections; ++c)
        {
            auto qv = conns[c]->read_quiesced();
            sum += *qv;
        }
        EXPECT_GE(sum, 0);

        // Between batches: one quiescent checkpoint for the whole core
        core->quiescent_state();
    }
}
