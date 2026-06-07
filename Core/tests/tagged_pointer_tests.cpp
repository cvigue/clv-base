// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#include "gtest/gtest.h"
#include "tagged_pointer.h"

#include <thread>
#include <atomic>
#include <vector>

using namespace clv;

TEST(TaggedPointer, RoundTrip)
{
    int value = 42;
    int *ptr = &value;
    std::uint64_t tag = 1;

    auto packed = TaggedPointer(ptr, tag);
    auto unpacked = static_cast<int *>(packed);

    EXPECT_EQ(unpacked, ptr);
}

TEST(TaggedPointer, RoundTrip2)
{
    int value = 42;
    int *ptr = &value;
    std::uint64_t tag = 1;

    auto packed = TaggedPointer(ptr, tag);
    packed.touch_tag(); // Change the tag
    auto [p2, t2] = packed.split();

    EXPECT_EQ(p2, ptr);
    EXPECT_NE(t2, tag);
}

TEST(TaggedPointer, TagWrap)
{
    int value = 7;
    int *ptr = &value;
    using T = TaggedPointer<int>;

    auto max_tag = T::TAG_MASK;
    auto packed = T(ptr, max_tag);
    packed.touch_tag(); // should wrap
    auto [p2, t2] = packed.split();
    EXPECT_EQ(p2, ptr);
    EXPECT_EQ(t2, static_cast<std::uint64_t>(0));
}

TEST(TaggedPointer, RawAndBits)
{
    int value = 9;
    int *ptr = &value;
    using T = TaggedPointer<int>;

    auto packed = T(ptr, 2);
    auto raw = packed.raw();
    EXPECT_EQ((raw & T::TAG_MASK), static_cast<std::uintptr_t>(2));
    auto [p, tag] = packed.split();
    EXPECT_EQ(p, ptr);
    EXPECT_EQ(tag, 2);
}

TEST(TaggedPointer, CompareExchangeSuccessAndFailure)
{
    int a = 1;
    int b = 2;
    int *pa = &a;
    int *pb = &b;
    TaggedPointer<int> t(pa, 1);

    int *exp_ptr = pa;
    std::uint64_t exp_tag = 1;
    bool ok = t.compare_exchange_pointer_and_tag(exp_ptr, exp_tag, pb, 2);
    EXPECT_TRUE(ok);
    auto [cur_ptr, cur_tag] = t.split();
    EXPECT_EQ(cur_ptr, pb);
    EXPECT_EQ(cur_tag, 2);

    // attempt with wrong expected should fail and update expected
    exp_ptr = pa; // wrong pointer
    exp_tag = 1;
    ok = t.compare_exchange_pointer_and_tag(exp_ptr, exp_tag, pa, 3);
    EXPECT_FALSE(ok);
    EXPECT_EQ(exp_ptr, pb);
    EXPECT_EQ(exp_tag, 2);
}

TEST(TaggedPointer, CopyAndMove)
{
    int a = 42;
    using T = TaggedPointer<int>;
    T original(&a, 3);
    T copy = original;
    auto [cp, ct] = copy.split();
    EXPECT_EQ(cp, &a);
    EXPECT_EQ(ct, 3);

    T moved = std::move(original);
    auto [mp, mt] = moved.split();
    EXPECT_EQ(mp, &a);
    EXPECT_EQ(mt, 3);
}

TEST(TaggedPointer, ConcurrentCompareExchange)
{
    int a = 10;
    int b = 20;
    TaggedPointer<int> t(&a, 0);
    const int thread_count = 8;
    std::vector<std::thread> workers;
    std::atomic<int> success_count{0};
    for (int i = 0; i < thread_count; ++i)
    {
        workers.emplace_back([&t, &a, &b, &success_count, i]()
        {
            // each thread will try to swap from (&a,0) to (&b,i)
            int tries = 1000;
            for (int j = 0; j < tries; ++j)
            {
                int *expected_ptr = &a;
                std::uint64_t expected_tag = 0;
                if (t.compare_exchange_pointer_and_tag(expected_ptr, expected_tag, &b, static_cast<std::uint64_t>(i + 1)))
                {
                    success_count.fetch_add(1, std::memory_order_relaxed);
                    break;
                }
            }
        });
    }
    for (auto &th : workers)
        th.join();
    EXPECT_GE(success_count.load(), 1);
}

TEST(TaggedPointer, ConcurrentTouchTag)
{
    int a = 0;
    TaggedPointer<int> t(&a, 0);
    const int thread_count = 8;
    const int iter = 10000;
    std::vector<std::thread> workers;
    for (int i = 0; i < thread_count; ++i)
    {
        workers.emplace_back([&t]()
        {
            for (int j = 0; j < iter; ++j)
                t.touch_tag();
        });
    }
    for (auto &th : workers)
        th.join();
    auto [p, tag] = t.split();
    EXPECT_EQ(p, &a);
    EXPECT_LT(tag, static_cast<std::uint64_t>(TaggedPointer<int>::TAG_MASK + 1));
}