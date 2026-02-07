// Copyright (c) 2023- Charlie Vigue. All rights reserved.


#include "gtest/gtest.h"

#include <chrono>

#include "auto_thread.h"

using namespace clv;
using namespace std::literals;

class CustomCancel
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

TEST(AutoThreadUnit, auto_join)
{
    int i = 0;
    {
        auto t = AutoThread<>([&i]()
        { ++i; std::cout << "First\n"; });
    }
    std::cout << "Second\n";
    EXPECT_EQ(i, 1);
}

TEST(AutoThreadUnit, swap)
{
    auto t1 = AutoThread<>([]() {});
    EXPECT_TRUE(t1.joinable());
    auto t2 = AutoThread<>([]() {});
    EXPECT_TRUE(t2.joinable());
    auto id1 = t1.get_id();
    auto id2 = t2.get_id();
    t1.swap(t2);
    EXPECT_EQ(t1.get_id(), id2);
    EXPECT_EQ(t2.get_id(), id1);
}

TEST(AutoThreadUnit, std_swap)
{
    auto t1 = AutoThread<>([]() {});
    EXPECT_TRUE(t1.joinable());
    auto t2 = AutoThread<>([]() {});
    EXPECT_TRUE(t2.joinable());
    auto id1 = t1.get_id();
    auto id2 = t2.get_id();
    std::swap(t1, t2);
    EXPECT_EQ(t1.get_id(), id2);
    EXPECT_EQ(t2.get_id(), id1);
}

TEST(AutoThreaUnit, cancel)
{
    // This is a data race but it usually goes our way
    auto t1 = AutoThread<>([](NoCancel &c)
    { std::this_thread::sleep_for(20ms);
                           EXPECT_FALSE(c.is_canceled()); });
    t1.cancel(); // Does nothing due to NoCancel default
}

TEST(AutoThreaUnit, basic_cancel)
{
    // This is a data race but it usually goes our way
    auto t1 = AutoThread<BasicCancel>([](BasicCancel &c)
    { std::this_thread::sleep_for(20ms);
                                        EXPECT_TRUE(c.is_canceled()); });
    t1.cancel();
}

TEST(AutoThreaUnit, custom_cancel)
{
    CustomCancel cc;
    // This is a data race but it usually goes our way
    auto t1 = AutoThread<>([](CustomCancel &c)
    { std::this_thread::sleep_for(20ms);
                           EXPECT_TRUE(c.is_canceled()); },
                           std::ref(cc));
    cc.cancel();
}

TEST(AutoThreaUnit, custom_cancel_false)
{
    CustomCancel cc;
    // This is a data race but it usually goes our way
    auto t1 = AutoThread<>([](CustomCancel &c)
    { std::this_thread::sleep_for(20ms);
                           EXPECT_FALSE(c.is_canceled()); },
                           std::ref(cc));
    t1.cancel();
}
TEST(AutoThreaUnit, cancel_int)
{
    // This is a data race but it usually goes our way
    auto t1 = AutoThread<>([](int, NoCancel &c)
    { std::this_thread::sleep_for(20ms);
                           EXPECT_FALSE(c.is_canceled()); },
                           99);
    t1.cancel(); // Does nothing due to NoCancel default
}

TEST(AutoThreaUnit, basic_cancel_int_int)
{
    // This is a data race but it usually goes our way
    auto t1 = AutoThread<BasicCancel>([](int, int, BasicCancel &c)
    { std::this_thread::sleep_for(20ms);
                                        EXPECT_TRUE(c.is_canceled()); },
                                      99,
                                      42);
    t1.cancel();
}

TEST(AutoThreaUnit, custom_cancel_int_double)
{
    CustomCancel cc;
    // This is a data race but it usually goes our way
    auto t1 = AutoThread<>([](int, double, CustomCancel &c)
    { std::this_thread::sleep_for(20ms);
                           EXPECT_TRUE(c.is_canceled()); },
                           1,
                           1.0,
                           std::ref(cc));
    cc.cancel();
}

TEST(AutoThreaUnit, custom_cancel_false_double_int)
{
    CustomCancel cc;
    // This is a data race but it usually goes our way
    auto t1 = AutoThread<>([](double, int, CustomCancel &c)
    { std::this_thread::sleep_for(20ms);
                           EXPECT_FALSE(c.is_canceled()); },
                           98.6,
                           42,
                           std::ref(cc));
    t1.cancel();
}
