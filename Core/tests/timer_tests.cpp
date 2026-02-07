// Copyright (c) 2023- Charlie Vigue. All rights reserved.


#include "gtest/gtest.h"

#include "timer.h"

using namespace clv;

TEST(TimerUnit, simple_time)
{
    auto t = Timer();
    EXPECT_NE(t.Elapsed(), t.Elapsed());
}