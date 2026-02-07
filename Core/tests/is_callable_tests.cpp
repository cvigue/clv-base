// Copyright (c) 2023- Charlie Vigue. All rights reserved.


#include "gtest/gtest.h"

#include "is_callable.h"

using namespace clv;

class Test
{
  public:
    template <typename... ArgsT>
    void func(int, ArgsT &&...) {};
    int another_func(std::string)
    {
        return 0;
    }
    [[nodiscard]] int nd_func(std::string)
    {
        return 0;
    }
    void const_func(int) const {};
    auto operator()() const -> int
    {
        return 0;
    }
    auto operator*()
    {
        return this;
    }
};

TEST(IsCallableUnit, member_template)
{
    EXPECT_FALSE((is_member_func_callable_v<decltype(&::Test::func<>), ::Test>));
    EXPECT_TRUE((is_member_func_callable_v<decltype(&::Test::func<>), ::Test, int>));
    EXPECT_FALSE((is_member_func_callable_v<decltype(&::Test::func<>), ::Test, int, double>));
}

TEST(IsCallableUnit, member_template_d)
{
    EXPECT_FALSE((is_member_func_callable_v<decltype(&::Test::func<double>), ::Test>));
    EXPECT_FALSE((is_member_func_callable_v<decltype(&::Test::func<double>), ::Test, int>));
    EXPECT_TRUE((is_member_func_callable_v<decltype(&::Test::func<double>), ::Test, int, double>));
}

TEST(IsCallableUnit, member_template_dd)
{
    EXPECT_FALSE((is_member_func_callable_v<decltype(&::Test::func<double, double>), ::Test, int>));
    EXPECT_FALSE((is_member_func_callable_v<decltype(&::Test::func<double, double>), ::Test, int, double>));
    EXPECT_TRUE((is_member_func_callable_v<decltype(&::Test::func<double, double>), ::Test, int, double, double>));
}

TEST(IsCallableUnit, member_func)
{
    EXPECT_FALSE((is_member_func_callable_v<decltype(&::Test::another_func), ::Test, int>));
    EXPECT_TRUE((is_member_func_callable_v<decltype(&::Test::another_func), ::Test, std::string>));
}

TEST(IsCallableUnit, const_member_func)
{
    EXPECT_TRUE((is_member_func_callable_v<decltype(&::Test::const_func), ::Test, int>));
    EXPECT_FALSE((is_member_func_callable_v<decltype(&::Test::const_func), ::Test, std::string>));
}

TEST(IsCallableUnit, nodiscard_member_func)
{
    EXPECT_FALSE((is_member_func_callable_v<decltype(&::Test::nd_func), ::Test, int>));
    EXPECT_TRUE((is_member_func_callable_v<decltype(&::Test::nd_func), ::Test, std::string>));
}

TEST(IsCallableUnit, overload_operator)
{
    EXPECT_TRUE((is_member_func_callable_v<decltype(&::Test::operator()), ::Test>));
    EXPECT_TRUE((is_member_func_callable_v<decltype(&::Test::operator*), ::Test>));
}
