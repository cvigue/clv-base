// Copyright (c) 2023- Charlie Vigue. All rights reserved.


#include <gtest/gtest.h>

#include <string>
#include <string_view>
#include <type_traits>

#include <array_deque.h>
#include <buffer_util.h>
#include <is_callable.h>

#include "static_vector.h"

using namespace clv;
using namespace std::literals;

using VectorBuffer = ArrayDeque<char>;
using ArrayBuffer = ArrayDeque<char, StaticVector<char, 200>>;

template <typename BufferType>
class ArrayDequeTypedTest : public ::testing::Test
{
  protected:
    using BufferT = BufferType;
};

using ArrayDequeTypes = ::testing::Types<VectorBuffer, ArrayBuffer>;
TYPED_TEST_SUITE(ArrayDequeTypedTest, ArrayDequeTypes);

TYPED_TEST(ArrayDequeTypedTest, OperatorEqual)
{
    auto buffer1 = TypeParam("Hello, World!");
    auto buffer2 = TypeParam("Hello, World!");

    EXPECT_TRUE(buffer1 == buffer2);
    EXPECT_FALSE(buffer1 != buffer2);

    buffer2.pop_back();
    EXPECT_FALSE(buffer1 == buffer2);
    EXPECT_TRUE(buffer1 != buffer2);
}

TYPED_TEST(ArrayDequeTypedTest, OperatorEqualSv)
{
    auto buffer1 = TypeParam("Hello, World!");
    auto buffer2 = "Hello, World!"sv;

    EXPECT_TRUE(buffer1 == buffer2);
    EXPECT_FALSE(buffer1 != buffer2);

    buffer1.pop_back();
    EXPECT_FALSE(buffer1 == buffer2);
    EXPECT_TRUE(buffer1 != buffer2);
}

TYPED_TEST(ArrayDequeTypedTest, OperatorEqualStr)
{
    auto buffer1 = TypeParam("Hello, World!");
    auto buffer2 = "Hello, World!"s;

    EXPECT_TRUE(buffer1 == buffer2);
    EXPECT_FALSE(buffer1 != buffer2);

    buffer2.pop_back();
    EXPECT_FALSE(buffer1 == buffer2);
    EXPECT_TRUE(buffer1 != buffer2);
}

TYPED_TEST(ArrayDequeTypedTest, OperatorLt)
{
    auto buffer1 = TypeParam("Hello, World!");
    auto buffer2 = TypeParam("Hello, World!");

    EXPECT_FALSE(buffer1 < buffer2);
    EXPECT_FALSE(buffer2 < buffer1);

    buffer1.pop_back();
    EXPECT_TRUE(buffer1 < buffer2);
    EXPECT_FALSE(buffer2 < buffer1);
}

TYPED_TEST(ArrayDequeTypedTest, OperatorLtSv)
{
    auto buffer1 = TypeParam("Hello, World!");
    auto buffer2 = "Hello, World!"sv;

    EXPECT_FALSE(buffer1 < buffer2);
    EXPECT_FALSE(buffer2 < buffer1);

    buffer1.pop_back();
    EXPECT_TRUE(buffer1 < buffer2);
    EXPECT_FALSE(buffer2 < buffer1);
}

TYPED_TEST(ArrayDequeTypedTest, OperatorLtStr)
{
    auto buffer1 = TypeParam("Hello, World!");
    auto buffer2 = "Hello, World!"s;

    EXPECT_FALSE(buffer1 < buffer2);
    EXPECT_FALSE(buffer2 < buffer1);

    buffer1.pop_back();
    EXPECT_TRUE(buffer1 < buffer2);
    EXPECT_FALSE(buffer2 < buffer1);
}

TYPED_TEST(ArrayDequeTypedTest, CtorCstrArray)
{
    auto buffer = TypeParam("Hello, World!");

    EXPECT_EQ(buffer.size(), 13);
    EXPECT_EQ(buffer.available(), 0);
    EXPECT_EQ(buffer.capacity(), 13);
    EXPECT_EQ(buffer.headroom(), 0);
    EXPECT_EQ(buffer.tailroom(), 0);
    EXPECT_EQ(buffer.front(), 'H');
    EXPECT_EQ(buffer.back(), '!');
    EXPECT_EQ(buffer[0], 'H');
    EXPECT_EQ(buffer[12], '!');
    EXPECT_EQ(std::string_view(buffer), "Hello, World!"sv);
}

TYPED_TEST(ArrayDequeTypedTest, CtorCstrArrayHeadroom)
{
    auto buffer = TypeParam("Hello, World!", 13, 3);

    EXPECT_EQ(buffer.size(), 13);
    EXPECT_GE(buffer.available(), 0);
    EXPECT_EQ(buffer.capacity(), 16);
    EXPECT_EQ(buffer.headroom(), 3);
    EXPECT_EQ(buffer.tailroom(), 0);
    EXPECT_EQ(buffer.front(), 'H');
    EXPECT_EQ(buffer.back(), '!');
    EXPECT_EQ(buffer[0], 'H');
    EXPECT_EQ(buffer[12], '!');
    EXPECT_EQ(std::string_view(buffer), "Hello, World!"sv);
}

TYPED_TEST(ArrayDequeTypedTest, CtorCstrArrayHeadroomTailroom)
{
    auto buffer = TypeParam("Hello, World!", 13, 3, 3);

    EXPECT_EQ(buffer.size(), 13);
    EXPECT_GE(buffer.available(), 0);
    EXPECT_EQ(buffer.capacity(), 19);
    EXPECT_EQ(buffer.headroom(), 3);
    EXPECT_EQ(buffer.tailroom(), 3);
    EXPECT_EQ(buffer.front(), 'H');
    EXPECT_EQ(buffer.back(), '!');
    EXPECT_EQ(buffer[0], 'H');
    EXPECT_EQ(buffer[12], '!');
    EXPECT_EQ(std::string_view(buffer), "Hello, World!"sv);
}

TYPED_TEST(ArrayDequeTypedTest, AdjustHr)
{
    auto buffer = TypeParam("Hello, World!");
    EXPECT_EQ(buffer.size(), 13);
    EXPECT_EQ(buffer.capacity(), 13);
    EXPECT_EQ(buffer.available(), 0);
    EXPECT_EQ(buffer.headroom(), 0);
    EXPECT_EQ(buffer.tailroom(), 0);

    buffer.set_headroom(3);

    EXPECT_EQ(buffer.size(), 13);
    EXPECT_GT(buffer.capacity(), 13);
    EXPECT_EQ(buffer.headroom(), 3);
    EXPECT_GE(buffer.tailroom(), 0);
    EXPECT_EQ(buffer.front(), 'H');
    EXPECT_EQ(buffer.back(), '!');
    EXPECT_EQ(buffer[0], 'H');
    EXPECT_EQ(buffer[12], '!');
    EXPECT_EQ(std::string_view(buffer), "Hello, World!"sv);
}

TYPED_TEST(ArrayDequeTypedTest, AdjustHrNoChange)
{
    auto buffer = TypeParam("Hello, World!");
    EXPECT_EQ(buffer.size(), 13);
    EXPECT_EQ(buffer.capacity(), 13);
    EXPECT_EQ(buffer.headroom(), 0);
    EXPECT_EQ(buffer.tailroom(), 0);

    buffer.set_headroom(0);

    EXPECT_EQ(buffer.size(), 13);
    EXPECT_EQ(buffer.capacity(), 13);
    EXPECT_EQ(buffer.headroom(), 0);
    EXPECT_GE(buffer.tailroom(), 0);
    EXPECT_EQ(buffer.front(), 'H');
    EXPECT_EQ(buffer.back(), '!');
    EXPECT_EQ(buffer[0], 'H');
    EXPECT_EQ(buffer[12], '!');
    EXPECT_EQ(std::string_view(buffer), "Hello, World!"sv);
}

TYPED_TEST(ArrayDequeTypedTest, AdjustTr)
{
    auto buffer = TypeParam("Hello, World!");
    EXPECT_EQ(buffer.size(), 13);
    EXPECT_EQ(buffer.available(), 0);
    EXPECT_EQ(buffer.capacity(), 13);
    EXPECT_EQ(buffer.headroom(), 0);
    EXPECT_EQ(buffer.tailroom(), 0);

    buffer.set_tailroom(3);

    EXPECT_EQ(buffer.size(), 13);
    EXPECT_GE(buffer.available(), 0);
    EXPECT_EQ(buffer.capacity(), 16);
    EXPECT_EQ(buffer.headroom(), 0);
    EXPECT_EQ(buffer.tailroom(), 3);
    EXPECT_EQ(buffer.front(), 'H');
    EXPECT_EQ(buffer.back(), '!');
    EXPECT_EQ(buffer[0], 'H');
    EXPECT_EQ(buffer[12], '!');
    EXPECT_EQ(std::string_view(buffer), "Hello, World!"sv);
}

TYPED_TEST(ArrayDequeTypedTest, ClearAndEmpty)
{
    auto buffer = TypeParam("Hello, World!");
    EXPECT_EQ(buffer.size(), 13);
    EXPECT_GE(buffer.available(), 0);
    EXPECT_EQ(buffer.capacity(), 13);
    EXPECT_EQ(buffer.headroom(), 0);
    EXPECT_EQ(buffer.tailroom(), 0);
    EXPECT_FALSE(buffer.empty());

    buffer.clear();

    EXPECT_EQ(buffer.size(), 0);
    EXPECT_EQ(buffer.available(), buffer.capacity());
    EXPECT_GE(buffer.capacity(), 13);
    EXPECT_EQ(buffer.headroom(), 0);
    EXPECT_EQ(buffer.tailroom(), buffer.available());
    EXPECT_TRUE(buffer.empty());
}

TYPED_TEST(ArrayDequeTypedTest, PushFront)
{
    auto buffer = TypeParam("Hello, World!");
    EXPECT_EQ(buffer.size(), 13);
    EXPECT_GE(buffer.available(), 0);
    EXPECT_EQ(buffer.capacity(), 13);
    EXPECT_EQ(buffer.headroom(), 0);
    EXPECT_EQ(buffer.tailroom(), 0);

    buffer.push_front(' ');
    buffer.push_front('!');
    buffer.push_front('d');
    buffer.push_front('l');
    buffer.push_front('r');
    buffer.push_front('o');
    buffer.push_front('W');
    buffer.push_front(' ');
    buffer.push_front(',');
    buffer.push_front('o');
    buffer.push_front('l');
    buffer.push_front('l');
    buffer.push_front('e');
    buffer.push_front('H');

    EXPECT_GE(buffer.size(), 26);
    EXPECT_EQ(std::string_view(buffer), "Hello, World! Hello, World!"sv);
}

TYPED_TEST(ArrayDequeTypedTest, PushFrontWithHint)
{
    auto buffer = TypeParam("Hello, World!");
    EXPECT_EQ(buffer.size(), 13);
    EXPECT_GE(buffer.available(), 0);
    EXPECT_EQ(buffer.capacity(), 13);
    EXPECT_EQ(buffer.headroom(), 0);
    EXPECT_EQ(buffer.tailroom(), 0);

    buffer.push_front(' ', 13);
    EXPECT_GE(buffer.headroom(), 12);
    buffer.push_front('!');
    buffer.push_front('d');
    buffer.push_front('l');
    buffer.push_front('r');
    buffer.push_front('o');
    buffer.push_front('W');
    buffer.push_front(' ');
    buffer.push_front(',');
    buffer.push_front('o');
    buffer.push_front('l');
    buffer.push_front('l');
    buffer.push_front('e');
    buffer.push_front('H');

    EXPECT_GE(buffer.size(), 26);
    EXPECT_EQ(std::string_view(buffer), "Hello, World! Hello, World!"sv);
}

TYPED_TEST(ArrayDequeTypedTest, PushBack)
{
    auto buffer = TypeParam("Hello, World!");
    EXPECT_EQ(buffer.size(), 13);
    EXPECT_GE(buffer.available(), 0);
    EXPECT_EQ(buffer.capacity(), 13);
    EXPECT_EQ(buffer.headroom(), 0);
    EXPECT_EQ(buffer.tailroom(), 0);

    buffer.push_back(' ');
    buffer.push_back('H');
    buffer.push_back('e');
    buffer.push_back('l');
    buffer.push_back('l');
    buffer.push_back('o');
    buffer.push_back(',');
    buffer.push_back(' ');
    buffer.push_back('W');
    buffer.push_back('o');
    buffer.push_back('r');
    buffer.push_back('l');
    buffer.push_back('d');
    buffer.push_back('!');

    EXPECT_GE(buffer.size(), 26);
    EXPECT_EQ(std::string_view(buffer), "Hello, World! Hello, World!"sv);
}

TYPED_TEST(ArrayDequeTypedTest, PopFront)
{
    auto buffer = TypeParam("Hello, World!");
    EXPECT_EQ(buffer.size(), 13);
    EXPECT_GE(buffer.available(), 0);
    EXPECT_EQ(buffer.capacity(), 13);
    EXPECT_EQ(buffer.headroom(), 0);
    EXPECT_EQ(buffer.tailroom(), 0);

    EXPECT_EQ(buffer.pop_front(), 'H');

    EXPECT_EQ(buffer.size(), 12);
    EXPECT_GE(buffer.available(), 1);
    EXPECT_EQ(buffer.capacity(), 13);
    EXPECT_EQ(buffer.headroom(), 1);
    EXPECT_EQ(buffer.tailroom(), 0);
    EXPECT_EQ(std::string_view(buffer), "ello, World!"sv);
}

TYPED_TEST(ArrayDequeTypedTest, PopBack)
{
    auto buffer = TypeParam("Hello, World!");
    EXPECT_EQ(buffer.size(), 13);
    EXPECT_GE(buffer.available(), 0);
    EXPECT_EQ(buffer.capacity(), 13);
    EXPECT_EQ(buffer.headroom(), 0);
    EXPECT_EQ(buffer.tailroom(), 0);

    EXPECT_EQ(buffer.pop_back(), '!');

    EXPECT_EQ(buffer.size(), 12);
    EXPECT_GE(buffer.available(), 1);
    EXPECT_EQ(buffer.capacity(), 13);
    EXPECT_EQ(buffer.headroom(), 0);
    EXPECT_EQ(buffer.tailroom(), 1);
    EXPECT_EQ(std::string_view(buffer), "Hello, World"sv);
}

TYPED_TEST(ArrayDequeTypedTest, OperatorIndex)
{
    auto buffer = TypeParam("Hello, World!");
    EXPECT_EQ(buffer.size(), 13);
    EXPECT_GE(buffer.available(), 0);
    EXPECT_EQ(buffer.capacity(), 13);
    EXPECT_EQ(buffer.headroom(), 0);
    EXPECT_EQ(buffer.tailroom(), 0);

    EXPECT_EQ(buffer[0], 'H');
    EXPECT_EQ(buffer[1], 'e');
    EXPECT_EQ(buffer[2], 'l');
    EXPECT_EQ(buffer[3], 'l');
    EXPECT_EQ(buffer[4], 'o');
    EXPECT_EQ(buffer[5], ',');
    EXPECT_EQ(buffer[6], ' ');
    EXPECT_EQ(buffer[7], 'W');
    EXPECT_EQ(buffer[8], 'o');
    EXPECT_EQ(buffer[9], 'r');
    EXPECT_EQ(buffer[10], 'l');
    EXPECT_EQ(buffer[11], 'd');
    EXPECT_EQ(buffer[12], '!');
}

TYPED_TEST(ArrayDequeTypedTest, OperatorIndexConst)
{
    const auto buffer = TypeParam("Hello, World!");
    EXPECT_EQ(buffer.size(), 13);
    EXPECT_GE(buffer.available(), 0);
    EXPECT_EQ(buffer.capacity(), 13);
    EXPECT_EQ(buffer.headroom(), 0);
    EXPECT_EQ(buffer.tailroom(), 0);

    EXPECT_EQ(buffer[0], 'H');
    EXPECT_EQ(buffer[1], 'e');
    EXPECT_EQ(buffer[2], 'l');
    EXPECT_EQ(buffer[3], 'l');
    EXPECT_EQ(buffer[4], 'o');
    EXPECT_EQ(buffer[5], ',');
    EXPECT_EQ(buffer[6], ' ');
    EXPECT_EQ(buffer[7], 'W');
    EXPECT_EQ(buffer[8], 'o');
    EXPECT_EQ(buffer[9], 'r');
    EXPECT_EQ(buffer[10], 'l');
    EXPECT_EQ(buffer[11], 'd');
    EXPECT_EQ(buffer[12], '!');
}

TYPED_TEST(ArrayDequeTypedTest, OperatorIndexAssign)
{
    auto buffer = TypeParam("Hello, World!");
    EXPECT_EQ(buffer.size(), 13);
    EXPECT_GE(buffer.available(), 0);
    EXPECT_EQ(buffer.capacity(), 13);
    EXPECT_EQ(buffer.headroom(), 0);
    EXPECT_EQ(buffer.tailroom(), 0);

    buffer[0] = 'h';
    buffer[1] = 'e';
    buffer[2] = 'l';
    buffer[3] = 'l';
    buffer[4] = 'o';
    buffer[5] = ',';
    buffer[6] = ' ';
    buffer[7] = 'w';
    buffer[8] = 'o';
    buffer[9] = 'r';
    buffer[10] = 'l';
    buffer[11] = 'd';
    buffer[12] = '!';

    EXPECT_EQ(buffer.size(), 13);
    EXPECT_GE(buffer.available(), 0);
    EXPECT_EQ(buffer.capacity(), 13);
    EXPECT_EQ(buffer.headroom(), 0);
    EXPECT_EQ(buffer.tailroom(), 0);
    EXPECT_EQ(std::string_view(buffer), "hello, world!"sv);
}

TYPED_TEST(ArrayDequeTypedTest, OperatorIndexAssignConst)
{
    const auto buffer = TypeParam("Hello, World!");
    EXPECT_EQ(buffer.size(), 13);
    EXPECT_GE(buffer.available(), 0);
    EXPECT_EQ(buffer.capacity(), 13);
    EXPECT_EQ(buffer.headroom(), 0);
    EXPECT_EQ(buffer.tailroom(), 0);

    EXPECT_EQ(buffer[0], 'H');
    EXPECT_EQ(buffer[1], 'e');
    EXPECT_EQ(buffer[2], 'l');
    EXPECT_EQ(buffer[3], 'l');
    EXPECT_EQ(buffer[4], 'o');
    EXPECT_EQ(buffer[5], ',');
    EXPECT_EQ(buffer[6], ' ');
    EXPECT_EQ(buffer[7], 'W');
    EXPECT_EQ(buffer[8], 'o');
    EXPECT_EQ(buffer[9], 'r');
    EXPECT_EQ(buffer[10], 'l');
    EXPECT_EQ(buffer[11], 'd');
    EXPECT_EQ(buffer[12], '!');

    EXPECT_FALSE((std::is_assignable_v<decltype(buffer[0]), char>)) << "Should not be assignable";
}

TYPED_TEST(ArrayDequeTypedTest, IterBegin)
{
    auto buffer = TypeParam("Hello, World!");
    auto it = buffer.begin();

    EXPECT_EQ(*it, 'H');
    EXPECT_EQ(*it++, 'H');
    EXPECT_EQ(*it, 'e');
    EXPECT_EQ(*it++, 'e');
    EXPECT_EQ(*it, 'l');
    EXPECT_EQ(*it++, 'l');
    EXPECT_EQ(*it, 'l');
    EXPECT_EQ(*it++, 'l');
    EXPECT_EQ(*it, 'o');
    EXPECT_EQ(*it++, 'o');
    EXPECT_EQ(*it, ',');
    EXPECT_EQ(*it++, ',');
    EXPECT_EQ(*it, ' ');
    EXPECT_EQ(*it++, ' ');
    EXPECT_EQ(*it, 'W');
    EXPECT_EQ(*it++, 'W');
    EXPECT_EQ(*it, 'o');
    EXPECT_EQ(*it++, 'o');
    EXPECT_EQ(*it, 'r');
    EXPECT_EQ(*it++, 'r');
    EXPECT_EQ(*it, 'l');
    EXPECT_EQ(*it++, 'l');
    EXPECT_EQ(*it, 'd');
    EXPECT_EQ(*it++, 'd');
    EXPECT_EQ(*it, '!');
    EXPECT_EQ(*it++, '!');
    EXPECT_EQ(it, buffer.end());
}

TYPED_TEST(ArrayDequeTypedTest, IterEnd)
{
    auto buffer = TypeParam("Hello, World!");
    auto it = buffer.end();

    EXPECT_EQ(*--it, '!');
    EXPECT_EQ(*it, '!');
    EXPECT_EQ(*--it, 'd');
    EXPECT_EQ(*it, 'd');
    EXPECT_EQ(*--it, 'l');
    EXPECT_EQ(*it, 'l');
    EXPECT_EQ(*--it, 'r');
    EXPECT_EQ(*it, 'r');
    EXPECT_EQ(*--it, 'o');
    EXPECT_EQ(*it, 'o');
    EXPECT_EQ(*--it, 'W');
    EXPECT_EQ(*it, 'W');
    EXPECT_EQ(*--it, ' ');
    EXPECT_EQ(*it, ' ');
    EXPECT_EQ(*--it, ',');
    EXPECT_EQ(*it, ',');
    EXPECT_EQ(*--it, 'o');
    EXPECT_EQ(*it, 'o');
    EXPECT_EQ(*--it, 'l');
    EXPECT_EQ(*it, 'l');
    EXPECT_EQ(*--it, 'l');
    EXPECT_EQ(*it, 'l');
    EXPECT_EQ(*--it, 'e');
    EXPECT_EQ(*it, 'e');
    EXPECT_EQ(*--it, 'H');
    EXPECT_EQ(*it, 'H');
    EXPECT_EQ(it, buffer.begin());
}

TYPED_TEST(ArrayDequeTypedTest, IterConstBegin)
{
    const auto buffer = TypeParam("Hello, World!");
    auto it = buffer.begin();

    EXPECT_FALSE((std::is_assignable_v<decltype(*it), char>)) << "Should not be assignable";

    EXPECT_EQ(*it, 'H');
    EXPECT_EQ(*it++, 'H');
    EXPECT_EQ(*it, 'e');
    EXPECT_EQ(*it++, 'e');
    EXPECT_EQ(*it, 'l');
    EXPECT_EQ(*it++, 'l');
    EXPECT_EQ(*it, 'l');
    EXPECT_EQ(*it++, 'l');
    EXPECT_EQ(*it, 'o');
    EXPECT_EQ(*it++, 'o');
    EXPECT_EQ(*it, ',');
    EXPECT_EQ(*it++, ',');
    EXPECT_EQ(*it, ' ');
    EXPECT_EQ(*it++, ' ');
    EXPECT_EQ(*it, 'W');
    EXPECT_EQ(*it++, 'W');
    EXPECT_EQ(*it, 'o');
    EXPECT_EQ(*it++, 'o');
    EXPECT_EQ(*it, 'r');
    EXPECT_EQ(*it++, 'r');
    EXPECT_EQ(*it, 'l');
    EXPECT_EQ(*it++, 'l');
    EXPECT_EQ(*it, 'd');
    EXPECT_EQ(*it++, 'd');
    EXPECT_EQ(*it, '!');
    EXPECT_EQ(*it++, '!');
    EXPECT_EQ(it, buffer.end());
}

TYPED_TEST(ArrayDequeTypedTest, IterConstEnd)
{
    const auto buffer = TypeParam("Hello, World!");
    auto it = buffer.end();

    EXPECT_FALSE((std::is_assignable_v<decltype(*it), char>)) << "Should not be assignable";

    EXPECT_EQ(*--it, '!');
    EXPECT_EQ(*it, '!');
    EXPECT_EQ(*--it, 'd');
    EXPECT_EQ(*it, 'd');
    EXPECT_EQ(*--it, 'l');
    EXPECT_EQ(*it, 'l');
    EXPECT_EQ(*--it, 'r');
    EXPECT_EQ(*it, 'r');
    EXPECT_EQ(*--it, 'o');
    EXPECT_EQ(*it, 'o');
    EXPECT_EQ(*--it, 'W');
    EXPECT_EQ(*it, 'W');
    EXPECT_EQ(*--it, ' ');
    EXPECT_EQ(*it, ' ');
    EXPECT_EQ(*--it, ',');
    EXPECT_EQ(*it, ',');
    EXPECT_EQ(*--it, 'o');
    EXPECT_EQ(*it, 'o');
    EXPECT_EQ(*--it, 'l');
    EXPECT_EQ(*it, 'l');
    EXPECT_EQ(*--it, 'l');
    EXPECT_EQ(*it, 'l');
    EXPECT_EQ(*--it, 'e');
    EXPECT_EQ(*it, 'e');
    EXPECT_EQ(*--it, 'H');
    EXPECT_EQ(*it, 'H');
    EXPECT_EQ(it, buffer.begin());
}

TYPED_TEST(ArrayDequeTypedTest, AllocateTail)
{
    auto buffer = TypeParam("Hello, World!");
    auto it = buffer.allocate_tail(3).begin();

    const char data[] = "123";
    std::copy(data, data + 3, it);

    EXPECT_GE(buffer.size(), 16);
    EXPECT_EQ(std::string_view(buffer), "Hello, World!123"sv);
}

TYPED_TEST(ArrayDequeTypedTest, AllocateHead)
{
    auto buffer = TypeParam("Hello, World!");
    auto it = buffer.allocate_head(3).begin();

    const char data[] = "123";
    std::copy(data, data + 3, it);

    EXPECT_GE(buffer.size(), 16);
    EXPECT_EQ(std::string_view(buffer), "123Hello, World!"sv);
}

TYPED_TEST(ArrayDequeTypedTest, Allocate)
{
    auto buffer = TypeParam("Hello, World!");
    auto it = buffer.allocate(buffer.begin() + 3, 3).begin();

    const char data[] = "123";
    std::copy(data, data + 3, it);

    EXPECT_EQ(buffer.size(), 16);
    EXPECT_EQ(std::string_view(buffer), "Hel123lo, World!"sv);
}

TYPED_TEST(ArrayDequeTypedTest, FreeHead)
{
    auto buffer = TypeParam("Hello, World!");

    buffer.free_head(3);

    EXPECT_EQ(buffer.size(), 10);
    EXPECT_EQ(std::string_view(buffer), "lo, World!"sv);
}

TYPED_TEST(ArrayDequeTypedTest, FreeTail)
{
    auto buffer = TypeParam("Hello, World!");

    buffer.free_tail(3);

    EXPECT_EQ(buffer.size(), 10);
    EXPECT_EQ(std::string_view(buffer), "Hello, Wor"sv);
}

TYPED_TEST(ArrayDequeTypedTest, Free)
{
    auto buffer = TypeParam("Hello, World!");

    buffer.free(buffer.begin() + 1, 2);

    EXPECT_EQ(buffer.size(), 11);
    EXPECT_EQ(std::string_view(buffer), "Hlo, World!"sv);
}

TYPED_TEST(ArrayDequeTypedTest, ViewAll)
{
    auto buffer = TypeParam("Hello, World!");
    auto view = buffer.view();

    EXPECT_EQ(view.size(), 13);
    EXPECT_EQ(std::string_view(view), "Hello, World!"sv);
}

TYPED_TEST(ArrayDequeTypedTest, ViewRange1)
{
    auto buffer = TypeParam("Hello, World!");
    auto view = buffer.view(buffer.begin() + 3, buffer.begin() + 8);

    EXPECT_EQ(view.size(), 5);
    EXPECT_EQ(std::string_view(view), "lo, W"sv);
}

TYPED_TEST(ArrayDequeTypedTest, ViewRange2)
{
    auto buffer = TypeParam("Hello, World!");
    auto view = buffer.view(3);

    EXPECT_EQ(view.size(), 10);
    EXPECT_EQ(std::string_view(view), "lo, World!"sv);
}

TYPED_TEST(ArrayDequeTypedTest, ViewRange3)
{
    auto buffer = TypeParam("Hello, World!");
    auto view = buffer.view(0, 3);

    EXPECT_EQ(view.size(), 3);
    EXPECT_EQ(std::string_view(view), "Hel"sv);
}

TYPED_TEST(ArrayDequeTypedTest, ViewRangeConst)
{
    auto buffer = TypeParam("Hello, World!");
    auto view = buffer.const_view(buffer.begin() + 3, buffer.begin() + 8);

    EXPECT_EQ(view.size(), 5);
    EXPECT_EQ(std::string_view(view), "lo, W"sv);
    EXPECT_FALSE((std::is_assignable_v<decltype(*view.data()), char>)) << "Should not be assignable";
    EXPECT_TRUE((std::is_assignable_v<decltype(*buffer.data()), char>)) << "Should be assignable";
}

// ================================================================================================
// Regression tests for move_data / set_headroom correctness (issue #1)
// ================================================================================================

// set_headroom must preserve data integrity when shifting right (increasing headroom).
// This catches the move_data branch swap: std::move was used for rightward shifts
// where std::move_backward is required (overlapping source/dest ranges).
TYPED_TEST(ArrayDequeTypedTest, SetHeadroomPreservesDataIntegrity)
{
    auto buffer = TypeParam("ABCDEFGHIJ");
    ASSERT_EQ(buffer.headroom(), 0);

    // Increase headroom — data must shift right within the backing store
    buffer.set_headroom(5);

    EXPECT_EQ(buffer.size(), 10);
    EXPECT_EQ(buffer.headroom(), 5);

    // Verify every element survived the move
    EXPECT_EQ(buffer[0], 'A');
    EXPECT_EQ(buffer[1], 'B');
    EXPECT_EQ(buffer[2], 'C');
    EXPECT_EQ(buffer[3], 'D');
    EXPECT_EQ(buffer[4], 'E');
    EXPECT_EQ(buffer[5], 'F');
    EXPECT_EQ(buffer[6], 'G');
    EXPECT_EQ(buffer[7], 'H');
    EXPECT_EQ(buffer[8], 'I');
    EXPECT_EQ(buffer[9], 'J');
    EXPECT_EQ(std::string_view(buffer), "ABCDEFGHIJ"sv);
}

// Increasing headroom incrementally should work correctly each time.
TYPED_TEST(ArrayDequeTypedTest, SetHeadroomIncrementalIncrease)
{
    auto buffer = TypeParam("12345");
    ASSERT_EQ(buffer.headroom(), 0);

    buffer.set_headroom(2);
    EXPECT_EQ(buffer.headroom(), 2);
    EXPECT_EQ(std::string_view(buffer), "12345"sv);

    buffer.set_headroom(6);
    EXPECT_EQ(buffer.headroom(), 6);
    EXPECT_EQ(std::string_view(buffer), "12345"sv);

    buffer.set_headroom(10);
    EXPECT_EQ(buffer.headroom(), 10);
    EXPECT_EQ(std::string_view(buffer), "12345"sv);
}

// allocate (general case, middle insertion) also uses move_data with rightward shift.
TYPED_TEST(ArrayDequeTypedTest, AllocateMiddlePreservesData)
{
    auto buffer = TypeParam("ABCDE");

    // Insert 3 bytes at position 2 — shifts CDE right by 3
    auto slot = buffer.allocate(2, 3);
    slot[0] = 'X';
    slot[1] = 'Y';
    slot[2] = 'Z';

    EXPECT_EQ(buffer.size(), 8);
    EXPECT_EQ(std::string_view(buffer), "ABXYZCDE"sv);
}

// free (general case, middle removal) uses move_data with leftward shift.
TYPED_TEST(ArrayDequeTypedTest, FreeMiddlePreservesData)
{
    auto buffer = TypeParam("ABXYZCDE");

    // Remove 3 bytes at position 2 — shifts CDE left by 3
    buffer.free(2, 3);

    EXPECT_EQ(buffer.size(), 5);
    EXPECT_EQ(std::string_view(buffer), "ABCDE"sv);
}
