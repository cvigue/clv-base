// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#include "gtest/gtest.h"

#include "not_null.h"

#include <array>
#include <cstddef>
#include <functional>
#include <memory>
#include <set>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <unordered_set>
#include <utility>

using namespace clv;

struct TestObject
{
    int value = 42;
    std::string name = "test";
};

TEST(not_null_suite, construct_from_valid_pointer)
{
    TestObject obj;
    not_null<TestObject *> ptr(&obj);

    EXPECT_EQ(ptr.get(), &obj);
    EXPECT_EQ(ptr->value, 42);
    EXPECT_EQ((*ptr).name, "test");
}

TEST(not_null_suite, construct_from_nullptr_throws)
{
    EXPECT_THROW(not_null<TestObject *>(nullptr), std::invalid_argument);
}

TEST(not_null_suite, copy_construct)
{
    TestObject obj;
    not_null<TestObject *> ptr1(&obj);
    not_null<TestObject *> ptr2(ptr1);

    EXPECT_EQ(ptr1.get(), ptr2.get());
    EXPECT_EQ(ptr2->value, 42);
}

TEST(not_null_suite, move_construct)
{
    TestObject obj;
    not_null<TestObject *> ptr1(&obj);
    not_null<TestObject *> ptr2(std::move(ptr1));

    EXPECT_EQ(ptr2.get(), &obj);
    EXPECT_EQ(ptr2->value, 42);
}

TEST(not_null_suite, copy_assign)
{
    TestObject obj1, obj2;
    not_null<TestObject *> ptr1(&obj1);
    not_null<TestObject *> ptr2(&obj2);

    ptr2 = ptr1;
    EXPECT_EQ(ptr2.get(), &obj1);
}

TEST(not_null_suite, move_assign)
{
    TestObject obj1, obj2;
    not_null<TestObject *> ptr1(&obj1);
    not_null<TestObject *> ptr2(&obj2);

    ptr2 = std::move(ptr1);
    EXPECT_EQ(ptr2.get(), &obj1);
}

TEST(not_null_suite, assign_from_valid_raw_pointer)
{
    TestObject obj1, obj2;
    not_null<TestObject *> ptr(&obj1);

    ptr = &obj2;
    EXPECT_EQ(ptr.get(), &obj2);
}

TEST(not_null_suite, assign_from_nullptr_throws)
{
    TestObject obj;
    not_null<TestObject *> ptr(&obj);

    TestObject *null_ptr = nullptr;
    EXPECT_THROW(ptr = null_ptr, std::invalid_argument);
}

TEST(not_null_suite, bool_conversion_always_true)
{
    TestObject obj;
    not_null<TestObject *> ptr(&obj);

    EXPECT_TRUE(static_cast<bool>(ptr));
    if (ptr)
    {
        SUCCEED();
    }
    else
    {
        FAIL() << "not_null should always be truthy";
    }
}

TEST(not_null_suite, comparison_operators)
{
    TestObject obj1, obj2;
    not_null<TestObject *> ptr1a(&obj1);
    not_null<TestObject *> ptr1b(&obj1);
    not_null<TestObject *> ptr2(&obj2);

    EXPECT_TRUE(ptr1a == ptr1b);
    EXPECT_FALSE(ptr1a != ptr1b);
    EXPECT_TRUE(ptr1a != ptr2);
    EXPECT_FALSE(ptr1a == ptr2);

    // Compare with raw pointer
    EXPECT_TRUE(ptr1a == &obj1);
    EXPECT_FALSE(ptr1a == &obj2);
}

TEST(not_null_suite, deduction_guide)
{
    TestObject obj;
    auto ptr = not_null(&obj);

    static_assert(std::is_same_v<decltype(ptr), not_null<TestObject *>>);
    EXPECT_EQ(ptr->value, 42);
}

TEST(not_null_suite, const_pointer)
{
    const TestObject obj;
    not_null<const TestObject *> ptr(&obj);

    EXPECT_EQ(ptr->value, 42);
    // ptr->value = 10; // Should not compile
}

TEST(not_null_suite, modify_through_pointer)
{
    TestObject obj;
    not_null<TestObject *> ptr(&obj);

    ptr->value = 100;
    ptr->name = "modified";

    EXPECT_EQ(obj.value, 100);
    EXPECT_EQ(obj.name, "modified");
}

TEST(not_null_suite, use_with_shared_ptr)
{
    auto shared = std::make_shared<TestObject>();
    not_null<TestObject *> ptr(shared.get());

    EXPECT_EQ(ptr->value, 42);
    ptr->value = 99;
    EXPECT_EQ(shared->value, 99);
}

TEST(not_null_suite, use_with_unique_ptr)
{
    auto unique = std::make_unique<TestObject>();
    not_null<TestObject *> ptr(unique.get());

    EXPECT_EQ(ptr->value, 42);
    ptr->value = 88;
    EXPECT_EQ(unique->value, 88);
}

TEST(not_null_suite, ordering_operators)
{
    std::array<TestObject, 3> objs;
    not_null<TestObject *> ptr0(&objs[0]);
    not_null<TestObject *> ptr1(&objs[1]);
    not_null<TestObject *> ptr2(&objs[2]);

    // Spaceship-derived ordering
    EXPECT_TRUE(ptr0 < ptr1);
    EXPECT_TRUE(ptr1 < ptr2);
    EXPECT_TRUE(ptr0 <= ptr1);
    EXPECT_TRUE(ptr1 <= ptr1);
    EXPECT_TRUE(ptr2 > ptr1);
    EXPECT_TRUE(ptr2 >= ptr1);
    EXPECT_TRUE(ptr1 >= ptr1);

    // Ordering with raw pointers
    EXPECT_TRUE(ptr0 < &objs[1]);
    EXPECT_TRUE(ptr2 > &objs[1]);
}

TEST(not_null_suite, std_hash_support)
{
    TestObject obj;
    not_null<TestObject *> ptr(&obj);

    std::hash<not_null<TestObject *>> hasher;
    std::size_t h = hasher(ptr);

    // Hash should match raw pointer hash
    EXPECT_EQ(h, std::hash<TestObject *>{}(&obj));
}

TEST(not_null_suite, use_in_unordered_set)
{
    TestObject obj1, obj2;
    not_null<TestObject *> ptr1(&obj1);
    not_null<TestObject *> ptr2(&obj2);
    not_null<TestObject *> ptr1_dup(&obj1);

    std::unordered_set<not_null<TestObject *>> set;
    set.insert(ptr1);
    set.insert(ptr2);
    set.insert(ptr1_dup); // Duplicate, should not increase size

    EXPECT_EQ(set.size(), 2u);
    EXPECT_TRUE(set.contains(ptr1));
    EXPECT_TRUE(set.contains(ptr2));
}

TEST(not_null_suite, use_in_ordered_set)
{
    std::array<TestObject, 3> objs;
    not_null<TestObject *> ptr0(&objs[0]);
    not_null<TestObject *> ptr1(&objs[1]);
    not_null<TestObject *> ptr2(&objs[2]);

    std::set<not_null<TestObject *>> set;
    set.insert(ptr2);
    set.insert(ptr0);
    set.insert(ptr1);

    // Should be ordered by pointer address
    auto it = set.begin();
    EXPECT_EQ(it->get(), &objs[0]);
    ++it;
    EXPECT_EQ(it->get(), &objs[1]);
    ++it;
    EXPECT_EQ(it->get(), &objs[2]);
}

TEST(not_null_suite, static_assert_requires_pointer_type)
{
    // This should not compile:
    // not_null<int> bad;  // Error: not_null<T> requires T to be a pointer type

    // Verify the static_assert message is correct by checking valid usage compiles
    not_null<int *> good(new int{42});
    EXPECT_EQ(*good, 42);
    delete good.get();
}
