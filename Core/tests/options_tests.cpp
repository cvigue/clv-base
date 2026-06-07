// Copyright (c) 2023- Charlie Vigue. All rights reserved.


#include <gtest/gtest.h>

#include <options.h>

using namespace std;
using namespace clv;

TEST(options_test, tags_init)
{
    Options::Spec a = {0, "", false, "cmd"};
    Options::Spec b = {"long1", std::nullopt, "Helpful hint", false, "long one"};
    Options::Spec c = {"short1", 's', "Helpful hint", false, "short one"};
}

TEST(options_test, parse_1)
{
    const char *avt[] = {"picorg.exe",
                         "/some/src/path",
                         "/some/dst/path",
                         "--long",
                         "val1",
                         "-s",
                         "val2"};
    int act = sizeof(avt) / sizeof(avt[0]);

    auto o = Options();

    o.Reset(act,
            avt,
            {{0, "", false, "cmd"},
             {1, "The source directory", false, "src"},
             {2, "The dest directory", false, "dst"},
             {"long", std::nullopt, "Helpful hint", false, "long"},
             {"short", 's', "Helpful hint", false, "short"}});
}

TEST(options_test, parse_check_values)
{
    const char *avt[] = {"picorg.exe",
                         "/some/src/path",
                         "/some/dst/path",
                         "--int",
                         "1",
                         "--long",
                         "long one",
                         "-s",
                         "short one",
                         "-f"};
    int act = sizeof(avt) / sizeof(avt[0]);
    auto o = Options(act,
                     avt,
                     {{0, "", false, "cmd"},
                      {1, "The source directory", false, "src"},
                      {2, "The dest directory", false, "dst"},
                      {"default", std::nullopt, "Helpful hint", false, "defVal", "default value"},
                      {"int", std::nullopt, "Helpful hint", false, "int"},
                      {"double", 'd', "Helpful hint", false, "double", "4.2"},
                      {"flag", 'f', "Helpful hint", true, "flag"},
                      {"long", std::nullopt, "Helpful hint", false, "long"},
                      {"short", 's', "Helpful hint", false, "short"}});

    EXPECT_EQ(o["cmd"].get<string>(), "picorg.exe");
    EXPECT_EQ(o["src"].get<string>(), "/some/src/path");
    EXPECT_EQ(o["dst"].get<string>(), "/some/dst/path");
    EXPECT_EQ(o["long"].get<string>(), "long one");
    EXPECT_EQ(o["short"].get<string>(), "short one");
    EXPECT_EQ(o["defVal"].get<string>(), "default value");
    EXPECT_EQ(o["int"].get<int>(), 1);
    EXPECT_EQ(o["double"].get<double>(), 4.2);
    EXPECT_TRUE(o["flag"].Exists());
    EXPECT_FALSE(o["nope"].Exists());
    EXPECT_THROW(o["x"].get<int>(), runtime_error);
}

TEST(options_test, unexpected_input)
{
    const char *avt[] = {"picorg.exe",
                         "/some/src/path",
                         "/some/dst/path",
                         "--long",
                         "long one",
                         "-s",
                         "short one",
                         "-f"};
    int act = sizeof(avt) / sizeof(avt[0]);

    auto o = Options();

    EXPECT_THROW(o.Reset(act,
                         avt,
                         {{0, "", false, "cmd"},
                          {1, "The source directory", false, "src"},
                          {2, "The dest directory", false, "dst"},
                          {"long", std::nullopt, "Helpful hint", false, "long"},
                          {"short", 's', "Helpful hint", false, "short"}}),
                 std::runtime_error);
}

TEST(options_test, missing_required_1)
{
    const char *avt[] = {"picorg.exe",
                         "/some/src/path",
                         "/some/dst/path",
                         "-s",
                         "short one"};
    int act = sizeof(avt) / sizeof(avt[0]);

    auto o = Options();

    EXPECT_THROW(o.Reset(act,
                         avt,
                         {{0, "", false, "cmd"},
                          {1, "The source directory", false, "src"},
                          {2, "The dest directory", false, "dst"},
                          {"flag", 'f', "Helpful hint", true, "flag"},
                          {"long", std::nullopt, "Helpful hint", false, "long"},
                          {"short", 's', "Helpful hint", false, "short"}}),
                 std::runtime_error);
}

TEST(options_test, missing_required_2)
{
    const char *avt[] = {"/some/dst/path",
                         "--long",
                         "long one",
                         "-s",
                         "short one",
                         "-f"};
    int act = sizeof(avt) / sizeof(avt[0]);

    auto o = Options();

    EXPECT_THROW(o.Reset(act,
                         avt,
                         {{0, "", false, "cmd"},
                          {1, "The source directory", false, "src"},
                          {2, "The dest directory", false, "dst"},
                          {"flag", 'f', "Helpful hint", true, "flag"},
                          {"long", std::nullopt, "Helpful hint", false, "long"},
                          {"short", 's', "Helpful hint", false, "short"}}),
                 std::runtime_error);
}

TEST(options_test, missing_not_required)
{
    const char *avt[] = {"picorg.exe",
                         "/some/src/path",
                         "/some/dst/path",
                         "-f",
                         "-s",
                         "short one"};
    int act = sizeof(avt) / sizeof(avt[0]);

    auto o = Options();

    o.Reset(act,
            avt,
            {{0, "", false, "cmd"},
             {1, "The source directory", false, "src"},
             {2, "The dest directory", false, "dst"},
             {"flag", 'f', "Helpful hint", true, "flag"},
             {"long", std::nullopt, "Helpful hint", false, "long", "some default long value"},
             {"short", 's', "Helpful hint", false, "short"}});
}

TEST(options_test, interleave_named)
{
    const char *avt[] = {"picorg.exe",
                         "-f",
                         "/some/src/path",
                         "/some/dst/path",
                         "--long",
                         "long one",
                         "-s",
                         "short one"};
    int act = sizeof(avt) / sizeof(avt[0]);

    auto o = Options();

    o.Reset(act,
            avt,
            {{0, "", false, "cmd"},
             {"flag", 'f', "Helpful hint", true, "flag"},
             {1, "The source directory", false, "src"},
             {2, "The dest directory", false, "dst"},
             {"long", std::nullopt, "Helpful hint", false, "long"},
             {"short", 's', "Helpful hint", false, "short"}});
}

TEST(options_test, hints)
{
    auto o = Options();
    o.EmitHints(std::cout,
                {{0, "", false, "cmd"},
                 {"flag", 'f', "Helpful hint", true, "flag"},
                 {1, "The source directory", false, "src"},
                 {2, "The dest directory", false, "dst"},
                 {"long", std::nullopt, "Helpful hint", false, "long"},
                 {"short", 's', "Helpful hint", false, "short"}});

    std::cout << "\n\n";

    o.EmitHints(std::cout,
                {{0, "", false, "cmd"},
                 {"flag_that_is_long", 'f', "Helpful hint", true, "flag"},
                 {1, "The source directory", false, "src"},
                 {2, "The dest directory", false, "dst"},
                 {"long", std::nullopt, "Helpful hint", false, "long"},
                 {"short", 's', "Helpful hint", false, "short"}});
}
