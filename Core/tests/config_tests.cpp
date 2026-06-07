// Copyright (c) 2023- Charlie Vigue. All rights reserved.

#include <gtest/gtest.h>

#include "config.h"

using namespace clv::config;

// ============================================================================
// Basic Type Tests
// ============================================================================

class ConfigBasicTest : public testing::Test
{
  protected:
    using TestConfig = Config<std::string, int, double, bool>;
};

TEST_F(ConfigBasicTest, CreateEmpty)
{
    TestConfig cfg;
    EXPECT_EQ(cfg.Size(), 0);
}

TEST_F(ConfigBasicTest, SetAndGetString)
{
    TestConfig cfg;
    cfg.Set("name", std::string("Charlie"));
    std::string name = cfg["name"].get<std::string>();
    EXPECT_EQ(name, "Charlie");
}

TEST_F(ConfigBasicTest, SetAndGetInt)
{
    TestConfig cfg;
    cfg.Set("port", 8080);
    int port = cfg["port"].get<int>();
    EXPECT_EQ(port, 8080);
}

TEST_F(ConfigBasicTest, SetAndGetDouble)
{
    TestConfig cfg;
    cfg.Set("ratio", 3.14159);
    double ratio = cfg["ratio"].get<double>();
    EXPECT_NEAR(ratio, 3.14159, 0.00001);
}

TEST_F(ConfigBasicTest, SetAndGetBool)
{
    TestConfig cfg;
    cfg.Set("enabled", true);
    bool enabled = cfg["enabled"].get<bool>();
    EXPECT_TRUE(enabled);
}

// ============================================================================
// Default Value Tests
// ============================================================================

class ConfigDefaultTest : public testing::Test
{
  protected:
    using TestConfig = Config<std::string, int, double, bool>;
};

TEST_F(ConfigDefaultTest, MissingKeyReturnsDefault)
{
    TestConfig cfg;
    int port = cfg["missing"].get<int>(9000);
    EXPECT_EQ(port, 9000);
}

TEST_F(ConfigDefaultTest, ExistingKeyIgnoresDefault)
{
    TestConfig cfg;
    cfg.Set("port", 8080);
    int port = cfg["port"].get<int>(9000);
    EXPECT_EQ(port, 8080);
}

TEST_F(ConfigDefaultTest, DefaultsForAllTypes)
{
    TestConfig cfg;

    std::string str = cfg["missing_str"].get<std::string>("default");
    EXPECT_EQ(str, "default");

    int i = cfg["missing_int"].get<int>(42);
    EXPECT_EQ(i, 42);

    double d = cfg["missing_double"].get<double>(3.14);
    EXPECT_NEAR(d, 3.14, 0.01);

    bool b = cfg["missing_bool"].get<bool>(false);
    EXPECT_FALSE(b);
}

// ============================================================================
// Nested Object Tests
// ============================================================================

// ============================================================================
// Nested Object Tests
// ============================================================================

class ConfigNestedTest : public testing::Test
{
  protected:
    using TestConfig = Config<std::string, int, double, bool>;
};

TEST_F(ConfigNestedTest, AccessNestedObject)
{
    TestConfig cfg;
    // Set at root level - the nested test will come when SetNested is implemented
    cfg.Set("port", 8080);
    int port = cfg["port"].get<int>(0);
    EXPECT_EQ(port, 8080);
}

TEST_F(ConfigNestedTest, MissingNestedKeyReturnsDefault)
{
    TestConfig cfg;
    cfg.Set("port", 8080);
    // Access non-existent nested key returns default
    int timeout = cfg["timeout"].get<int>(30);
    EXPECT_EQ(timeout, 30);
}

// ============================================================================
// Array Tests
// ============================================================================

class ConfigArrayTest : public testing::Test
{
  protected:
    using TestConfig = Config<std::string, int, double, bool>;
};

TEST_F(ConfigArrayTest, AccessArrayByIndex)
{
    TestConfig cfg;
    // Note: Array support depends on implementation
    // For now, these tests are placeholders
    int val = cfg["numbers"][0].get<int>(999);
    EXPECT_EQ(val, 999); // Should return default for missing
}

// ============================================================================
// Type Introspection Tests
// ============================================================================

class ConfigTypeTest : public testing::Test
{
  protected:
    using TestConfig = Config<std::string, int, double, bool>;
};

TEST_F(ConfigTypeTest, IsType)
{
    TestConfig cfg;

    cfg.Set("text", std::string("hello"));
    cfg.Set("number", 42);
    cfg.Set("flag", true);

    EXPECT_TRUE(cfg["text"].IsType<std::string>());
    EXPECT_FALSE(cfg["text"].IsType<int>());

    EXPECT_TRUE(cfg["number"].IsType<int>());
    EXPECT_FALSE(cfg["number"].IsType<std::string>());

    EXPECT_TRUE(cfg["flag"].IsType<bool>());
}

TEST_F(ConfigTypeTest, IsNull)
{
    TestConfig cfg;

    cfg.Set("text_val", std::string("hello"));

    EXPECT_FALSE(cfg["text_val"].IsNull());
    EXPECT_TRUE(cfg["missing"].IsNull());
}

// ============================================================================
// Existence Tests
// ============================================================================

class ConfigExistenceTest : public testing::Test
{
  protected:
    using TestConfig = Config<std::string, int, double, bool>;
};

TEST_F(ConfigExistenceTest, KeyExists)
{
    TestConfig cfg;
    cfg.Set("key", std::string("value"));

    EXPECT_TRUE(cfg["key"].Exists());
    EXPECT_FALSE(cfg["missing"].Exists());
}

TEST_F(ConfigExistenceTest, HasKey)
{
    TestConfig cfg;
    cfg.Set("key", std::string("value"));

    EXPECT_TRUE(cfg.HasKey("key"));
    EXPECT_FALSE(cfg.HasKey("missing"));
}

TEST_F(ConfigExistenceTest, Size)
{
    TestConfig cfg;

    EXPECT_EQ(cfg.Size(), 0);

    cfg.Set("a", 1);
    EXPECT_EQ(cfg.Size(), 1);

    cfg.Set("b", 2);
    EXPECT_EQ(cfg.Size(), 2);

    cfg.Clear();
    EXPECT_EQ(cfg.Size(), 0);
}

// ============================================================================
// Type Conversion Tests
// ============================================================================

class ConfigConversionTest : public testing::Test
{
  protected:
    using TestConfig = Config<std::string, int, double, bool>;
};

TEST_F(ConfigConversionTest, StringToInt)
{
    TestConfig cfg;
    cfg.Set("number", std::string("42"));
    int val = cfg["number"].get<int>();
    EXPECT_EQ(val, 42);
}

TEST_F(ConfigConversionTest, StringToDouble)
{
    TestConfig cfg;
    cfg.Set("pi", std::string("3.14159"));
    double val = cfg["pi"].get<double>();
    EXPECT_NEAR(val, 3.14159, 0.00001);
}

TEST_F(ConfigConversionTest, StringToBool)
{
    TestConfig cfg;
    cfg.Set("true1", std::string("true"));
    cfg.Set("true2", std::string("1"));
    cfg.Set("false1", std::string("false"));
    cfg.Set("false2", std::string("0"));

    EXPECT_TRUE(cfg["true1"].get<bool>());
    EXPECT_TRUE(cfg["true2"].get<bool>());
    EXPECT_FALSE(cfg["false1"].get<bool>());
    EXPECT_FALSE(cfg["false2"].get<bool>());
}

// ============================================================================
// Error Handling Tests
// ============================================================================

class ConfigErrorTest : public testing::Test
{
  protected:
    using TestConfig = Config<std::string, int, double, bool>;
};

TEST_F(ConfigErrorTest, GetThrowsOnNull)
{
    TestConfig cfg;
    EXPECT_THROW(cfg["missing"].get<int>(), std::runtime_error);
}

TEST_F(ConfigErrorTest, GetWithDefaultDoesNotThrow)
{
    TestConfig cfg;
    EXPECT_NO_THROW({
        int val = cfg["missing"].get<int>(42);
        EXPECT_EQ(val, 42);
    });
}

TEST_F(ConfigErrorTest, InvalidConversion)
{
    TestConfig cfg;
    cfg.Set("text", std::string("not_a_number"));
    EXPECT_THROW(cfg["text"].get<int>(), std::invalid_argument);
}
