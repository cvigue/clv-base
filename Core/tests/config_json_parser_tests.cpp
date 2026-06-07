// Copyright (c) 2023- Charlie Vigue. All rights reserved.

#include <gtest/gtest.h>

#include "config.h"
#include "config_json_parser.h"

using namespace clv::config;

// ============================================================================
// Parse String Tests
// ============================================================================

class ConfigJsonParserStringTest : public testing::Test
{
  protected:
    using TestConfig = Config<std::string, int, double, bool>;
};

TEST_F(ConfigJsonParserStringTest, ParseSimpleObject)
{
    std::string json = R"({
        "name": "test",
        "port": 8080,
        "ratio": 3.14,
        "enabled": true
    })";

    TestConfig cfg = ConfigJsonParser<std::string, int, double, bool>::ParseString(json);

    EXPECT_EQ(cfg["name"].get<std::string>(), "test");
    EXPECT_EQ(cfg["port"].get<int>(), 8080);
    EXPECT_NEAR(cfg["ratio"].get<double>(), 3.14, 0.01);
    EXPECT_TRUE(cfg["enabled"].get<bool>());
}

TEST_F(ConfigJsonParserStringTest, ParseNestedObject)
{
    std::string json = R"({
        "server": {
            "host": "localhost",
            "port": 8443
        }
    })";

    TestConfig cfg = ConfigJsonParser<std::string, int, double, bool>::ParseString(json);

    EXPECT_EQ(cfg["server"]["host"].get<std::string>(), "localhost");
    EXPECT_EQ(cfg["server"]["port"].get<int>(), 8443);
}

TEST_F(ConfigJsonParserStringTest, ParseArray)
{
    std::string json = R"({
        "ports": [8080, 8081, 8082]
    })";

    TestConfig cfg = ConfigJsonParser<std::string, int, double, bool>::ParseString(json);

    EXPECT_TRUE(cfg["ports"].IsArray());
    EXPECT_EQ(cfg["ports"][0].get<int>(), 8080);
    EXPECT_EQ(cfg["ports"][1].get<int>(), 8081);
    EXPECT_EQ(cfg["ports"][2].get<int>(), 8082);
}

TEST_F(ConfigJsonParserStringTest, ParseMixedTypes)
{
    std::string json = R"({
        "string_val": "hello",
        "int_val": 42,
        "double_val": 2.71828,
        "bool_val": false,
        "null_val": null
    })";

    TestConfig cfg = ConfigJsonParser<std::string, int, double, bool>::ParseString(json);

    EXPECT_EQ(cfg["string_val"].get<std::string>(), "hello");
    EXPECT_EQ(cfg["int_val"].get<int>(), 42);
    EXPECT_NEAR(cfg["double_val"].get<double>(), 2.71828, 0.00001);
    EXPECT_FALSE(cfg["bool_val"].get<bool>());
    EXPECT_TRUE(cfg["null_val"].IsNull());
}

TEST_F(ConfigJsonParserStringTest, ParseInvalidJsonThrows)
{
    std::string json = "{ invalid json }";
    using Parser = ConfigJsonParser<std::string, int, double, bool>;
    EXPECT_THROW(Parser::ParseString(json), std::runtime_error);
}

TEST_F(ConfigJsonParserStringTest, ParseNonObjectRootThrows)
{
    std::string json = R"([1, 2, 3])";
    using Parser = ConfigJsonParser<std::string, int, double, bool>;
    EXPECT_THROW(Parser::ParseString(json), std::runtime_error);
}

// ============================================================================
// Parse File Tests
// ============================================================================

class ConfigJsonParserFileTest : public testing::Test
{
  protected:
    using TestConfig = Config<std::string, int, double, bool>;
};

TEST_F(ConfigJsonParserFileTest, ParseConfigFile)
{
    // This test requires test_config.json to be copied to the build directory
    TestConfig cfg = ConfigJsonParser<std::string, int, double, bool>::ParseFile("test_config.json");

    // Test nested server config
    EXPECT_EQ(cfg["server"]["host"].get<std::string>(), "0.0.0.0");
    EXPECT_EQ(cfg["server"]["port"].get<int>(), 8443);
    EXPECT_EQ(cfg["server"]["threads"].get<int>(), 4);
    EXPECT_TRUE(cfg["server"]["enabled"].get<bool>());

    // Test SSL config
    EXPECT_EQ(cfg["ssl"]["cert_path"].get<std::string>(), "./cert.pem");
    EXPECT_EQ(cfg["ssl"]["key_path"].get<std::string>(), "./pvtkey.pem");
    EXPECT_EQ(cfg["ssl"]["dh_path"].get<std::string>(), "./dh2048.pem");

    // Test static config
    EXPECT_EQ(cfg["static"]["root_dir"].get<std::string>(), "./www");
    EXPECT_EQ(cfg["static"]["default_file"].get<std::string>(), "index.html");

    // Test mixed types
    EXPECT_EQ(cfg["test_values"]["name"].get<std::string>(), "test_server");
    EXPECT_EQ(cfg["test_values"]["version"].get<int>(), 1);
    EXPECT_NEAR(cfg["test_values"]["ratio"].get<double>(), 3.14159, 0.00001);
    EXPECT_FALSE(cfg["test_values"]["debug"].get<bool>());
}

TEST_F(ConfigJsonParserFileTest, ParseNonExistentFileThrows)
{
    using Parser = ConfigJsonParser<std::string, int, double, bool>;
    EXPECT_THROW(Parser::ParseFile("nonexistent.json"), std::runtime_error);
}

// ============================================================================
// Type Validation Tests
// ============================================================================

class ConfigJsonParserTypeTest : public testing::Test
{
};

TEST_F(ConfigJsonParserTypeTest, UnsupportedTypeThrows)
{
    // Config without bool support
    using Parser = ConfigJsonParser<std::string, int, double>;

    std::string json = R"({ "flag": true })";
    EXPECT_THROW(Parser::ParseString(json), std::runtime_error);
}

TEST_F(ConfigJsonParserTypeTest, AllTypesSupported)
{
    // Config with all common types
    // Note: JSON integers will use the first matching integer type in the list (int)
    // and JSON floats will use the first matching float type (double)

    std::string json = R"({
        "str": "test",
        "i": 42,
        "d": 3.14159,
        "b": true
    })";

    auto cfg = ConfigJsonParser<std::string, int, long, long long, double, float, bool>::ParseString(json);

    EXPECT_EQ(cfg["str"].get<std::string>(), "test");
    // JSON integers become 'int' (first integer type in list)
    EXPECT_EQ(cfg["i"].get<int>(), 42);
    // JSON floats become 'double' (first float type in list)
    EXPECT_NEAR(cfg["d"].get<double>(), 3.14159, 0.00001);
    EXPECT_TRUE(cfg["b"].get<bool>());
}
