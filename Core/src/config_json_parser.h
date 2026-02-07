// Copyright (c) 2023- Charlie Vigue. All rights reserved.

#ifndef CLV_ConfigJsonParser_H
#define CLV_ConfigJsonParser_H

#include "config.h"
#include <fstream>
#include <filesystem>
#include <stdexcept>

#include "nlohmann/json.hpp"

namespace clv::config {

/**
    @brief JSON configuration file parser
    @details Parses JSON files into Config objects using nlohmann/json library.

    Supports:
    - Basic types: string, int, double, bool
    - Nested objects
    - Arrays

    Example JSON:
    ```json
    {
        "server": {
            "host": "0.0.0.0",
            "port": 8443,
            "threads": 4
        },
        "ssl": {
            "enabled": true,
            "cert_path": "./cert.pem"
        }
    }
    ```

    Usage:
    ```cpp
    using MyConfig = Config<std::string, int, double, bool>;
    MyConfig cfg = ConfigJsonParser<std::string, int, double, bool>::ParseFile("config.json");
    ```
*/
template <typename... Ts>
class ConfigJsonParser
{
  public:
    /**
        @brief Parse a JSON file into a Config object
        @param filepath Path to the JSON file
        @return Config<Ts...> Parsed configuration
        @throws std::runtime_error if file cannot be read or parsed
    */
    static Config<Ts...> ParseFile(const std::filesystem::path &filepath);

    /**
        @brief Parse a JSON string into a Config object
        @param jsonString JSON string to parse
        @return Config<Ts...> Parsed configuration
        @throws std::runtime_error if JSON is malformed
    */
    static Config<Ts...> ParseString(std::string_view jsonString);

  private:
    /**
        @brief Convert a JSON value to a ConfigValue
        @param json The JSON value to convert
        @return ConfigValue<Ts...> The converted config value
    */
    static ConfigValue<Ts...> JsonToConfigValue(const nlohmann::json &json);
};

template <typename... Ts>
Config<Ts...> ConfigJsonParser<Ts...>::ParseFile(const std::filesystem::path &filepath)
{
    if (!std::filesystem::exists(filepath))
        throw std::runtime_error("ConfigJsonParser::ParseFile: File not found: " + filepath.string());

    std::ifstream file(filepath);
    if (!file.is_open())
        throw std::runtime_error("ConfigJsonParser::ParseFile: Cannot open file: " + filepath.string());

    nlohmann::json json;
    try
    {
        file >> json;
    }
    catch (const nlohmann::json::parse_error &e)
    {
        throw std::runtime_error("ConfigJsonParser::ParseFile: JSON parse error: " + std::string(e.what()));
    }

    if (!json.is_object())
        throw std::runtime_error("ConfigJsonParser::ParseFile: Root JSON must be an object");

    Config<Ts...> config;
    for (auto it = json.begin(); it != json.end(); ++it)
    {
        config.Set(it.key(), JsonToConfigValue(it.value()));
    }

    return config;
}

template <typename... Ts>
Config<Ts...> ConfigJsonParser<Ts...>::ParseString(std::string_view jsonString)
{
    nlohmann::json json;
    try
    {
        json = nlohmann::json::parse(jsonString);
    }
    catch (const nlohmann::json::parse_error &e)
    {
        throw std::runtime_error("ConfigJsonParser::ParseString: JSON parse error: " + std::string(e.what()));
    }

    if (!json.is_object())
        throw std::runtime_error("ConfigJsonParser::ParseString: Root JSON must be an object");

    Config<Ts...> config;
    for (auto it = json.begin(); it != json.end(); ++it)
    {
        config.Set(it.key(), JsonToConfigValue(it.value()));
    }

    return config;
}

template <typename... Ts>
ConfigValue<Ts...> ConfigJsonParser<Ts...>::JsonToConfigValue(const nlohmann::json &json)
{
    ConfigValue<Ts...> value;

    if (json.is_null())
    {
        value.data = std::monostate{};
    }
    else if (json.is_boolean())
    {
        // Try to match bool type
        if constexpr ((std::is_same_v<bool, Ts> || ...))
        {
            value.data = json.get<bool>();
        }
        else
        {
            throw std::runtime_error("ConfigJsonParser: Boolean type not supported in Config type list");
        }
    }
    else if (json.is_number_integer())
    {
        // Try to match int type
        if constexpr ((std::is_same_v<int, Ts> || ...))
        {
            value.data = json.get<int>();
        }
        else if constexpr ((std::is_same_v<long, Ts> || ...))
        {
            value.data = json.get<long>();
        }
        else if constexpr ((std::is_same_v<long long, Ts> || ...))
        {
            value.data = json.get<long long>();
        }
        else
        {
            throw std::runtime_error("ConfigJsonParser: Integer type not supported in Config type list");
        }
    }
    else if (json.is_number_float())
    {
        // Try to match double/float type
        if constexpr ((std::is_same_v<double, Ts> || ...))
        {
            value.data = json.get<double>();
        }
        else if constexpr ((std::is_same_v<float, Ts> || ...))
        {
            value.data = json.get<float>();
        }
        else
        {
            throw std::runtime_error("ConfigJsonParser: Floating-point type not supported in Config type list");
        }
    }
    else if (json.is_string())
    {
        // Try to match string type
        if constexpr ((std::is_same_v<std::string, Ts> || ...))
        {
            value.data = json.get<std::string>();
        }
        else
        {
            throw std::runtime_error("ConfigJsonParser: String type not supported in Config type list");
        }
    }
    else if (json.is_array())
    {
        std::vector<ConfigValue<Ts...>> array;
        for (const auto &element : json)
        {
            array.push_back(JsonToConfigValue(element));
        }
        value.data = array;
    }
    else if (json.is_object())
    {
        std::unordered_map<std::string, ConfigValue<Ts...>> obj;
        for (auto it = json.begin(); it != json.end(); ++it)
        {
            obj[it.key()] = JsonToConfigValue(it.value());
        }
        value.data = obj;
    }
    else
    {
        throw std::runtime_error("ConfigJsonParser: Unsupported JSON type");
    }

    return value;
}

} // namespace clv::config


#endif // CLV_ConfigJsonParser_H
