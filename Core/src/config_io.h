// Copyright (c) 2026- Charlie Vigue. All rights reserved.

#ifndef CLV_CONFIG_IO_H
#define CLV_CONFIG_IO_H

#include <cstddef>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>

#include <nlohmann/json.hpp>

namespace clv::config {

[[nodiscard]] inline std::string ReadTextFile(const std::filesystem::path &filepath,
                                              std::size_t max_bytes,
                                              std::string_view context)
{
    if (!std::filesystem::exists(filepath))
        throw std::runtime_error(std::string(context) + ": file not found: " + filepath.string());

    std::error_code ec;
    const auto fsize = std::filesystem::file_size(filepath, ec);
    if (!ec && fsize > max_bytes)
        throw std::runtime_error(std::string(context) + ": file too large: " + filepath.string());

    std::ifstream file(filepath);
    if (!file.is_open())
        throw std::runtime_error(std::string(context) + ": cannot open file: " + filepath.string());

    std::ostringstream buffer;
    buffer << file.rdbuf();
    const auto content = buffer.str();
    if (content.size() > max_bytes)
        throw std::runtime_error(std::string(context) + ": file too large: " + filepath.string());
    return content;
}

[[nodiscard]] inline nlohmann::json ParseJsonString(std::string_view json_text, std::string_view context)
{
    try
    {
        return nlohmann::json::parse(json_text);
    }
    catch (const nlohmann::json::parse_error &e)
    {
        throw std::runtime_error(std::string(context) + ": JSON parse error: " + std::string(e.what()));
    }
}

[[nodiscard]] inline nlohmann::json ParseJsonFile(const std::filesystem::path &filepath,
                                                  std::string_view context,
                                                  std::size_t max_bytes = 16 * 1024 * 1024)
{
    return ParseJsonString(ReadTextFile(filepath, max_bytes, context), context);
}

[[nodiscard]] inline nlohmann::json ParseJsonObjectFile(const std::filesystem::path &filepath,
                                                        std::string_view context,
                                                        std::size_t max_bytes = 16 * 1024 * 1024)
{
    auto json = ParseJsonFile(filepath, context, max_bytes);
    if (!json.is_object())
        throw std::runtime_error(std::string(context) + ": root JSON must be an object");
    return json;
}

} // namespace clv::config

#endif // CLV_CONFIG_IO_H
