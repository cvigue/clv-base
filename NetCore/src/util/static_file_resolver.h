// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#pragma once

#include <filesystem>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>

namespace clv::util {

/**
 * @brief Resolves and validates static file paths with security checks
 * @details Provides protocol-agnostic static file resolution with:
 *          - Path sanitization and normalization
 *          - Directory traversal attack prevention
 *          - Root directory confinement verification
 *          - Default file handling (index.html)
 */
struct StaticFileResolver
{
    /**
     * @brief Resolve a request URL to a filesystem path with security validation
     * @param request_url The incoming request URL (e.g., "/static/page.html")
     * @param url_prefix The URL prefix to strip (e.g., "/static")
     * @param root_dir The filesystem root directory to serve from
     * @param default_file Default file to serve for directory requests (default: "index.html")
     * @return The resolved filesystem path if valid, std::nullopt if invalid/insecure
     * @details Validates that:
     *          - URL starts with the expected prefix
     *          - No null bytes in URL (security)
     *          - No ".." directory traversal attempts
     *          - Resolved path stays within root_dir (canonical path check)
     *          - File exists and is a regular file
     */
    static std::optional<std::filesystem::path>
    Resolve(std::string_view request_url,
            std::string_view url_prefix,
            const std::filesystem::path &root_dir,
            std::string_view default_file = "index.html")
    {
        // Check if the request URL starts with our URL prefix
        if (request_url.size() < url_prefix.size() || request_url.substr(0, url_prefix.size()) != url_prefix)
        {
            return std::nullopt;
        }

        // Check for null bytes in the URL (security measure)
        if (request_url.find('\0') != std::string_view::npos)
        {
            return std::nullopt;
        }

        // Extract the relative path from the URL
        std::string relative_path;
        if (request_url.size() > url_prefix.size())
        {
            relative_path = request_url.substr(url_prefix.size());
        }
        else
        {
            relative_path = "/";
        }

        // Handle root case - serve default file if it exists
        if (relative_path == "/" || relative_path.empty())
        {
            auto default_path = root_dir / default_file;
            if (std::filesystem::exists(default_path) && std::filesystem::is_regular_file(default_path))
            {
                return default_path;
            }
        }

        // Build the full file path
        auto full_path = root_dir;

        // Parse the relative path and build filesystem path
        std::istringstream path_stream(relative_path);
        std::string segment;

        while (std::getline(path_stream, segment, '/'))
        {
            if (segment.empty() || segment == ".")
            {
                continue;
            }
            if (segment == "..")
            {
                // Prevent directory traversal attacks
                return std::nullopt;
            }
            full_path /= segment;
        }

        // Security check: ensure the resolved path is still under our base directory
        auto canonical_base = std::filesystem::canonical(root_dir);
        std::filesystem::path canonical_full;

        try
        {
            canonical_full = std::filesystem::weakly_canonical(full_path);
        }
        catch (const std::filesystem::filesystem_error &)
        {
            // Path is invalid (e.g., too long, invalid characters)
            return std::nullopt;
        }

        auto base_str = canonical_base.string();
        auto full_str = canonical_full.string();

        if (full_str.size() < base_str.size() || full_str.substr(0, base_str.size()) != base_str)
        {
            return std::nullopt;
        }

        // Check if the file exists and is a regular file
        if (std::filesystem::exists(full_path) && std::filesystem::is_regular_file(full_path))
        {
            return full_path;
        }

        return std::nullopt;
    }

    /**
     * @brief Normalize URL prefix for consistent matching
     * @param url_prefix The URL prefix to normalize
     * @return Normalized prefix (starts with "/", doesn't end with "/")
     * @details Ensures prefix format: "/prefix" not "prefix/" or "prefix"
     */
    static std::string NormalizeUrlPrefix(std::string_view url_prefix)
    {
        std::string normalized{url_prefix};

        // Ensure it starts with "/"
        if (normalized.empty() || normalized[0] != '/')
        {
            normalized = "/" + normalized;
        }

        // Remove trailing "/" if present (except for root "/")
        if (normalized.size() > 1 && normalized.back() == '/')
        {
            normalized.pop_back();
        }

        return normalized;
    }
};

} // namespace clv::util
