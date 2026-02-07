// Copyright (c) 2023- Charlie Vigue. All rights reserved.

#ifndef CLV_HTTPCORE_MIMETYPE_H
#define CLV_HTTPCORE_MIMETYPE_H

#include <string>
#include <string_view>
#include <unordered_map>
#include <filesystem>

namespace clv::http {

/**
 * @brief Utility class for MIME type detection based on file extensions
 * @details Provides mapping from file extensions to appropriate MIME types
 * for HTTP Content-Type headers. Supports common web file types including
 * HTML, CSS, JavaScript, images, fonts, and various document formats.
 */
class MimeType
{
  public:
    /**
     * @brief Get MIME type for a file extension
     * @param extension File extension (with or without leading dot)
     * @return MIME type string, or "application/octet-stream" for unknown types
     */
    static std::string GetMimeType(std::string_view extension);

    /**
     * @brief Get MIME type for a file path
     * @param filePath Path to the file
     * @return MIME type string based on the file's extension
     */
    static std::string GetMimeType(const std::filesystem::path &filePath);

    /**
     * @brief Check if a MIME type is a text-based type
     * @param mimeType The MIME type to check
     * @return true if the MIME type represents text-based content
     */
    static bool IsTextType(std::string_view mimeType);

    /**
     * @brief Check if a MIME type represents an image
     * @param mimeType The MIME type to check
     * @return true if the MIME type represents an image
     */
    static bool IsImageType(std::string_view mimeType);

  private:
    static const std::unordered_map<std::string, std::string> &GetMimeTypeMap();
};

// ============================================================================================
// Implementation
// ============================================================================================

inline std::string MimeType::GetMimeType(std::string_view extension)
{
    std::string ext(extension);

    // Ensure extension starts with a dot
    if (!ext.empty() && ext[0] != '.')
    {
        ext = "." + ext;
    }

    const auto &mimeTypes = GetMimeTypeMap();
    auto it = mimeTypes.find(ext);
    if (it != mimeTypes.end())
    {
        return it->second;
    }

    return "application/octet-stream"; // Default for unknown types
}

inline std::string MimeType::GetMimeType(const std::filesystem::path &filePath)
{
    return GetMimeType(static_cast<std::string_view>(filePath.extension().string()));
}

inline bool MimeType::IsTextType(std::string_view mimeType)
{
    return mimeType.starts_with("text/") || mimeType == "application/javascript" || mimeType == "application/json" || mimeType == "application/xml" || mimeType == "image/svg+xml";
}

inline bool MimeType::IsImageType(std::string_view mimeType)
{
    return mimeType.starts_with("image/");
}

inline const std::unordered_map<std::string, std::string> &MimeType::GetMimeTypeMap()
{
    static const std::unordered_map<std::string, std::string> mimeTypes = {
        // Text files
        {".html", "text/html"},
        {".htm", "text/html"},
        {".css", "text/css"},
        {".js", "application/javascript"},
        {".mjs", "application/javascript"},
        {".json", "application/json"},
        {".xml", "application/xml"},
        {".txt", "text/plain"},
        {".md", "text/markdown"},
        {".csv", "text/csv"},

        // Images
        {".jpg", "image/jpeg"},
        {".jpeg", "image/jpeg"},
        {".png", "image/png"},
        {".gif", "image/gif"},
        {".bmp", "image/bmp"},
        {".ico", "image/x-icon"},
        {".svg", "image/svg+xml"},
        {".webp", "image/webp"},
        {".tiff", "image/tiff"},
        {".tif", "image/tiff"},

        // Documents
        {".pdf", "application/pdf"},
        {".doc", "application/msword"},
        {".docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
        {".xls", "application/vnd.ms-excel"},
        {".xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"},
        {".ppt", "application/vnd.ms-powerpoint"},
        {".pptx", "application/vnd.openxmlformats-officedocument.presentationml.presentation"},

        // Archives
        {".zip", "application/zip"},
        {".tar", "application/x-tar"},
        {".gz", "application/gzip"},
        {".bz2", "application/x-bzip2"},
        {".7z", "application/x-7z-compressed"},
        {".rar", "application/vnd.rar"},

        // Audio
        {".mp3", "audio/mpeg"},
        {".wav", "audio/wav"},
        {".ogg", "audio/ogg"},
        {".m4a", "audio/mp4"},
        {".aac", "audio/aac"},
        {".flac", "audio/flac"},

        // Video
        {".mp4", "video/mp4"},
        {".avi", "video/x-msvideo"},
        {".mov", "video/quicktime"},
        {".wmv", "video/x-ms-wmv"},
        {".flv", "video/x-flv"},
        {".webm", "video/webm"},
        {".mkv", "video/x-matroska"},

        // Fonts
        {".woff", "font/woff"},
        {".woff2", "font/woff2"},
        {".ttf", "font/ttf"},
        {".otf", "font/otf"},
        {".eot", "application/vnd.ms-fontobject"},

        // Other common web types
        {".manifest", "text/cache-manifest"},
        {".appcache", "text/cache-manifest"},
        {".webapp", "application/x-web-app-manifest+json"},
        {".rss", "application/rss+xml"},
        {".atom", "application/atom+xml"}};

    return mimeTypes;
}

} // namespace clv::http

#endif // CLV_HTTPCORE_MIMETYPE_H