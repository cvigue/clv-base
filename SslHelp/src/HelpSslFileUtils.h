// Copyright (c) 2023- Charlie Vigue. All rights reserved.

#ifndef CLV_SSLHELP_FILE_UTILS_H
#define CLV_SSLHELP_FILE_UTILS_H

#include <cstdio>

namespace clv::OpenSSL {

/// Custom deleter for FILE* to avoid lint warnings about fclose attributes
inline void FileDeleter(FILE *f) noexcept
{
    if (f)
        fclose(f);
}

} // namespace clv::OpenSSL

#endif // CLV_SSLHELP_FILE_UTILS_H
