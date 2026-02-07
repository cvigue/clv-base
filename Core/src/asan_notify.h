#ifndef CLV_ASAN_NOTIFY_H
#define CLV_ASAN_NOTIFY_H

#include <iostream>

#ifndef CLV_ASAN_ENABLED
#if defined(__SANITIZE_ADDRESS__) || (defined(__has_feature) && __has_feature(address_sanitizer))
#define CLV_ASAN_ENABLED 1
#else
#define CLV_ASAN_ENABLED 0
#endif
#endif

inline void clv_announce_asan()
{
#if CLV_ASAN_ENABLED
    std::cout << "[ ASAN ] AddressSanitizer is enabled for this build." << std::endl;
#endif
}

#endif // CLV_ASAN_NOTIFY_H
