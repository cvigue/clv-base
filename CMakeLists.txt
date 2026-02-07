cmake_minimum_required(VERSION 3.15.0)
project(ClvBase VERSION 0.1.0)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Enable position-independent code
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Add googletest from extern/
add_subdirectory(extern/googletest)

# Add spdlog from extern/
add_subdirectory(extern/spdlog)

# Enable testing before including nghttp3
include(CTest)

# Add nghttp3 from extern/ (for HTTP/3 support) - disable examples and tests
set(ENABLE_LIB_ONLY ON CACHE BOOL "Build nghttp3 library only" FORCE)
set(BUILD_TESTING_SAVED ${BUILD_TESTING})
set(BUILD_TESTING OFF CACHE BOOL "Disable nghttp3 tests" FORCE)
add_subdirectory(extern/nghttp3)
set(BUILD_TESTING ${BUILD_TESTING_SAVED} CACHE BOOL "Restore BUILD_TESTING" FORCE)

# Add json from extern/ (nlohmann/json)
add_subdirectory(extern/json)

# Find required dependencies
find_package(OpenSSL REQUIRED)

# Add compiler-specific flags
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fcoroutines")
    if(CMAKE_CXX_COMPILER_VERSION VERSION_GREATER_EQUAL "11.0")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-deprecated-declarations")
    endif()
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    if(APPLE)
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -stdlib=libc++")
    endif()
endif()

# ASIO configuration
set(ASIO_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/extern/asio/asio/include")
if(NOT EXISTS "${ASIO_INCLUDE_DIR}/asio.hpp")
    message(FATAL_ERROR "ASIO not found at ${ASIO_INCLUDE_DIR}. Please ensure ASIO is present in extern/asio/")
endif()

# Build quictls (OpenSSL fork with QUIC support) - needed for QUIC/HTTP3
# Off by default; consumers that need QUIC (e.g. meshcore) set -DUSING_QUIC_TLS=ON
option(USING_QUIC_TLS "Build and link the vendored quictls (OpenSSL+QUIC)" OFF)
if(USING_QUIC_TLS)
    add_subdirectory(cmake/quictls)
endif()

# Optional ASAN (Address Sanitizer) support
option(ENABLE_ASAN "Enable Address Sanitizer" OFF)

# Auto-enable ASAN when build type is "ASAN"
if(CMAKE_BUILD_TYPE STREQUAL "ASAN" AND NOT ENABLE_ASAN)
    message(STATUS "CMAKE_BUILD_TYPE is ASAN — enabling ENABLE_ASAN automatically")
    set(ENABLE_ASAN ON CACHE BOOL "Enable Address Sanitizer" FORCE)
endif()

function(apply_asan_flags target)
    if(ENABLE_ASAN)
        target_compile_options(${target} PRIVATE
            -fsanitize=address
            -fno-omit-frame-pointer
            -g
        )
        target_link_options(${target} PRIVATE
            -fsanitize=address
        )
    endif()
endfunction()

# Add subdirectories
add_subdirectory(Core)
add_subdirectory(SslHelp)
add_subdirectory(NetCore)
