# CMake wrapper for quictls/openssl
# quictls is a fork of OpenSSL with QUIC API support
# See: https://github.com/quictls/openssl

cmake_minimum_required(VERSION 3.15)
project(quictls_wrapper)

include(ExternalProject)

# Detect number of CPU cores for parallel build
include(ProcessorCount)
ProcessorCount(NPROCS)
if(NPROCS EQUAL 0)
    set(NPROCS 4)
endif()

set(QUICTLS_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../extern/quictls)

# Configure options for quictls build
# Important: quictls provides the QUIC callback API (SSL_set_quic_method, etc.)
# which is what we need for our ASIO-based architecture.
# Note: We exclude tests and apps to speed up the build.
set(QUICTLS_CONFIGURE_OPTIONS
    --prefix=${CMAKE_BINARY_DIR}/quictls
    --openssldir=${CMAKE_BINARY_DIR}/quictls/ssl
    no-shared
    no-tests
)

# Add debug config for Debug builds
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    list(APPEND QUICTLS_CONFIGURE_OPTIONS --debug)
endif()

# Platform-specific settings
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    list(APPEND QUICTLS_CONFIGURE_OPTIONS linux-x86_64)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    if(CMAKE_SYSTEM_PROCESSOR STREQUAL "arm64")
        list(APPEND QUICTLS_CONFIGURE_OPTIONS darwin64-arm64-cc)
    else()
        list(APPEND QUICTLS_CONFIGURE_OPTIONS darwin64-x86_64-cc)
    endif()
elseif(WIN32)
    list(APPEND QUICTLS_CONFIGURE_OPTIONS VC-WIN64A)
endif()

# Determine library directory (quictls installs to lib64 on x86_64 Linux)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64")
    set(QUICTLS_LIB_DIR ${CMAKE_BINARY_DIR}/quictls/lib64)
else()
    set(QUICTLS_LIB_DIR ${CMAKE_BINARY_DIR}/quictls/lib)
endif()

# Create quictls directories ahead of time so CMake doesn't complain about non-existent paths
file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/quictls/include)

# Build quictls as an external project
ExternalProject_Add(quictls_build
    SOURCE_DIR ${QUICTLS_SOURCE_DIR}
    CONFIGURE_COMMAND ${QUICTLS_SOURCE_DIR}/Configure ${QUICTLS_CONFIGURE_OPTIONS}
    BUILD_COMMAND make -j${NPROCS} build_libs
    INSTALL_COMMAND make install_sw
    BUILD_IN_SOURCE OFF
    BINARY_DIR ${CMAKE_BINARY_DIR}/quictls-build
    INSTALL_DIR ${CMAKE_BINARY_DIR}/quictls
    BUILD_BYPRODUCTS
        ${QUICTLS_LIB_DIR}/libssl.a
        ${QUICTLS_LIB_DIR}/libcrypto.a
)

# Create imported targets for quictls libraries
add_library(quictls_ssl STATIC IMPORTED GLOBAL)
set_target_properties(quictls_ssl PROPERTIES
    IMPORTED_LOCATION ${QUICTLS_LIB_DIR}/libssl.a
    # Use generator expression to avoid validation at config time
    INTERFACE_INCLUDE_DIRECTORIES "$<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/quictls/include>"
)
add_dependencies(quictls_ssl quictls_build)

add_library(quictls_crypto STATIC IMPORTED GLOBAL)
set_target_properties(quictls_crypto PROPERTIES
    IMPORTED_LOCATION ${QUICTLS_LIB_DIR}/libcrypto.a
    INTERFACE_INCLUDE_DIRECTORIES "$<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/quictls/include>"
)
add_dependencies(quictls_crypto quictls_build)

# Create an interface library for convenient linking
add_library(quictls INTERFACE)
target_link_libraries(quictls INTERFACE quictls_ssl quictls_crypto)
target_include_directories(quictls INTERFACE ${CMAKE_BINARY_DIR}/quictls/include)
add_dependencies(quictls quictls_build)

# Export variables for parent CMakeLists
set(QUICTLS_INCLUDE_DIR ${CMAKE_BINARY_DIR}/quictls/include CACHE PATH "quictls include directory")
set(QUICTLS_SSL_LIBRARY ${QUICTLS_LIB_DIR}/libssl.a CACHE FILEPATH "quictls ssl library")
set(QUICTLS_CRYPTO_LIBRARY ${QUICTLS_LIB_DIR}/libcrypto.a CACHE FILEPATH "quictls crypto library")
