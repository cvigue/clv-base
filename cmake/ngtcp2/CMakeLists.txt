# CMake wrapper for ngtcp2 (and ngtcp2_crypto_quictls).
#
# ngtcp2 is a C library implementation of QUIC (RFC 9000/9001/9002).
# We build it via ExternalProject so that it can pick up the quictls
# install tree, whose outputs are only available at build time (quictls
# itself is also an ExternalProject — see ../quictls/CMakeLists.txt).
#
# Source: clv-base/extern/ngtcp2 (git submodule of github.com/ngtcp2/ngtcp2).

cmake_minimum_required(VERSION 3.15)
project(ngtcp2_wrapper C)

include(ExternalProject)
include(ProcessorCount)
ProcessorCount(NPROCS)
if(NPROCS EQUAL 0)
    set(NPROCS 4)
endif()

set(NGTCP2_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../extern/ngtcp2)
set(NGTCP2_INSTALL_DIR ${CMAKE_BINARY_DIR}/ngtcp2)

# quictls install tree (set by ../quictls/CMakeLists.txt during its build).
# We must depend on quictls_build so that quictls headers and libraries
# exist before ngtcp2 configures.
set(QUICTLS_INSTALL_DIR ${CMAKE_BINARY_DIR}/quictls)

# Match the quictls lib path resolution (lib64 on x86_64 Linux, lib elsewhere).
if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64")
    set(_quictls_libdir ${QUICTLS_INSTALL_DIR}/lib64)
else()
    set(_quictls_libdir ${QUICTLS_INSTALL_DIR}/lib)
endif()

# ngtcp2 produces (with quictls backend):
#   lib/libngtcp2.a
#   crypto/quictls/libngtcp2_crypto_quictls.a
set(NGTCP2_LIB         ${NGTCP2_INSTALL_DIR}/lib/libngtcp2.a)
set(NGTCP2_CRYPTO_LIB  ${NGTCP2_INSTALL_DIR}/lib/libngtcp2_crypto_quictls.a)

# Configuration arguments. We disable shared/tests/examples and pin the
# crypto backend to OpenSSL (quictls is detected via the QUIC API symbols).
set(NGTCP2_CMAKE_ARGS
    -DCMAKE_BUILD_TYPE=$<IF:$<CONFIG:Debug>,Debug,Release>
    -DCMAKE_INSTALL_PREFIX=${NGTCP2_INSTALL_DIR}
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON
    -DENABLE_STATIC_LIB=ON
    -DENABLE_SHARED_LIB=OFF
    -DENABLE_LIB_ONLY=ON
    -DENABLE_OPENSSL=ON
    -DENABLE_GNUTLS=OFF
    -DENABLE_BORINGSSL=OFF
    -DENABLE_PICOTLS=OFF
    -DENABLE_WOLFSSL=OFF
    -DBUILD_TESTING=OFF
    -DOPENSSL_ROOT_DIR=${QUICTLS_INSTALL_DIR}
    -DOPENSSL_USE_STATIC_LIBS=ON
    -DOPENSSL_INCLUDE_DIR=${QUICTLS_INSTALL_DIR}/include
    -DOPENSSL_CRYPTO_LIBRARY=${_quictls_libdir}/libcrypto.a
    -DOPENSSL_SSL_LIBRARY=${_quictls_libdir}/libssl.a
)

# Pre-create install dirs so include directory checks pass at configure time.
file(MAKE_DIRECTORY ${NGTCP2_INSTALL_DIR}/include)

ExternalProject_Add(ngtcp2_build
    SOURCE_DIR        ${NGTCP2_SOURCE_DIR}
    BINARY_DIR        ${CMAKE_BINARY_DIR}/ngtcp2-build
    INSTALL_DIR       ${NGTCP2_INSTALL_DIR}
    CMAKE_ARGS        ${NGTCP2_CMAKE_ARGS}
    BUILD_BYPRODUCTS  ${NGTCP2_LIB} ${NGTCP2_CRYPTO_LIB}
    DEPENDS           quictls_build
)

# Imported targets ---------------------------------------------------------

add_library(ngtcp2 STATIC IMPORTED GLOBAL)
set_target_properties(ngtcp2 PROPERTIES
    IMPORTED_LOCATION ${NGTCP2_LIB}
    INTERFACE_INCLUDE_DIRECTORIES "$<BUILD_INTERFACE:${NGTCP2_INSTALL_DIR}/include>"
)
add_dependencies(ngtcp2 ngtcp2_build)

add_library(ngtcp2_crypto_quictls STATIC IMPORTED GLOBAL)
set_target_properties(ngtcp2_crypto_quictls PROPERTIES
    IMPORTED_LOCATION ${NGTCP2_CRYPTO_LIB}
    INTERFACE_INCLUDE_DIRECTORIES "$<BUILD_INTERFACE:${NGTCP2_INSTALL_DIR}/include>"
    INTERFACE_LINK_LIBRARIES "ngtcp2;quictls"
)
add_dependencies(ngtcp2_crypto_quictls ngtcp2_build)

# Export variables for parent CMakeLists -----------------------------------

set(NGTCP2_INCLUDE_DIR    ${NGTCP2_INSTALL_DIR}/include   CACHE PATH     "ngtcp2 include directory")
set(NGTCP2_LIBRARY        ${NGTCP2_LIB}                   CACHE FILEPATH "ngtcp2 static library")
set(NGTCP2_CRYPTO_LIBRARY ${NGTCP2_CRYPTO_LIB}            CACHE FILEPATH "ngtcp2 quictls crypto static library")
