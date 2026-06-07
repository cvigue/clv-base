# Copyright (c) 2023- Charlie Vigue. All rights reserved.

find_package(OpenSSL REQUIRED)

# NetCore library
add_library(clv_netcore STATIC
    src/util/netlink_helper.cpp
    src/util/nftables_client.cpp
    src/tun/tun_device.cpp
)

target_include_directories(clv_netcore
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${ASIO_INCLUDE_DIR}
)

target_link_libraries(clv_netcore
    PUBLIC
        clv::sslhelp
        clv::core
        OpenSSL::SSL
        OpenSSL::Crypto
        spdlog::spdlog
)
if(USING_QUIC_TLS)
    target_link_libraries(clv_netcore PRIVATE quictls_ssl quictls_crypto)

    # clv::quic — ngtcp2-based transport (Phase 1 of QUIC migration).
    # Compiled into clv_netcore so that consumers (meshcore) pick it up
    # via the existing PUBLIC clv::netcore link.
    target_sources(clv_netcore PRIVATE
        src/quic/endpoint.cpp
        src/quic/tls_context.cpp
        src/quic/connection.cpp
    )
    target_include_directories(clv_netcore PRIVATE
        "${NGTCP2_INCLUDE_DIR}"
        "${QUICTLS_INCLUDE_DIR}"
    )
    target_link_libraries(clv_netcore PRIVATE ngtcp2_crypto_quictls)
    add_dependencies(clv_netcore ngtcp2_build)
endif()

# Add alias
add_library(clv::netcore ALIAS clv_netcore)

# QUIC HTTP/3 demo server target used by interop adapter images
if(USING_QUIC_TLS)
    find_package(Threads REQUIRED)

    add_executable(quic_simple_server demos/quic_simple_server.cpp)
    target_include_directories(quic_simple_server PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/src/"
        "${CMAKE_CURRENT_SOURCE_DIR}/../Core/src"
        "${CMAKE_CURRENT_SOURCE_DIR}/../SslHelp/src"
        "${CMAKE_CURRENT_SOURCE_DIR}/../extern/asio/asio/include"
        "${CMAKE_CURRENT_SOURCE_DIR}/../extern/nghttp3/lib"
        "${CMAKE_CURRENT_SOURCE_DIR}/../extern/nghttp3/lib/includes"
        "${CMAKE_BINARY_DIR}/clv-base/extern/nghttp3/lib/includes"
        "${NGTCP2_INCLUDE_DIR}"
        "${QUICTLS_INCLUDE_DIR}"
    )
    target_compile_definitions(quic_simple_server PRIVATE
        ASIO_STANDALONE
        ASIO_NO_DEPRECATED
        CLV_HAS_QUIC_TLS=1
    )
    target_link_libraries(quic_simple_server PRIVATE
        clv::netcore
        clv::sslhelp
        clv::core
        nlohmann_json::nlohmann_json
        quictls_ssl
        quictls_crypto
        nghttp3_static
        ngtcp2_crypto_quictls
        Threads::Threads
        spdlog::spdlog
    )
    add_dependencies(quic_simple_server ngtcp2_build)
    if(UNIX)
        target_link_libraries(quic_simple_server PRIVATE ${CMAKE_DL_LIBS})
    endif()
    apply_asan_flags(quic_simple_server)
endif()

# Tests (simplified - only if BUILD_TESTING is ON)
if(BUILD_TESTING)
    find_package(Threads REQUIRED)

    # quictls paths (for QUIC TLS support)
    set(QUICTLS_INCLUDE_DIR "${CMAKE_BINARY_DIR}/quictls/include")

    # ============================================================================
    # test_netcore — OpenSSL-based tests (no QUIC crypto)
    # ============================================================================
    add_executable(test_netcore)
    target_sources(test_netcore PRIVATE
        tests/stun_client_tests.cpp
        tests/stun_utils_tests.cpp
        tests/HttpClientServer_tests.cpp
        tests/micro_tls_tests.cpp
        tests/micro_udp_server_tests.cpp
        tests/byte_packer_tests.cpp
        tests/HttpRequest_tests.cpp
        tests/HttpResponse_tests.cpp
        tests/HttpProto_tests.cpp
        tests/HttpStaticRouter_tests.cpp
        tests/nla_helpers_tests.cpp
        tests/ipv6_utils_tests.cpp
        tests/static_file_resolver_tests.cpp
        tests/AsanVerification_tests.cpp
    )
    target_include_directories(test_netcore PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/src/"
        "${CMAKE_CURRENT_SOURCE_DIR}/../Core/src"
        "${CMAKE_CURRENT_SOURCE_DIR}/../SslHelp/src"
        "${CMAKE_CURRENT_SOURCE_DIR}/../extern/asio/asio/include"
    )
    target_compile_definitions(test_netcore PRIVATE
        ASIO_STANDALONE
        ASIO_NO_DEPRECATED
    )
    target_link_libraries(test_netcore
        GTest::gtest_main
        GTest::gmock
        OpenSSL::SSL
        OpenSSL::Crypto
        nlohmann_json::nlohmann_json
        Threads::Threads
        spdlog::spdlog
    )
    if(UNIX)
        target_link_libraries(test_netcore ${CMAKE_DL_LIBS})
    endif()
    apply_asan_flags(test_netcore)

    # Copy SSL certs and keys for tests
    set(netcore_test_data
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/data/cert.pem
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/data/key.pem
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/data/dh2048.pem
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/data/pvtkey.pem
    )
    foreach(df ${netcore_test_data})
        add_custom_command(TARGET test_netcore POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy ${df} $<TARGET_FILE_DIR:test_netcore>
        )
    endforeach()

    # Copy static test files for HttpStaticRouter tests
    add_custom_command(TARGET test_netcore POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_directory
            ${CMAKE_CURRENT_SOURCE_DIR}/test_static
            $<TARGET_FILE_DIR:test_netcore>/test_static
    )

    include(GoogleTest)
    gtest_discover_tests(test_netcore
        WORKING_DIRECTORY $<TARGET_FILE_DIR:test_netcore>
    )

    # ============================================================================
    # test_netcore_quic — QUIC/quictls-based tests (only when quictls is built)
    # ============================================================================
    if(USING_QUIC_TLS)
    add_executable(test_netcore_quic)
    target_sources(test_netcore_quic PRIVATE
        # clv::quic (ngtcp2) tests.
        tests/quic_endpoint_smoke_tests.cpp
        tests/quic_tls_context_tests.cpp
        tests/quic_connection_tests.cpp
        tests/quic_tls_verify_tests.cpp
    )
    target_include_directories(test_netcore_quic PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/src/"
        "${CMAKE_CURRENT_SOURCE_DIR}/../Core/src"
        "${CMAKE_CURRENT_SOURCE_DIR}/../SslHelp/src"
        "${CMAKE_CURRENT_SOURCE_DIR}/../extern/asio/asio/include"
        "${CMAKE_CURRENT_SOURCE_DIR}/../extern/nghttp3/lib"
        "${CMAKE_CURRENT_SOURCE_DIR}/../extern/nghttp3/lib/includes"
        "${CMAKE_BINARY_DIR}/clv-base/extern/nghttp3/lib/includes"
        "${QUICTLS_INCLUDE_DIR}"
    )
    target_compile_definitions(test_netcore_quic PRIVATE
        ASIO_STANDALONE
        ASIO_NO_DEPRECATED
        CLV_HAS_QUIC_TLS=1
    )
    target_link_libraries(test_netcore_quic
        GTest::gtest_main
        GTest::gmock
        nlohmann_json::nlohmann_json
        quictls_ssl
        quictls_crypto
        nghttp3_static
        Threads::Threads
        spdlog::spdlog
        # quic2 (ngtcp2) Phase 1: pulls in clv::quic::Endpoint and ngtcp2.
        clv_netcore
        ngtcp2_crypto_quictls
    )
    if(UNIX)
        target_link_libraries(test_netcore_quic ${CMAKE_DL_LIBS})
    endif()
    apply_asan_flags(test_netcore_quic)

    # Copy SSL certs for QUIC tests
    foreach(df ${netcore_test_data})
        add_custom_command(TARGET test_netcore_quic POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy ${df} $<TARGET_FILE_DIR:test_netcore_quic>
        )
    endforeach()

    gtest_discover_tests(test_netcore_quic
        WORKING_DIRECTORY $<TARGET_FILE_DIR:test_netcore_quic>
    )
    endif() # USING_QUIC_TLS
endif()
