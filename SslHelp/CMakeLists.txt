# Copyright (c) 2023- Charlie Vigue. All rights reserved.

find_package(OpenSSL REQUIRED)

# SslHelp library (header-only interface library)
add_library(clv_sslhelp INTERFACE)
target_include_directories(clv_sslhelp
    INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>
        $<INSTALL_INTERFACE:include>
)
target_link_libraries(clv_sslhelp
    INTERFACE
        OpenSSL::SSL
        OpenSSL::Crypto
        clv::core
)

# Add alias
add_library(clv::sslhelp ALIAS clv_sslhelp)

# Tests
if(BUILD_TESTING)
    project(test_sslhelp VERSION 0.1.0)

    set(test_data
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/data/cert.pem
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/data/dh2048.pem
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/data/key.pem
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/data/pvtkey.pem
    )

    add_executable(test_sslhelp)
    target_sources(test_sslhelp PRIVATE
        tests/AsanVerification_tests.cpp
        tests/HelpSslAsn1_tests.cpp
        tests/HelpSslBase_tests.cpp
        tests/HelpSslBigNum_tests.cpp
        tests/HelpSslBioMethod_tests.cpp
        tests/HelpSslBio_tests.cpp
        tests/HelpSslCipher_tests.cpp
        tests/HelpSslContext_tests.cpp
        tests/HelpSslCustomBio_tests.cpp
        tests/HelpSslEvpPkeyCtx_tests.cpp
        tests/HelpSslEvpPkey_tests.cpp
        tests/HelpSslHandshakeContext_tests.cpp
        tests/HelpSslHmac_tests.cpp
        tests/HelpSslMemBio_tests.cpp
        tests/HelpSslStreamCipher_tests.cpp
        tests/HelpSslTrustStore_tests.cpp
        tests/HelpSslVerifyHelper_tests.cpp
        tests/HelpSslX509Name_tests.cpp
        tests/HelpSslX509_tests.cpp
        tests/trust_store_tests.cpp
    )

    target_include_directories(test_sslhelp PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/src/"
    )

    target_link_libraries(test_sslhelp
        GTest::gtest_main
        clv::sslhelp
    )

    foreach(df ${test_data})
        add_custom_command(TARGET test_sslhelp POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy ${df} $<TARGET_FILE_DIR:test_sslhelp>
        )
    endforeach()

    add_test(NAME SslHelpTests COMMAND test_sslhelp)
    apply_asan_flags(test_sslhelp)
endif()
