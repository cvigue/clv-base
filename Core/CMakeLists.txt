# Copyright (c) 2023- Charlie Vigue. All rights reserved.

# Core library (header-only interface library)
add_library(clv_core INTERFACE)
target_include_directories(clv_core
    INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>
        $<INSTALL_INTERFACE:include>
)
target_link_libraries(clv_core
    INTERFACE
        nlohmann_json::nlohmann_json
        pthread
)

# Add alias
add_library(clv::core ALIAS clv_core)

# Tests
if(BUILD_TESTING)
    project(test_core VERSION 0.1.0)

    add_executable(test_core)
    target_sources(test_core PRIVATE
        tests/array_deque_tests.cpp
        tests/auto_thread_tests.cpp
        tests/cbmi_tests.cpp
        tests/char_util_tests.cpp
        tests/ci_string_tests.cpp
        tests/config_tests.cpp
        tests/config_json_parser_tests.cpp
        tests/event_tests.cpp
        tests/hash_util_tests.cpp
        tests/intrinsic_type_tests.cpp
        tests/is_callable_tests.cpp
        tests/make_pooled_st_tests.cpp
        tests/make_pooled_tests.cpp
        tests/mutex_type_tests.cpp
        tests/not_null_tests.cpp
        tests/numeric_util_tests.cpp
        tests/optional_ref_tests.cpp
        tests/options_tests.cpp
        tests/pid_controller_tests.cpp
        tests/scope_guard_tests.cpp
        tests/st_alloc_pool_tests.cpp
        tests/timer_tests.cpp
        tests/AsanVerification_tests.cpp
    )

    target_include_directories(test_core PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/src/"
    )

    target_link_libraries(test_core
        GTest::gtest_main
        clv::core
    )

    # Copy test data files to build directory
    set(test_data
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/data/test_config.json
    )

    foreach(df ${test_data})
        add_custom_command(TARGET test_core POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy ${df} $<TARGET_FILE_DIR:test_core>
        )
    endforeach()

    # Apply ASAN flags if enabled
    apply_asan_flags(test_core)

    # Register the test
    add_test(NAME CoreTests COMMAND test_core)
endif()
