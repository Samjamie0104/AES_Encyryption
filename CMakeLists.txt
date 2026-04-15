cmake_minimum_required(VERSION 3.10)
project(AES_Encryption C)

set(CMAKE_C_STANDARD 99)

# ---------------------------------------------------------------------------
# Main executable
# ---------------------------------------------------------------------------
add_executable(aes_encryption src/main.c)

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
enable_testing()

# Each test file #includes src/main.c directly (with HYBRID_CRYPTO_TESTS
# defined to suppress main()) so no separate library target is needed.

set(TEST_NAMES
    test_bignum
    test_aes_ops
    test_hybrid
    test_rng
    test_adversarial
    test_stress
)

foreach(TEST_NAME ${TEST_NAMES})
    add_executable(${TEST_NAME} tests/${TEST_NAME}.c)
    target_compile_definitions(${TEST_NAME} PRIVATE HYBRID_CRYPTO_TESTS)
    # Expose the tests/ directory so test files can #include "test_framework.h"
    target_include_directories(${TEST_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/tests)
    add_test(NAME ${TEST_NAME} COMMAND ${TEST_NAME})
endforeach()

# ---------------------------------------------------------------------------
# Optional: coverage build (enable with -DCOVERAGE=ON)
# ---------------------------------------------------------------------------
option(COVERAGE "Enable gcov/lcov coverage instrumentation" OFF)
if(COVERAGE)
    foreach(TARGET aes_encryption ${TEST_NAMES})
        target_compile_options(${TARGET} PRIVATE --coverage -O0 -g)
        target_link_options(${TARGET} PRIVATE --coverage)
    endforeach()
endif()
