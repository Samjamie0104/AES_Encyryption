/*
 * test_framework.h — Minimal unit-test helper macros
 *
 * Usage:
 *   #include "test_framework.h"
 *
 *   static void test_something(void) {
 *       ASSERT_EQ(1 + 1, 2);
 *       ASSERT(ptr != NULL);
 *       ASSERT_MEM_EQ(buf_a, buf_b, 16);
 *   }
 *
 *   int main(void) {
 *       RUN_TEST(test_something);
 *       PRINT_SUMMARY();
 *   }
 */

#ifndef TEST_FRAMEWORK_H
#define TEST_FRAMEWORK_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int _tf_pass = 0;
static int _tf_fail = 0;
/* Name of the currently-running test (set by RUN_TEST). */
static const char *_tf_current = "(unknown)";

#define ASSERT(cond)                                                    \
    do {                                                                \
        if (cond) {                                                     \
            _tf_pass++;                                                 \
        } else {                                                        \
            fprintf(stderr, "  ASSERT failed [%s:%d]: %s\n",          \
                    __FILE__, __LINE__, #cond);                         \
            _tf_fail++;                                                 \
        }                                                               \
    } while (0)

#define ASSERT_EQ(a, b)                                                 \
    do {                                                                \
        long long _a = (long long)(a);                                  \
        long long _b = (long long)(b);                                  \
        if (_a == _b) {                                                 \
            _tf_pass++;                                                 \
        } else {                                                        \
            fprintf(stderr,                                             \
                    "  ASSERT_EQ failed [%s:%d]: %s=%lld, %s=%lld\n", \
                    __FILE__, __LINE__, #a, _a, #b, _b);               \
            _tf_fail++;                                                 \
        }                                                               \
    } while (0)

#define ASSERT_MEM_EQ(a, b, n)                                          \
    do {                                                                \
        if (memcmp((a), (b), (n)) == 0) {                              \
            _tf_pass++;                                                 \
        } else {                                                        \
            fprintf(stderr,                                             \
                    "  ASSERT_MEM_EQ failed [%s:%d]: %s vs %s "        \
                    "(%zu bytes differ)\n",                             \
                    __FILE__, __LINE__, #a, #b, (size_t)(n));          \
            /* Print both buffers as hex for easy diagnosis */          \
            const unsigned char *_pa = (const unsigned char *)(a);     \
            const unsigned char *_pb = (const unsigned char *)(b);     \
            fprintf(stderr, "    got:      ");                          \
            for (size_t _i = 0; _i < (size_t)(n); _i++)               \
                fprintf(stderr, "%02x", _pa[_i]);                      \
            fprintf(stderr, "\n    expected: ");                        \
            for (size_t _i = 0; _i < (size_t)(n); _i++)               \
                fprintf(stderr, "%02x", _pb[_i]);                      \
            fprintf(stderr, "\n");                                      \
            _tf_fail++;                                                 \
        }                                                               \
    } while (0)

/* Run a test function, print PASS/FAIL on the same line. */
#define RUN_TEST(fn)                                                    \
    do {                                                                \
        _tf_current = #fn;                                              \
        int _before = _tf_fail;                                         \
        printf("  %-55s", #fn "...");                                   \
        fflush(stdout);                                                 \
        fn();                                                           \
        printf("%s\n", (_tf_fail == _before) ? "PASS" : "FAIL");       \
    } while (0)

/* Print summary and return a non-zero exit code if any test failed. */
#define PRINT_SUMMARY()                                                 \
    do {                                                                \
        printf("\n%d assertion(s) passed, %d failed.\n",               \
               _tf_pass, _tf_fail);                                     \
        return _tf_fail > 0 ? 1 : 0;                                   \
    } while (0)

#endif /* TEST_FRAMEWORK_H */
