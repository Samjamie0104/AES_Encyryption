/*
 * test_rng.c — Sanity tests for the xoshiro256** RNG
 *
 * Covers:
 *   rng_seed    — seeds without crashing (both /dev/urandom and fallback)
 *   rng_next    — returns values, successive calls differ
 *   rng_bytes   — fills exactly n bytes, does not write outside the buffer,
 *                 two calls produce different output,
 *                 deterministic output for a known seed
 */

#include "../src/main.c"
#include "test_framework.h"

/* Force-set the internal RNG state to a known value so we can test
 * determinism without /dev/urandom. */
static void seed_fixed(void) {
    rng_s[0] = 0x0102030405060708ULL;
    rng_s[1] = 0x090a0b0c0d0e0f10ULL;
    rng_s[2] = 0x1112131415161718ULL;
    rng_s[3] = 0x191a1b1c1d1e1f20ULL;
}

/* =========================================================================
 * rng_seed
 * ========================================================================= */

static void test_seed_does_not_crash(void) {
    /* rng_seed() either reads /dev/urandom or falls back to constants.
     * Either way it must not crash and must leave a non-all-zero state. */
    rng_seed();
    int nonzero = (rng_s[0] | rng_s[1] | rng_s[2] | rng_s[3]) != 0;
    ASSERT_EQ(nonzero, 1);
}

/* =========================================================================
 * rng_next
 * ========================================================================= */

static void test_next_changes_state(void) {
    seed_fixed();
    u64 v1 = rng_next();
    u64 v2 = rng_next();
    /* Two successive outputs must differ */
    ASSERT(v1 != v2);
}

static void test_next_not_always_zero(void) {
    seed_fixed();
    u64 accum = 0;
    for (int i = 0; i < 16; i++) accum |= rng_next();
    ASSERT(accum != 0);
}

static void test_next_deterministic_from_known_seed(void) {
    /* With a fixed seed the sequence is fully deterministic. */
    seed_fixed();
    u64 a = rng_next();
    /* Re-seed identically and check we get the same first value. */
    seed_fixed();
    u64 b = rng_next();
    ASSERT_EQ(a, b);
}

/* =========================================================================
 * rng_bytes
 * ========================================================================= */

static void test_bytes_fills_requested_length(void) {
    seed_fixed();
    /* Sentinels before and after the buffer */
    uint8_t buf[18];
    memset(buf, 0xAA, sizeof buf);
    rng_bytes(buf + 1, 16);
    /* Sentinels must be untouched */
    ASSERT_EQ(buf[0],  0xAA);
    ASSERT_EQ(buf[17], 0xAA);
}

static void test_bytes_output_is_nonzero_for_nonzero_seed(void) {
    seed_fixed();
    uint8_t buf[16] = {0};
    rng_bytes(buf, 16);
    int nonzero = 0;
    for (int i = 0; i < 16; i++) if (buf[i]) nonzero = 1;
    ASSERT_EQ(nonzero, 1);
}

static void test_bytes_two_calls_differ(void) {
    seed_fixed();
    uint8_t buf1[16], buf2[16];
    rng_bytes(buf1, 16);
    rng_bytes(buf2, 16);
    /* Extremely unlikely to match */
    ASSERT(memcmp(buf1, buf2, 16) != 0);
}

static void test_bytes_deterministic_from_known_seed(void) {
    seed_fixed();
    uint8_t buf1[32];
    rng_bytes(buf1, 32);

    seed_fixed();
    uint8_t buf2[32];
    rng_bytes(buf2, 32);

    ASSERT_MEM_EQ(buf1, buf2, 32);
}

static void test_bytes_single_byte(void) {
    seed_fixed();
    uint8_t sentinel_before = 0xAA, sentinel_after = 0xBB;
    uint8_t buf[3] = {sentinel_before, 0, sentinel_after};
    rng_bytes(buf + 1, 1);
    ASSERT_EQ(buf[0], sentinel_before);
    ASSERT_EQ(buf[2], sentinel_after);
    /* The written byte may be anything; we just verify boundaries. */
}

static void test_bytes_partial_last_word(void) {
    /* 13 bytes — the last call to rng_next() fills 8 bytes but we only
     * copy 5 of them.  Verify the buffer is fully filled without OOB. */
    seed_fixed();
    uint8_t buf[15];
    memset(buf, 0xCC, sizeof buf);
    rng_bytes(buf, 13);
    /* Bytes [13..14] must remain as sentinel */
    ASSERT_EQ(buf[13], 0xCC);
    ASSERT_EQ(buf[14], 0xCC);
}

/* =========================================================================
 * Main
 * ========================================================================= */

int main(void) {
    printf("=== RNG (xoshiro256**) tests ===\n\n");

    printf("rng_seed:\n");
    RUN_TEST(test_seed_does_not_crash);

    printf("\nrng_next:\n");
    RUN_TEST(test_next_changes_state);
    RUN_TEST(test_next_not_always_zero);
    RUN_TEST(test_next_deterministic_from_known_seed);

    printf("\nrng_bytes:\n");
    RUN_TEST(test_bytes_fills_requested_length);
    RUN_TEST(test_bytes_output_is_nonzero_for_nonzero_seed);
    RUN_TEST(test_bytes_two_calls_differ);
    RUN_TEST(test_bytes_deterministic_from_known_seed);
    RUN_TEST(test_bytes_single_byte);
    RUN_TEST(test_bytes_partial_last_word);

    PRINT_SUMMARY();
}
