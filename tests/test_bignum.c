/*
 * test_bignum.c — Unit tests for the BigNum (512-bit) arithmetic layer
 *
 * Covers:
 *   bn_is_zero, bn_cmp, bn_add, bn_sub,
 *   bn_divmod, bn_mulmod (large values),
 *   bn_from_bytes_be / bn_to_bytes_be round-trip,
 *   bn_from_hex
 *
 * Each function that was previously untested (or only tested via a trivial
 * proxy) now has targeted, isolated tests with known-answer verification.
 */

#include "../src/main.c"
#include "test_framework.h"

/* -------------------------------------------------------------------------
 * Helpers
 * ---------------------------------------------------------------------- */

/* Build a BN from two 32-bit limbs (rest zero). */
static BN make_bn2(u32 lo, u32 hi) {
    BN r; bn_zero(&r); r.d[0] = lo; r.d[1] = hi; return r;
}

/* Return 1 if BN equals a single 32-bit value (all upper limbs zero). */
static int bn_eq32(const BN *a, u32 v) {
    if (a->d[0] != v) return 0;
    for (int i = 1; i < BN_LIMBS; i++) if (a->d[i]) return 0;
    return 1;
}

/* =========================================================================
 * bn_is_zero
 * ========================================================================= */

static void test_is_zero_on_zero_bignum(void) {
    BN a; bn_zero(&a);
    ASSERT_EQ(bn_is_zero(&a), 1);
}

static void test_is_zero_on_nonzero_low_limb(void) {
    BN a; bn_zero(&a); a.d[0] = 1;
    ASSERT_EQ(bn_is_zero(&a), 0);
}

static void test_is_zero_on_nonzero_high_limb(void) {
    BN a; bn_zero(&a); a.d[BN_LIMBS - 1] = 0xdeadbeef;
    ASSERT_EQ(bn_is_zero(&a), 0);
}

static void test_is_zero_after_set32(void) {
    BN a; bn_set32(&a, 0);
    ASSERT_EQ(bn_is_zero(&a), 1);
    bn_set32(&a, 7);
    ASSERT_EQ(bn_is_zero(&a), 0);
}

/* =========================================================================
 * bn_cmp
 * ========================================================================= */

static void test_cmp_equal(void) {
    BN a, b; bn_set32(&a, 42); bn_set32(&b, 42);
    ASSERT_EQ(bn_cmp(&a, &b), 0);
}

static void test_cmp_less(void) {
    BN a, b; bn_set32(&a, 5); bn_set32(&b, 10);
    ASSERT_EQ(bn_cmp(&a, &b), -1);
}

static void test_cmp_greater(void) {
    BN a, b; bn_set32(&a, 100); bn_set32(&b, 3);
    ASSERT_EQ(bn_cmp(&a, &b), 1);
}

static void test_cmp_differs_in_high_limb(void) {
    /* a has a non-zero high limb; b has the same low limb but zero high limb */
    BN a = make_bn2(0, 0); a.d[BN_LIMBS - 1] = 1;
    BN b; bn_zero(&b); b.d[0] = 0xffffffff;
    /* a has a set bit at limb 15, b only has bits in limb 0 — a > b */
    ASSERT_EQ(bn_cmp(&a, &b), 1);
}

static void test_cmp_zero_vs_zero(void) {
    BN a, b; bn_zero(&a); bn_zero(&b);
    ASSERT_EQ(bn_cmp(&a, &b), 0);
}

/* =========================================================================
 * bn_add
 * ========================================================================= */

static void test_add_simple(void) {
    BN a, b, r; bn_set32(&a, 7); bn_set32(&b, 3);
    u32 carry = bn_add(&r, &a, &b);
    ASSERT_EQ(carry, 0);
    ASSERT_EQ(r.d[0], 10u);
}

static void test_add_carry_into_second_limb(void) {
    /* 0xFFFFFFFF + 1 = 0x1_00000000 */
    BN a, b, r;
    bn_set32(&a, 0xFFFFFFFF); bn_set32(&b, 1);
    u32 carry = bn_add(&r, &a, &b);
    ASSERT_EQ(carry, 0);
    ASSERT_EQ(r.d[0], 0u);
    ASSERT_EQ(r.d[1], 1u);
}

static void test_add_carry_propagates_through_limbs(void) {
    /* All-ones + 1 = overflow (carry out, result = 0) */
    BN a, b, r;
    memset(a.d, 0xFF, sizeof a.d); /* a = 2^512 - 1 */
    bn_set32(&b, 1);
    u32 carry = bn_add(&r, &a, &b);
    ASSERT_EQ(carry, 1);
    ASSERT_EQ(bn_is_zero(&r), 1);
}

static void test_add_zero_identity(void) {
    BN a, zero, r; bn_set32(&a, 999); bn_zero(&zero);
    bn_add(&r, &a, &zero);
    ASSERT_EQ(bn_cmp(&r, &a), 0);
}

/* =========================================================================
 * bn_sub
 * ========================================================================= */

static void test_sub_simple(void) {
    BN a, b, r; bn_set32(&a, 10); bn_set32(&b, 3);
    bn_sub(&r, &a, &b);
    ASSERT_EQ(r.d[0], 7u);
    ASSERT_EQ(bn_is_zero(&r), 0);
}

static void test_sub_borrow_from_second_limb(void) {
    /* 0x1_00000000 - 1 = 0xFFFFFFFF */
    BN a = make_bn2(0, 1); /* limb[0]=0, limb[1]=1 => value = 2^32 */
    BN b; bn_set32(&b, 1);
    BN r; bn_sub(&r, &a, &b);
    ASSERT_EQ(r.d[0], 0xFFFFFFFFu);
    ASSERT_EQ(r.d[1], 0u);
}

static void test_sub_equal_gives_zero(void) {
    BN a, r; bn_set32(&a, 42);
    bn_sub(&r, &a, &a);
    ASSERT_EQ(bn_is_zero(&r), 1);
}

static void test_sub_zero_identity(void) {
    BN a, zero, r; bn_set32(&a, 1234); bn_zero(&zero);
    bn_sub(&r, &a, &zero);
    ASSERT_EQ(bn_cmp(&r, &a), 0);
}

/* =========================================================================
 * bn_divmod
 * ========================================================================= */

static void test_divmod_basic(void) {
    /* 17 / 5 = 3 remainder 2 */
    BN a, b, q, rem;
    bn_set32(&a, 17); bn_set32(&b, 5);
    bn_divmod(&q, &rem, &a, &b);
    ASSERT(bn_eq32(&q, 3));
    ASSERT(bn_eq32(&rem, 2));
}

static void test_divmod_exact(void) {
    /* 100 / 25 = 4, remainder 0 */
    BN a, b, q, rem;
    bn_set32(&a, 100); bn_set32(&b, 25);
    bn_divmod(&q, &rem, &a, &b);
    ASSERT(bn_eq32(&q, 4));
    ASSERT_EQ(bn_is_zero(&rem), 1);
}

static void test_divmod_dividend_less_than_divisor(void) {
    /* 3 / 17 = 0, remainder 3 */
    BN a, b, q, rem;
    bn_set32(&a, 3); bn_set32(&b, 17);
    bn_divmod(&q, &rem, &a, &b);
    ASSERT_EQ(bn_is_zero(&q), 1);
    ASSERT(bn_eq32(&rem, 3));
}

static void test_divmod_large_values(void) {
    /* 2^64 / 2^32 = 2^32, remainder 0 */
    BN a, b, q, rem;
    bn_zero(&a); a.d[2] = 1;  /* a = 2^64 */
    bn_zero(&b); b.d[1] = 1;  /* b = 2^32 */
    bn_divmod(&q, &rem, &a, &b);
    /* q should be 2^32 */
    ASSERT_EQ(q.d[0], 0u);
    ASSERT_EQ(q.d[1], 1u);
    for (int i = 2; i < BN_LIMBS; i++) ASSERT_EQ(q.d[i], 0u);
    ASSERT_EQ(bn_is_zero(&rem), 1);
}

/* =========================================================================
 * bn_mulmod — large values (beyond the trivial 17*19 mod 7 existing test)
 * ========================================================================= */

static void test_mulmod_medium_values(void) {
    /* (2^32+1)^2 mod (2^64+1) = 2^33
     *
     * Proof: (2^32+1)^2 = 2^64 + 2*2^32 + 1
     *        2^64 ≡ -1 (mod 2^64+1)
     *        => -1 + 2^33 + 1 = 2^33
     */
    BN a, m, r;
    bn_zero(&a); a.d[0] = 1; a.d[1] = 1;  /* 2^32 + 1 */
    bn_zero(&m); m.d[0] = 1; m.d[2] = 1;  /* 2^64 + 1 */
    bn_mulmod(&r, &a, &a, &m);
    /* result = 2^33, represented as d[0]=0, d[1]=2 */
    ASSERT_EQ(r.d[0], 0u);
    ASSERT_EQ(r.d[1], 2u);
    for (int i = 2; i < BN_LIMBS; i++) ASSERT_EQ(r.d[i], 0u);
}

static void test_mulmod_large_256bit_values(void) {
    /* a = 2^256, m = 2^256+1
     * a * a mod m: 2^256 ≡ -1 (mod 2^256+1) so a^2 ≡ 1
     *
     * Limb 8 corresponds to 2^(8*32)=2^256.
     * a = BN with d[8]=1, all others 0.
     * m = BN with d[0]=1, d[8]=1.
     */
    BN a, m, r;
    bn_zero(&a); a.d[8] = 1;             /* 2^256 */
    bn_zero(&m); m.d[0] = 1; m.d[8] = 1; /* 2^256 + 1 */
    bn_mulmod(&r, &a, &a, &m);
    ASSERT(bn_eq32(&r, 1));
}

static void test_mulmod_by_zero(void) {
    BN a, zero, m, r;
    bn_set32(&a, 12345); bn_zero(&zero); bn_set32(&m, 9999);
    bn_mulmod(&r, &a, &zero, &m);
    ASSERT_EQ(bn_is_zero(&r), 1);
}

static void test_mulmod_by_one(void) {
    BN a, one, m, r;
    bn_set32(&a, 77); bn_set32(&one, 1); bn_set32(&m, 100);
    bn_mulmod(&r, &a, &one, &m);
    ASSERT(bn_eq32(&r, 77));
}

/* =========================================================================
 * Serialisation: bn_from_bytes_be / bn_to_bytes_be round-trip
 * ========================================================================= */

static void test_bytes_roundtrip_small_value(void) {
    /* Encode the value 0x0102030405060708090a0b0c0d0e0f10 as 16 bytes */
    uint8_t orig[16] = {
        0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
        0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10
    };
    BN a;
    bn_from_bytes_be(&a, orig, 16);
    uint8_t out[16] = {0};
    bn_to_bytes_be(&a, out, 16);
    ASSERT_MEM_EQ(out, orig, 16);
}

static void test_bytes_roundtrip_64_bytes(void) {
    /* Full 64-byte (512-bit) round-trip with a pseudo-random-looking buffer */
    uint8_t orig[64];
    for (int i = 0; i < 64; i++) orig[i] = (uint8_t)(i * 7 + 3);
    BN a;
    bn_from_bytes_be(&a, orig, 64);
    uint8_t out[64] = {0};
    bn_to_bytes_be(&a, out, 64);
    ASSERT_MEM_EQ(out, orig, 64);
}

static void test_bytes_roundtrip_all_zeros(void) {
    uint8_t orig[64]; memset(orig, 0, 64);
    BN a; bn_from_bytes_be(&a, orig, 64);
    uint8_t out[64]; memset(out, 0xFF, 64);
    bn_to_bytes_be(&a, out, 64);
    ASSERT_MEM_EQ(out, orig, 64);
}

static void test_bytes_roundtrip_all_ones(void) {
    uint8_t orig[64]; memset(orig, 0xFF, 64);
    BN a; bn_from_bytes_be(&a, orig, 64);
    uint8_t out[64] = {0};
    bn_to_bytes_be(&a, out, 64);
    ASSERT_MEM_EQ(out, orig, 64);
}

static void test_bytes_known_value(void) {
    /* value = 1 (last byte = 1, rest zero) stored big-endian in 8 bytes */
    uint8_t orig[8] = {0,0,0,0,0,0,0,1};
    BN a; bn_from_bytes_be(&a, orig, 8);
    ASSERT(bn_eq32(&a, 1));
    uint8_t out[8] = {0};
    bn_to_bytes_be(&a, out, 8);
    ASSERT_MEM_EQ(out, orig, 8);
}

/* =========================================================================
 * bn_from_hex
 * ========================================================================= */

static void test_from_hex_single_digit(void) {
    BN a; bn_from_hex(&a, "f");
    ASSERT(bn_eq32(&a, 15));
}

static void test_from_hex_one_full_limb(void) {
    BN a; bn_from_hex(&a, "deadbeef");
    ASSERT_EQ(a.d[0], 0xdeadbeef);
    for (int i = 1; i < BN_LIMBS; i++) ASSERT_EQ(a.d[i], 0u);
}

static void test_from_hex_two_limbs(void) {
    /* "0000000100000002" => d[1]=1, d[0]=2 */
    BN a; bn_from_hex(&a, "0000000100000002");
    ASSERT_EQ(a.d[0], 2u);
    ASSERT_EQ(a.d[1], 1u);
}

static void test_from_hex_zero(void) {
    BN a; bn_from_hex(&a, "0");
    ASSERT_EQ(bn_is_zero(&a), 1);
}

static void test_from_hex_known_rsa_d(void) {
    /* The known RSA private exponent from test_modinv — verify we can load
     * it and that it is non-zero and has the expected low limb. */
    const char *known_d =
        "8d0cb321db1617923b34c49c490ad825"
        "7a2e5047f1ee90eec8838665aee80ffd"
        "ceb96591ae76458f600737698def2094"
        "df8ef4ef453ad3ef7fadd0828b752581";
    BN d; bn_from_hex(&d, known_d);
    ASSERT_EQ(bn_is_zero(&d), 0);
    /* Low 32 bits: last 8 hex chars = "8b752581" */
    ASSERT_EQ(d.d[0], 0x8b752581u);
}

/* =========================================================================
 * Main
 * ========================================================================= */

int main(void) {
    printf("=== BigNum arithmetic tests ===\n\n");

    printf("bn_is_zero:\n");
    RUN_TEST(test_is_zero_on_zero_bignum);
    RUN_TEST(test_is_zero_on_nonzero_low_limb);
    RUN_TEST(test_is_zero_on_nonzero_high_limb);
    RUN_TEST(test_is_zero_after_set32);

    printf("\nbn_cmp:\n");
    RUN_TEST(test_cmp_equal);
    RUN_TEST(test_cmp_less);
    RUN_TEST(test_cmp_greater);
    RUN_TEST(test_cmp_differs_in_high_limb);
    RUN_TEST(test_cmp_zero_vs_zero);

    printf("\nbn_add:\n");
    RUN_TEST(test_add_simple);
    RUN_TEST(test_add_carry_into_second_limb);
    RUN_TEST(test_add_carry_propagates_through_limbs);
    RUN_TEST(test_add_zero_identity);

    printf("\nbn_sub:\n");
    RUN_TEST(test_sub_simple);
    RUN_TEST(test_sub_borrow_from_second_limb);
    RUN_TEST(test_sub_equal_gives_zero);
    RUN_TEST(test_sub_zero_identity);

    printf("\nbn_divmod:\n");
    RUN_TEST(test_divmod_basic);
    RUN_TEST(test_divmod_exact);
    RUN_TEST(test_divmod_dividend_less_than_divisor);
    RUN_TEST(test_divmod_large_values);

    printf("\nbn_mulmod (large values):\n");
    RUN_TEST(test_mulmod_medium_values);
    RUN_TEST(test_mulmod_large_256bit_values);
    RUN_TEST(test_mulmod_by_zero);
    RUN_TEST(test_mulmod_by_one);

    printf("\nbn_from_bytes_be / bn_to_bytes_be:\n");
    RUN_TEST(test_bytes_roundtrip_small_value);
    RUN_TEST(test_bytes_roundtrip_64_bytes);
    RUN_TEST(test_bytes_roundtrip_all_zeros);
    RUN_TEST(test_bytes_roundtrip_all_ones);
    RUN_TEST(test_bytes_known_value);

    printf("\nbn_from_hex:\n");
    RUN_TEST(test_from_hex_single_digit);
    RUN_TEST(test_from_hex_one_full_limb);
    RUN_TEST(test_from_hex_two_limbs);
    RUN_TEST(test_from_hex_zero);
    RUN_TEST(test_from_hex_known_rsa_d);

    PRINT_SUMMARY();
}
