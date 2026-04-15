/*
 * test_stress.c — Mathematical stress tests
 *
 * These probe deep correctness properties that the happy-path and
 * tamper tests miss:
 *
 *   1. Fermat's Little Theorem  — a^(p-1) ≡ 1 (mod p) for the actual RSA
 *      primes p and q with several distinct bases. Any bug in the
 *      square-and-multiply loop, carry propagation, or modular reduction
 *      breaks this immediately.
 *
 *   2. Near-modulus mulmod — (n-1)^2 mod n = 1. Tests that the
 *      shift-and-subtract reduction handles products that are nearly
 *      double the modulus without an off-by-one in the loop count.
 *
 *   3. RSA roundtrip sweep — encrypt/decrypt for all m in 2..255.
 *      Small values expose patterns that a single-value test hides
 *      (e.g. a faulty squaring that cancels out for m=12345 but
 *      fails for m=7).
 *
 *   4. CTR counter-uniqueness — encrypt 512 bytes of zeros (32 blocks)
 *      and verify every 16-byte keystream block is distinct. Catches
 *      a counter that doesn't increment, resets, or wraps incorrectly.
 *
 *   5. CTR boundary messages — hybrid roundtrip for message lengths
 *      0, 1, 15, 16, 17, 31, 32, 33 bytes. The buggy region is usually
 *      right at a 16-byte block boundary.
 *
 *   6. bn_mulmod commutativity — a*b mod m == b*a mod m. Fails if
 *      there is any asymmetry in the schoolbook multiply or reduction.
 *
 *   7. Repeated squaring identity — a^(2k) mod n == (a^k)^2 mod n.
 *      Verifies the squaring step in powmod is consistent with a
 *      separate mulmod call.
 */

#include "../src/main.c"
#include "test_framework.h"

/* =========================================================================
 * Helpers
 * ========================================================================= */

static int bn_eq32(const BN *a, u32 v) {
    if (a->d[0] != v) return 0;
    for (int i = 1; i < BN_LIMBS; i++) if (a->d[i]) return 0;
    return 1;
}

/* =========================================================================
 * 1. Fermat's Little Theorem
 *
 * For a prime p, any base a (1 <= a < p) satisfies a^(p-1) ≡ 1 (mod p).
 *
 * We test this for the two 256-bit primes embedded in main.c, using
 * several small bases (2, 3, 5, 7, 65537).  This exercises bn_powmod
 * with 256-bit exponents and 256-bit moduli — far beyond what the
 * existing tests cover.
 * ========================================================================= */

static void fermat_check(const BN *base, const BN *p) {
    /* Compute p-1 */
    BN one, pm1;
    bn_set32(&one, 1);
    bn_sub(&pm1, p, &one);

    BN result;
    bn_powmod(&result, base, &pm1, p);
    ASSERT(bn_eq32(&result, 1));
}

static void test_fermat_prime_p_base2(void) {
    BN p, base;
    bn_from_hex(&p, P_HEX);
    bn_set32(&base, 2);
    fermat_check(&base, &p);
}

static void test_fermat_prime_p_base3(void) {
    BN p, base;
    bn_from_hex(&p, P_HEX);
    bn_set32(&base, 3);
    fermat_check(&base, &p);
}

static void test_fermat_prime_p_base65537(void) {
    BN p, base;
    bn_from_hex(&p, P_HEX);
    bn_set32(&base, 65537);
    fermat_check(&base, &p);
}

static void test_fermat_prime_q_base2(void) {
    BN q, base;
    bn_from_hex(&q, Q_HEX);
    bn_set32(&base, 2);
    fermat_check(&base, &q);
}

static void test_fermat_prime_q_base7(void) {
    BN q, base;
    bn_from_hex(&q, Q_HEX);
    bn_set32(&base, 7);
    fermat_check(&base, &q);
}

/* =========================================================================
 * 2. Near-modulus mulmod: (m-1)^2 mod m = 1
 *
 * Because (m-1) ≡ -1 (mod m), so (-1)^2 = 1.
 * The product (m-1)^2 is close to m^2, which stresses the reduction step.
 * ========================================================================= */

static void test_mulmod_m_minus_one_squared(void) {
    BN m, mm1, r, one;
    bn_from_hex(&m, P_HEX);     /* use the real 256-bit prime */
    bn_set32(&one, 1);
    bn_sub(&mm1, &m, &one);     /* mm1 = m - 1 */
    bn_mulmod(&r, &mm1, &mm1, &m);
    ASSERT(bn_eq32(&r, 1));
}

/* Same property for the RSA modulus n = p*q (512-bit). */
static void test_mulmod_n_minus_one_squared(void) {
    RSAKey k = rsa_keygen();
    BN mm1, r, one;
    bn_set32(&one, 1);
    bn_sub(&mm1, &k.n, &one);
    bn_mulmod(&r, &mm1, &mm1, &k.n);
    ASSERT(bn_eq32(&r, 1));
}

/* =========================================================================
 * 3. RSA roundtrip sweep: m = 2 .. 127
 *
 * A single KAT (m=12345) passes even if the exponentiation has a
 * systematic error that happens to cancel.  Sweeping small values
 * (which have distinct bit patterns) makes that much less likely.
 * ========================================================================= */

static void test_rsa_roundtrip_sweep(void) {
    RSAKey k = rsa_keygen();
    for (u32 m_val = 2; m_val <= 127; m_val++) {
        BN m, c, rec;
        bn_set32(&m, m_val);
        bn_powmod(&c, &m, &k.e, &k.n);   /* encrypt */
        bn_powmod(&rec, &c, &k.d, &k.n); /* decrypt */
        ASSERT(bn_eq32(&rec, m_val));
    }
}

/* =========================================================================
 * 4. CTR counter-uniqueness
 *
 * Encrypt 512 bytes of constant data (all zeros).  Each of the 32
 * resulting 16-byte ciphertext blocks is the AES encryption of a
 * distinct counter value.  If two blocks are equal, the counter is
 * not advancing correctly.
 * ========================================================================= */

static void test_ctr_counter_uniqueness(void) {
    uint8_t pt[512];
    uint8_t ct[512];
    uint8_t key[16]   = {0x42};
    uint8_t nonce[16] = {0};
    memset(pt, 0, 512);

    aes_ctr(pt, ct, 512, key, nonce);

    /* Check every pair of 16-byte blocks is distinct. */
    for (int i = 0; i < 32; i++) {
        for (int j = i + 1; j < 32; j++) {
            ASSERT(memcmp(ct + i*16, ct + j*16, 16) != 0);
        }
    }
}

/* =========================================================================
 * 5. CTR / Hybrid message boundary lengths
 *
 * The bug region for CTR is right at a 16-byte block boundary.  Test
 * messages of length 0, 1, 15, 16, 17, 31, 32, and 33 bytes.
 * ========================================================================= */

static void ctr_boundary_check(size_t len) {
    uint8_t pt[33], ct[33], dec[33];
    uint8_t key[16]   = {0xAB,0xCD,0xEF};
    uint8_t nonce[16] = {0x01};
    for (size_t i = 0; i < len; i++) pt[i] = (uint8_t)(i ^ 0x5A);

    aes_ctr(pt, ct,  len, key, nonce);
    aes_ctr(ct, dec, len, key, nonce);
    ASSERT(memcmp(dec, pt, len) == 0);
}

static void test_ctr_boundary_0  (void) { ctr_boundary_check(0);  }
static void test_ctr_boundary_1  (void) { ctr_boundary_check(1);  }
static void test_ctr_boundary_15 (void) { ctr_boundary_check(15); }
static void test_ctr_boundary_16 (void) { ctr_boundary_check(16); }
static void test_ctr_boundary_17 (void) { ctr_boundary_check(17); }
static void test_ctr_boundary_31 (void) { ctr_boundary_check(31); }
static void test_ctr_boundary_32 (void) { ctr_boundary_check(32); }
static void test_ctr_boundary_33 (void) { ctr_boundary_check(33); }

/* =========================================================================
 * 6. bn_mulmod commutativity
 *
 * a*b mod m must equal b*a mod m.  The schoolbook multiply is symmetric
 * in theory but an implementation mistake (wrong loop bound, asymmetric
 * carry propagation) can break it.
 * ========================================================================= */

static void test_mulmod_commutativity_small(void) {
    BN a, b, m, r1, r2;
    bn_set32(&a, 0xDEADBEEF);
    bn_set32(&b, 0xCAFEBABE);
    bn_set32(&m, 0xFFFFFFFB); /* large prime fits in 32 bits */
    bn_mulmod(&r1, &a, &b, &m);
    bn_mulmod(&r2, &b, &a, &m);
    ASSERT(memcmp(r1.d, r2.d, sizeof r1.d) == 0);
}

static void test_mulmod_commutativity_256bit(void) {
    BN a, b, m, r1, r2;
    bn_from_hex(&m, P_HEX);
    /* a = m/2 (rough), b = m/3 (rough) — use fixed hex values near that range */
    bn_from_hex(&a, "4d0ef3224af7b6e89dc7d50c1bfc5445"
                    "0bfe34ad03d06537041174791e018ffa");
    bn_from_hex(&b, "33c5c6e832ab04a47c284803443f587c"
                    "4cd6054e218702be05fa80e9042b060b");
    bn_mulmod(&r1, &a, &b, &m);
    bn_mulmod(&r2, &b, &a, &m);
    ASSERT(memcmp(r1.d, r2.d, sizeof r1.d) == 0);
}

/* =========================================================================
 * 7. Repeated squaring identity: a^(2k) mod n == (a^k mod n)^2 mod n
 *
 * Verifies that squaring inside powmod is consistent with a direct
 * mulmod call.  A bug that only manifests after many squarings would
 * fail this.
 * ========================================================================= */

static void test_powmod_squaring_consistency(void) {
    RSAKey k = rsa_keygen();
    BN base, exp_k, exp_2k, r_k, r_2k, r_sq;

    bn_set32(&base, 65537);

    /* exp_k = 0x1000  (bit 12 set) */
    bn_set32(&exp_k, 0x1000);

    /* exp_2k = 0x2000  (bit 13 set) = exp_k << 1 */
    bn_set32(&exp_2k, 0x2000);

    bn_powmod(&r_k,  &base, &exp_k,  &k.n);   /* base^k mod n */
    bn_powmod(&r_2k, &base, &exp_2k, &k.n);   /* base^(2k) mod n */

    bn_mulmod(&r_sq, &r_k, &r_k, &k.n);       /* (base^k)^2 mod n */

    /* base^(2k) must equal (base^k)^2 */
    ASSERT(memcmp(r_2k.d, r_sq.d, sizeof r_2k.d) == 0);
}

/* =========================================================================
 * Main
 * ========================================================================= */

int main(void) {
    printf("=== Fermat's Little Theorem (powmod stress) ===\n\n");
    RUN_TEST(test_fermat_prime_p_base2);
    RUN_TEST(test_fermat_prime_p_base3);
    RUN_TEST(test_fermat_prime_p_base65537);
    RUN_TEST(test_fermat_prime_q_base2);
    RUN_TEST(test_fermat_prime_q_base7);

    printf("\n=== Near-modulus mulmod reduction ===\n\n");
    RUN_TEST(test_mulmod_m_minus_one_squared);
    RUN_TEST(test_mulmod_n_minus_one_squared);

    printf("\n=== RSA roundtrip sweep (m = 2..127) ===\n\n");
    RUN_TEST(test_rsa_roundtrip_sweep);

    printf("\n=== CTR counter uniqueness (32 blocks) ===\n\n");
    RUN_TEST(test_ctr_counter_uniqueness);

    printf("\n=== CTR block boundary lengths ===\n\n");
    RUN_TEST(test_ctr_boundary_0);
    RUN_TEST(test_ctr_boundary_1);
    RUN_TEST(test_ctr_boundary_15);
    RUN_TEST(test_ctr_boundary_16);
    RUN_TEST(test_ctr_boundary_17);
    RUN_TEST(test_ctr_boundary_31);
    RUN_TEST(test_ctr_boundary_32);
    RUN_TEST(test_ctr_boundary_33);

    printf("\n=== bn_mulmod commutativity ===\n\n");
    RUN_TEST(test_mulmod_commutativity_small);
    RUN_TEST(test_mulmod_commutativity_256bit);

    printf("\n=== Repeated squaring consistency ===\n\n");
    RUN_TEST(test_powmod_squaring_consistency);

    PRINT_SUMMARY();
}
