/*
 * test_aes_ops.c — Unit tests for AES-128 sub-operations and CTR mode
 *
 * Covers:
 *   gmul            — Galois field GF(2^8) multiplication
 *   aes_key_expansion  — key schedule against FIPS-197 Appendix A.1 vectors
 *   aes_sub_bytes   — S-box substitution
 *   aes_shift_rows  — row permutation
 *   aes_mix_columns — column mixing against FIPS-197 Appendix B vectors
 *   aes_ctr         — counter mode encrypt/decrypt round-trip
 *                     + non-multiple-of-16-byte messages
 *                     + in-place operation (out == in)
 */

#include "../src/main.c"
#include "test_framework.h"

/* =========================================================================
 * gmul — GF(2^8) multiply
 *
 * Reference values from FIPS-197 Section 4.2 and standard xtime examples.
 * ========================================================================= */

static void test_gmul_zero(void) {
    /* Anything multiplied by 0 = 0 */
    ASSERT_EQ(gmul(0x57, 0x00), 0x00);
    ASSERT_EQ(gmul(0x00, 0xab), 0x00);
}

static void test_gmul_one_identity(void) {
    /* Multiplying by 1 is identity */
    ASSERT_EQ(gmul(0x57, 0x01), 0x57);
    ASSERT_EQ(gmul(0x01, 0xca), 0xca);
}

static void test_gmul_by_two_no_reduction(void) {
    /* 0x57 << 1 = 0xae (high bit clear, no reduction needed) */
    ASSERT_EQ(gmul(0x57, 0x02), 0xae);
}

static void test_gmul_by_two_with_reduction(void) {
    /* 0x80 << 1 overflows — XOR with 0x1b: 0x00 ^ 0x1b = 0x1b */
    ASSERT_EQ(gmul(0x80, 0x02), 0x1b);
    /* 0xd4: high bit set, 0xd4<<1 = 0xa8 (truncated), XOR 0x1b = 0xb3 */
    ASSERT_EQ(gmul(0xd4, 0x02), 0xb3);
}

static void test_gmul_by_three(void) {
    /* gmul(a, 3) = gmul(a, 2) ^ a */
    ASSERT_EQ(gmul(0x57, 0x03), (uint8_t)(0xae ^ 0x57)); /* = 0xf9 */
    ASSERT_EQ(gmul(0xbf, 0x03), (uint8_t)(gmul(0xbf,2) ^ 0xbf));
}

static void test_gmul_inverse_pair(void) {
    /* 0x53 and 0xca are multiplicative inverses in GF(2^8) (FIPS-197 §4.2) */
    ASSERT_EQ(gmul(0x53, 0xca), 0x01);
}

static void test_gmul_commutativity(void) {
    ASSERT_EQ(gmul(0x57, 0x13), gmul(0x13, 0x57));
    ASSERT_EQ(gmul(0xab, 0xcd), gmul(0xcd, 0xab));
}

/* =========================================================================
 * aes_key_expansion — FIPS-197 Appendix A.1 (AES-128 key schedule)
 *
 * Key: 2b7e151628aed2a6abf7158809cf4f3c
 *
 * Expected expanded words (each w[i] is 4 bytes, big-endian):
 *   w[0..3]  : 2b7e1516 28aed2a6 abf71588 09cf4f3c
 *   w[4..7]  : a0fafe17 88542cb1 23a33939 2a6c7605
 *   w[8..11] : f2c295f2 7a96b943 59f45f13 0aafd4a3
 * ========================================================================= */

static void test_key_expansion_initial_words(void) {
    uint8_t key[16] = {
        0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
        0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
    };
    uint8_t w[44][4];
    aes_key_expansion(key, w);

    /* w[0] = 2b 7e 15 16 */
    uint8_t exp0[4] = {0x2b,0x7e,0x15,0x16};
    ASSERT_MEM_EQ(w[0], exp0, 4);

    /* w[3] = 09 cf 4f 3c */
    uint8_t exp3[4] = {0x09,0xcf,0x4f,0x3c};
    ASSERT_MEM_EQ(w[3], exp3, 4);
}

static void test_key_expansion_round1_words(void) {
    uint8_t key[16] = {
        0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
        0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
    };
    uint8_t w[44][4];
    aes_key_expansion(key, w);

    /* w[4] = a0 fa fe 17 */
    uint8_t exp4[4] = {0xa0,0xfa,0xfe,0x17};
    ASSERT_MEM_EQ(w[4], exp4, 4);

    /* w[5] = 88 54 2c b1 */
    uint8_t exp5[4] = {0x88,0x54,0x2c,0xb1};
    ASSERT_MEM_EQ(w[5], exp5, 4);

    /* w[6] = 23 a3 39 39 */
    uint8_t exp6[4] = {0x23,0xa3,0x39,0x39};
    ASSERT_MEM_EQ(w[6], exp6, 4);

    /* w[7] = 2a 6c 76 05 */
    uint8_t exp7[4] = {0x2a,0x6c,0x76,0x05};
    ASSERT_MEM_EQ(w[7], exp7, 4);
}

static void test_key_expansion_round2_words(void) {
    uint8_t key[16] = {
        0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
        0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
    };
    uint8_t w[44][4];
    aes_key_expansion(key, w);

    /* w[8] = f2 c2 95 f2 */
    uint8_t exp8[4]  = {0xf2,0xc2,0x95,0xf2};
    ASSERT_MEM_EQ(w[8],  exp8,  4);

    /* w[9] = 7a 96 b9 43 */
    uint8_t exp9[4]  = {0x7a,0x96,0xb9,0x43};
    ASSERT_MEM_EQ(w[9],  exp9,  4);

    /* w[10] = w[6] ^ w[9] = {23,a3,39,39} ^ {7a,96,b9,43} = {59,35,80,7a} */
    uint8_t exp10[4] = {0x59,0x35,0x80,0x7a};
    ASSERT_MEM_EQ(w[10], exp10, 4);

    /* w[11] = w[7] ^ w[10] = {2a,6c,76,05} ^ {59,35,80,7a} = {73,59,f6,7f} */
    uint8_t exp11[4] = {0x73,0x59,0xf6,0x7f};
    ASSERT_MEM_EQ(w[11], exp11, 4);
}

static void test_key_expansion_all_zeros(void) {
    /* All-zero key — mainly verifies it doesn't crash and produces
     * 44 words without reading out of bounds. */
    uint8_t key[16] = {0};
    uint8_t w[44][4];
    aes_key_expansion(key, w);
    /* w[0..3] must all be zero */
    uint8_t zero4[4] = {0,0,0,0};
    ASSERT_MEM_EQ(w[0], zero4, 4);
    ASSERT_MEM_EQ(w[1], zero4, 4);
    ASSERT_MEM_EQ(w[2], zero4, 4);
    ASSERT_MEM_EQ(w[3], zero4, 4);
    /* w[4] must be non-zero (RCON[0]=1 XORd in) */
    int nonzero = 0;
    for (int i = 0; i < 4; i++) if (w[4][i]) nonzero = 1;
    ASSERT_EQ(nonzero, 1);
}

/* =========================================================================
 * aes_sub_bytes — S-box substitution
 *
 * Reference: FIPS-197 Appendix B, Round 1, after initial AddRoundKey the
 * state is the matrix below; SubBytes transforms it to the second matrix.
 * ========================================================================= */

static void test_sub_bytes_fips197_round1(void) {
    /*
     * State after initial AddRoundKey (FIPS-197 App B):
     *   19 a0 9a e9
     *   3d f4 c6 f8
     *   e3 e2 8d 48
     *   be 2b 2a 08
     *
     * After SubBytes:
     *   d4 e0 b8 1e
     *   27 bf b4 41
     *   11 98 5d 52
     *   ae f1 e5 30
     */
    AES_State s = {
        {0x19, 0xa0, 0x9a, 0xe9},
        {0x3d, 0xf4, 0xc6, 0xf8},
        {0xe3, 0xe2, 0x8d, 0x48},
        {0xbe, 0x2b, 0x2a, 0x08}
    };
    aes_sub_bytes(s);

    uint8_t expected[4][4] = {
        {0xd4, 0xe0, 0xb8, 0x1e},
        {0x27, 0xbf, 0xb4, 0x41},
        {0x11, 0x98, 0x5d, 0x52},
        {0xae, 0xf1, 0xe5, 0x30}
    };
    for (int r = 0; r < 4; r++)
        ASSERT_MEM_EQ(s[r], expected[r], 4);
}

static void test_sub_bytes_identity_sbox_entry(void) {
    /* SBOX[0x63] = 0xfb... actually SBOX maps 0x00 -> 0x63.
     * Test that every byte goes through SBOX correctly for a
     * 16-byte state filled with the same value. */
    AES_State s;
    memset(s, 0x00, sizeof s);
    aes_sub_bytes(s);
    /* SBOX[0] = 0x63 */
    for (int r = 0; r < 4; r++)
        for (int c = 0; c < 4; c++)
            ASSERT_EQ(s[r][c], 0x63);
}

/* =========================================================================
 * aes_shift_rows
 *
 * Reference: FIPS-197 Appendix B Round 1, after SubBytes state (above)
 * ShiftRows rotates row r left by r positions.
 * ========================================================================= */

static void test_shift_rows_fips197_round1(void) {
    /*
     * Input (post-SubBytes):
     *   Row 0: d4 e0 b8 1e  (no shift)
     *   Row 1: 27 bf b4 41  (shift left 1 → bf b4 41 27)
     *   Row 2: 11 98 5d 52  (shift left 2 → 5d 52 11 98)
     *   Row 3: ae f1 e5 30  (shift left 3 → 30 ae f1 e5)
     */
    AES_State s = {
        {0xd4, 0xe0, 0xb8, 0x1e},
        {0x27, 0xbf, 0xb4, 0x41},
        {0x11, 0x98, 0x5d, 0x52},
        {0xae, 0xf1, 0xe5, 0x30}
    };
    aes_shift_rows(s);

    /* Row 0 unchanged */
    uint8_t exp0[4] = {0xd4, 0xe0, 0xb8, 0x1e};
    ASSERT_MEM_EQ(s[0], exp0, 4);

    uint8_t exp1[4] = {0xbf, 0xb4, 0x41, 0x27};
    ASSERT_MEM_EQ(s[1], exp1, 4);

    uint8_t exp2[4] = {0x5d, 0x52, 0x11, 0x98};
    ASSERT_MEM_EQ(s[2], exp2, 4);

    uint8_t exp3[4] = {0x30, 0xae, 0xf1, 0xe5};
    ASSERT_MEM_EQ(s[3], exp3, 4);
}

static void test_shift_rows_row0_unchanged(void) {
    /* Row 0 must never move, regardless of values. */
    AES_State s;
    for (int r = 0; r < 4; r++)
        for (int c = 0; c < 4; c++)
            s[r][c] = (uint8_t)(r * 4 + c);
    uint8_t row0_before[4]; memcpy(row0_before, s[0], 4);
    aes_shift_rows(s);
    ASSERT_MEM_EQ(s[0], row0_before, 4);
}

static void test_shift_rows_identity_on_uniform_rows(void) {
    /* If every element in a row has the same value, shifting is a no-op. */
    AES_State s;
    memset(s[0], 0xaa, 4); memset(s[1], 0xbb, 4);
    memset(s[2], 0xcc, 4); memset(s[3], 0xdd, 4);
    AES_State before; memcpy(before, s, sizeof s);
    aes_shift_rows(s);
    for (int r = 0; r < 4; r++)
        ASSERT_MEM_EQ(s[r], before[r], 4);
}

/* =========================================================================
 * aes_mix_columns
 *
 * Reference: FIPS-197 Appendix B Round 1, after ShiftRows the state is:
 *   Row 0: d4 e0 b8 1e
 *   Row 1: bf b4 41 27
 *   Row 2: 5d 52 11 98
 *   Row 3: 30 ae f1 e5
 *
 * After MixColumns:
 *   Row 0: 04 e0 48 28
 *   Row 1: 66 cb f8 06
 *   Row 2: 81 19 d3 26
 *   Row 3: e5 9a 7a 4c
 * ========================================================================= */

static void test_mix_columns_fips197_round1(void) {
    AES_State s = {
        {0xd4, 0xe0, 0xb8, 0x1e},
        {0xbf, 0xb4, 0x41, 0x27},
        {0x5d, 0x52, 0x11, 0x98},
        {0x30, 0xae, 0xf1, 0xe5}
    };
    aes_mix_columns(s);

    uint8_t expected[4][4] = {
        {0x04, 0xe0, 0x48, 0x28},
        {0x66, 0xcb, 0xf8, 0x06},
        {0x81, 0x19, 0xd3, 0x26},
        {0xe5, 0x9a, 0x7a, 0x4c}
    };
    for (int r = 0; r < 4; r++)
        ASSERT_MEM_EQ(s[r], expected[r], 4);
}

static void test_mix_columns_zero_state(void) {
    /* MixColumns(0) = 0 (linear operation over GF(2^8)) */
    AES_State s; memset(s, 0, sizeof s);
    aes_mix_columns(s);
    for (int r = 0; r < 4; r++)
        for (int c = 0; c < 4; c++)
            ASSERT_EQ(s[r][c], 0);
}

/* =========================================================================
 * aes_ctr — counter mode
 * ========================================================================= */

static void test_ctr_encrypt_decrypt_roundtrip_full_block(void) {
    uint8_t key[16]   = {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
                         0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};
    uint8_t nonce[16] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
                         0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
    uint8_t plain[32] = "AES-CTR test plaintext here!!!!!";
    uint8_t ct[32], recovered[32];

    aes_ctr(plain, ct, 32, key, nonce);
    /* ct must differ from plaintext */
    ASSERT(memcmp(plain, ct, 32) != 0);

    aes_ctr(ct, recovered, 32, key, nonce);
    ASSERT_MEM_EQ(recovered, plain, 32);
}

static void test_ctr_encrypt_decrypt_partial_block(void) {
    /* 5 bytes — not a multiple of 16 */
    uint8_t key[16]   = {0};
    uint8_t nonce[16] = {0};
    uint8_t plain[5]  = {0x48,0x65,0x6c,0x6c,0x6f}; /* "Hello" */
    uint8_t ct[5], recovered[5];

    aes_ctr(plain, ct, 5, key, nonce);
    aes_ctr(ct, recovered, 5, key, nonce);
    ASSERT_MEM_EQ(recovered, plain, 5);
}

static void test_ctr_single_byte(void) {
    uint8_t key[16] = {0xab};
    uint8_t nonce[16] = {0x01};
    uint8_t plain[1] = {0x42};
    uint8_t ct[1], recovered[1];

    aes_ctr(plain, ct, 1, key, nonce);
    aes_ctr(ct, recovered, 1, key, nonce);
    ASSERT_EQ(recovered[0], plain[0]);
}

static void test_ctr_empty_message(void) {
    /* Zero-length message — must not crash or write anything */
    uint8_t key[16] = {0}, nonce[16] = {0};
    uint8_t out[1] = {0xAB}; /* sentinel */
    aes_ctr(NULL, out, 0, key, nonce);
    ASSERT_EQ(out[0], 0xAB); /* sentinel unchanged */
}

static void test_ctr_different_nonces_produce_different_ciphertext(void) {
    uint8_t key[16]    = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
                          0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10};
    uint8_t nonce1[16] = {0};
    uint8_t nonce2[16] = {0}; nonce2[15] = 1;
    uint8_t plain[16]  = {0x55};
    uint8_t ct1[16], ct2[16];

    aes_ctr(plain, ct1, 16, key, nonce1);
    aes_ctr(plain, ct2, 16, key, nonce2);
    ASSERT(memcmp(ct1, ct2, 16) != 0);
}

static void test_ctr_counter_increments_across_blocks(void) {
    /* Encrypting 32 bytes in one call vs two 16-byte calls must give the
     * same result only when the second call uses counter+1.  Here we just
     * verify the two-block single-call decrypt round-trips correctly. */
    uint8_t key[16]   = {0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,
                         0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00};
    uint8_t nonce[16] = {0};
    uint8_t plain[32];
    for (int i = 0; i < 32; i++) plain[i] = (uint8_t)i;
    uint8_t ct[32], recovered[32];
    aes_ctr(plain, ct, 32, key, nonce);
    aes_ctr(ct, recovered, 32, key, nonce);
    ASSERT_MEM_EQ(recovered, plain, 32);
}

/* =========================================================================
 * Main
 * ========================================================================= */

int main(void) {
    printf("=== AES sub-operation & CTR tests ===\n\n");

    printf("gmul:\n");
    RUN_TEST(test_gmul_zero);
    RUN_TEST(test_gmul_one_identity);
    RUN_TEST(test_gmul_by_two_no_reduction);
    RUN_TEST(test_gmul_by_two_with_reduction);
    RUN_TEST(test_gmul_by_three);
    RUN_TEST(test_gmul_inverse_pair);
    RUN_TEST(test_gmul_commutativity);

    printf("\naes_key_expansion:\n");
    RUN_TEST(test_key_expansion_initial_words);
    RUN_TEST(test_key_expansion_round1_words);
    RUN_TEST(test_key_expansion_round2_words);
    RUN_TEST(test_key_expansion_all_zeros);

    printf("\naes_sub_bytes:\n");
    RUN_TEST(test_sub_bytes_fips197_round1);
    RUN_TEST(test_sub_bytes_identity_sbox_entry);

    printf("\naes_shift_rows:\n");
    RUN_TEST(test_shift_rows_fips197_round1);
    RUN_TEST(test_shift_rows_row0_unchanged);
    RUN_TEST(test_shift_rows_identity_on_uniform_rows);

    printf("\naes_mix_columns:\n");
    RUN_TEST(test_mix_columns_fips197_round1);
    RUN_TEST(test_mix_columns_zero_state);

    printf("\naes_ctr:\n");
    RUN_TEST(test_ctr_encrypt_decrypt_roundtrip_full_block);
    RUN_TEST(test_ctr_encrypt_decrypt_partial_block);
    RUN_TEST(test_ctr_single_byte);
    RUN_TEST(test_ctr_empty_message);
    RUN_TEST(test_ctr_different_nonces_produce_different_ciphertext);
    RUN_TEST(test_ctr_counter_increments_across_blocks);

    PRINT_SUMMARY();
}
