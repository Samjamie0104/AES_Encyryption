/*
 * test_adversarial.c — Adversarial / property-based tests
 *
 * These tests are designed to break things. They verify that:
 *   - Corrupted ciphertext produces wrong plaintext (not silently accepted)
 *   - Wrong keys / nonces produce wrong output
 *   - Edge-case inputs (m=0, m=1, exponent=0) behave correctly
 *   - Cryptographic properties hold: sensitivity to input, distinctness,
 *     determinism, and correct CTR malleability behaviour
 *
 * Happy-path tests prove things work when nothing goes wrong.
 * These tests prove things fail correctly when something does.
 */

#include "../src/main.c"
#include "test_framework.h"

/* =========================================================================
 * Helpers
 * ========================================================================= */

static int buf_eq(const uint8_t *a, const uint8_t *b, size_t n) {
    return memcmp(a, b, n) == 0;
}

/* Count differing bytes between two buffers of equal length. */
static int count_diffs(const uint8_t *a, const uint8_t *b, size_t n) {
    int d = 0;
    for (size_t i = 0; i < n; i++) if (a[i] != b[i]) d++;
    return d;
}

static int bn_eq32(const BN *a, u32 v) {
    if (a->d[0] != v) return 0;
    for (int i = 1; i < BN_LIMBS; i++) if (a->d[i]) return 0;
    return 1;
}

/* =========================================================================
 * AES block cipher — sensitivity and distinctness
 * ========================================================================= */

/* Encrypting the same plaintext with two different keys must give
 * different ciphertext — if this fails the key is being ignored. */
static void test_aes_different_keys_give_different_ct(void) {
    uint8_t pt[16]  = {0x32,0x43,0xf6,0xa8,0x88,0x5a,0x30,0x8d,
                       0x31,0x31,0x98,0xa2,0xe0,0x37,0x07,0x34};
    uint8_t key1[16] = {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
                        0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};
    uint8_t key2[16] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
                        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
    uint8_t ct1[16], ct2[16];
    aes_encrypt_block(pt, key1, ct1);
    aes_encrypt_block(pt, key2, ct2);
    ASSERT(count_diffs(ct1, ct2, 16) > 0);
}

/* Ciphertext must differ from plaintext — catches identity-function bugs. */
static void test_aes_output_differs_from_input(void) {
    uint8_t pt[16]  = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
                       0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
    uint8_t key[16] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
                       0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
    uint8_t ct[16];
    aes_encrypt_block(pt, key, ct);
    ASSERT(count_diffs(pt, ct, 16) > 0);
}

/* Flipping one bit in the key must change the ciphertext (avalanche).
 * A broken key schedule might only use part of the key. */
static void test_aes_single_bit_key_change_changes_output(void) {
    uint8_t pt[16]   = {0};
    uint8_t key1[16] = {0};
    uint8_t key2[16] = {0}; key2[0] ^= 0x01; /* flip bit 0 */
    uint8_t ct1[16], ct2[16];
    aes_encrypt_block(pt, key1, ct1);
    aes_encrypt_block(pt, key2, ct2);
    ASSERT(count_diffs(ct1, ct2, 16) > 0);
}

/* Flipping one bit in the plaintext must change the ciphertext. */
static void test_aes_single_bit_pt_change_changes_output(void) {
    uint8_t key[16] = {0};
    uint8_t pt1[16] = {0};
    uint8_t pt2[16] = {0}; pt2[7] ^= 0x80; /* flip high bit of byte 7 */
    uint8_t ct1[16], ct2[16];
    aes_encrypt_block(pt1, key, ct1);
    aes_encrypt_block(pt2, key, ct2);
    ASSERT(count_diffs(ct1, ct2, 16) > 0);
}

/* All-zero key + all-zero plaintext must not produce all-zero ciphertext. */
static void test_aes_all_zeros_not_identity(void) {
    uint8_t pt[16]  = {0};
    uint8_t key[16] = {0};
    uint8_t ct[16];
    aes_encrypt_block(pt, key, ct);
    int all_zero = 1;
    for (int i = 0; i < 16; i++) if (ct[i]) { all_zero = 0; break; }
    ASSERT(!all_zero);
}

/* =========================================================================
 * AES-CTR — wrong key / nonce / tampered ciphertext
 * ========================================================================= */

static void test_ctr_wrong_key_gives_wrong_plaintext(void) {
    uint8_t pt[32]    = "Hello, adversarial test world!!";
    uint8_t key1[16]  = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
                         0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10};
    uint8_t key2[16]  = {0xff,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
                         0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10};
    uint8_t nonce[16] = {0};
    uint8_t ct[32], dec[32];

    aes_ctr(pt, ct,  32, key1, nonce);   /* encrypt with key1 */
    aes_ctr(ct, dec, 32, key2, nonce);   /* decrypt with wrong key2 */
    ASSERT(!buf_eq(dec, pt, 32));
}

static void test_ctr_wrong_nonce_gives_wrong_plaintext(void) {
    uint8_t pt[32]     = "Hello, adversarial test world!!";
    uint8_t key[16]    = {0};
    uint8_t nonce1[16] = {0x00};
    uint8_t nonce2[16] = {0x00}; nonce2[15] = 0x01;
    uint8_t ct[32], dec[32];

    aes_ctr(pt,  ct,  32, key, nonce1);  /* encrypt with nonce1 */
    aes_ctr(ct,  dec, 32, key, nonce2);  /* decrypt with nonce2 */
    ASSERT(!buf_eq(dec, pt, 32));
}

/* CTR is a stream cipher: flipping bit i in ciphertext flips bit i in the
 * decrypted plaintext. This is a known property (no integrity), but the
 * position of the corruption must be exactly where the flip was made. */
static void test_ctr_bit_flip_propagates_exactly(void) {
    uint8_t pt[16]    = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
                         0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
    uint8_t key[16]   = {0};
    uint8_t nonce[16] = {0};
    uint8_t ct[16], dec[16];

    aes_ctr(pt, ct, 16, key, nonce);
    ct[5] ^= 0x08;                        /* flip bit 3 of byte 5 */
    aes_ctr(ct, dec, 16, key, nonce);

    /* Only byte 5 should differ from original plaintext. */
    for (int i = 0; i < 16; i++) {
        if (i == 5) {
            ASSERT(dec[i] != pt[i]);      /* the flipped byte is wrong */
        } else {
            ASSERT_EQ(dec[i], pt[i]);     /* all other bytes are correct */
        }
    }
}

/* Same key + same nonce must produce the same ciphertext (deterministic). */
static void test_ctr_deterministic(void) {
    uint8_t pt[24]    = "determinism check 123456";
    uint8_t key[16]   = {0xAB};
    uint8_t nonce[16] = {0xCD};
    uint8_t ct1[24], ct2[24];
    aes_ctr(pt, ct1, 24, key, nonce);
    aes_ctr(pt, ct2, 24, key, nonce);
    ASSERT(buf_eq(ct1, ct2, 24));
}

/* Same plaintext + different nonces must give different ciphertexts.
 * If this fails the nonce is being ignored (nonce reuse vulnerability). */
static void test_ctr_different_nonces_give_different_ct(void) {
    uint8_t pt[16]     = "same message    ";
    uint8_t key[16]    = {0};
    uint8_t nonce1[16] = {0};
    uint8_t nonce2[16] = {0}; nonce2[0] = 0xFF;
    uint8_t ct1[16], ct2[16];
    aes_ctr(pt, ct1, 16, key, nonce1);
    aes_ctr(pt, ct2, 16, key, nonce2);
    ASSERT(count_diffs(ct1, ct2, 16) > 0);
}

/* Ciphertext must differ from plaintext (stream cipher isn't identity). */
static void test_ctr_output_differs_from_input(void) {
    uint8_t pt[16]    = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
                         0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
    uint8_t key[16]   = {0};
    uint8_t nonce[16] = {0};
    uint8_t ct[16];
    aes_ctr(pt, ct, 16, key, nonce);
    ASSERT(count_diffs(pt, ct, 16) > 0);
}

/* A 1-byte message must survive a CTR round-trip. Partial block edge case. */
static void test_ctr_single_byte_roundtrip(void) {
    uint8_t pt[1]     = {0x42};
    uint8_t key[16]   = {0};
    uint8_t nonce[16] = {0};
    uint8_t ct[1], dec[1];
    aes_ctr(pt, ct,  1, key, nonce);
    aes_ctr(ct, dec, 1, key, nonce);
    ASSERT_EQ(dec[0], pt[0]);
}

/* =========================================================================
 * RSA — mathematical edge cases and fixed points
 * ========================================================================= */

/* RSA fixed point: 0^e mod n = 0.
 * Encrypting m=0 leaks the message (ciphertext = 0). */
static void test_rsa_fixed_point_zero(void) {
    RSAKey k = rsa_keygen();
    BN m, c;
    bn_set32(&m, 0);
    bn_powmod(&c, &m, &k.e, &k.n);
    ASSERT(bn_is_zero(&c));
}

/* RSA fixed point: 1^e mod n = 1.
 * Encrypting m=1 leaks the message (ciphertext = 1). */
static void test_rsa_fixed_point_one(void) {
    RSAKey k = rsa_keygen();
    BN m, c;
    bn_set32(&m, 1);
    bn_powmod(&c, &m, &k.e, &k.n);
    ASSERT(bn_eq32(&c, 1));
}

/* Decrypting with the wrong private key must not recover the message. */
static void test_rsa_wrong_d_gives_wrong_plaintext(void) {
    RSAKey k = rsa_keygen();
    BN m, c, rec;
    bn_set32(&m, 42);
    bn_powmod(&c, &m, &k.e, &k.n);   /* encrypt */

    /* Corrupt d by adding 1 */
    BN bad_d, one;
    bn_copy(&bad_d, &k.d);
    bn_set32(&one, 1);
    bn_add(&bad_d, &bad_d, &one);

    bn_powmod(&rec, &c, &bad_d, &k.n); /* decrypt with bad d */
    ASSERT(bn_cmp(&rec, &m) != 0);
}

/* Two different messages must encrypt to different ciphertexts
 * (RSA is a permutation — it must be injective). */
static void test_rsa_distinct_messages_give_distinct_ct(void) {
    RSAKey k = rsa_keygen();
    BN m1, m2, c1, c2;
    bn_set32(&m1, 1000);
    bn_set32(&m2, 1001);
    bn_powmod(&c1, &m1, &k.e, &k.n);
    bn_powmod(&c2, &m2, &k.e, &k.n);
    ASSERT(bn_cmp(&c1, &c2) != 0);
}

/* =========================================================================
 * BigNum — powmod edge cases
 * ========================================================================= */

/* x^0 mod n = 1 for any x > 0. */
static void test_powmod_zero_exponent(void) {
    BN base, exp, mod, r;
    bn_set32(&base, 12345);
    bn_set32(&exp, 0);
    bn_set32(&mod, 9999);
    bn_powmod(&r, &base, &exp, &mod);
    ASSERT(bn_eq32(&r, 1));
}

/* 0^e mod n = 0 for any e > 0. */
static void test_powmod_zero_base(void) {
    BN base, exp, mod, r;
    bn_set32(&base, 0);
    bn_set32(&exp, 65537);
    bn_set32(&mod, 9999);
    bn_powmod(&r, &base, &exp, &mod);
    ASSERT(bn_is_zero(&r));
}

/* 1^e mod n = 1 for any e, n > 1. */
static void test_powmod_one_base(void) {
    BN base, exp, mod, r;
    bn_set32(&base, 1);
    bn_set32(&exp, 65537);
    bn_set32(&mod, 9999);
    bn_powmod(&r, &base, &exp, &mod);
    ASSERT(bn_eq32(&r, 1));
}

/* =========================================================================
 * Hybrid — tamper with each section of the wire format
 * ========================================================================= */

static void seed_fixed_rng(void) {
    /* Use a fixed RNG state for reproducible hybrid encrypt output. */
    rng_s[0] = 0x123456789abcdef0ULL;
    rng_s[1] = 0xfedcba9876543210ULL;
    rng_s[2] = 0xdeadbeefcafeULL;
    rng_s[3] = 0xbabe1234feULL;
}

/* Flipping a byte inside the RSA-encrypted key section must produce
 * a different (wrong) plaintext after decryption. */
static void test_hybrid_tamper_rsa_key_section(void) {
    RSAKey k = rsa_keygen();
    seed_fixed_rng();

    const uint8_t *msg = (const uint8_t *)"secret message";
    size_t mlen = 14;

    Blob ct = hybrid_encrypt(msg, mlen, &k);
    ASSERT(ct.data != NULL);

    /* Flip a byte in the first RSA_BYTES (64) of the ciphertext. */
    ct.data[10] ^= 0xFF;

    Blob dec = hybrid_decrypt(ct.data, ct.len, &k);

    /* Either decryption fails (NULL/short) or produces wrong plaintext. */
    int wrong = (dec.data == NULL) ||
                (dec.len != mlen)  ||
                !buf_eq(dec.data, msg, mlen);
    ASSERT(wrong);

    blob_free(&ct);
    blob_free(&dec);
}

/* Flipping a byte in the nonce section must produce wrong plaintext. */
static void test_hybrid_tamper_nonce_section(void) {
    RSAKey k = rsa_keygen();
    seed_fixed_rng();

    const uint8_t *msg = (const uint8_t *)"secret message";
    size_t mlen = 14;

    Blob ct = hybrid_encrypt(msg, mlen, &k);
    ASSERT(ct.data != NULL);

    /* Nonce is at bytes [RSA_BYTES .. RSA_BYTES+16). Flip byte in the middle. */
    ct.data[RSA_BYTES + 8] ^= 0x01;

    Blob dec = hybrid_decrypt(ct.data, ct.len, &k);

    int wrong = (dec.data == NULL) ||
                (dec.len != mlen)  ||
                !buf_eq(dec.data, msg, mlen);
    ASSERT(wrong);

    blob_free(&ct);
    blob_free(&dec);
}

/* Flipping a byte in the payload section must corrupt exactly that region
 * of the decrypted plaintext (CTR stream-cipher property). */
static void test_hybrid_tamper_payload_section(void) {
    RSAKey k = rsa_keygen();
    seed_fixed_rng();

    const uint8_t *msg = (const uint8_t *)"secret message";
    size_t mlen = 14;

    Blob ct = hybrid_encrypt(msg, mlen, &k);
    ASSERT(ct.data != NULL);

    /* Payload starts at offset RSA_BYTES + 16. Flip the first payload byte. */
    size_t payload_off = RSA_BYTES + 16;
    ct.data[payload_off] ^= 0xFF;

    Blob dec = hybrid_decrypt(ct.data, ct.len, &k);
    ASSERT(dec.data != NULL);
    ASSERT_EQ(dec.len, mlen);

    /* The first byte must be corrupted; the rest must be intact. */
    ASSERT(dec.data[0] != msg[0]);
    if (mlen > 1) {
        ASSERT(buf_eq(dec.data + 1, msg + 1, mlen - 1));
    }

    blob_free(&ct);
    blob_free(&dec);
}

/* Two encryptions of the same message must produce different ciphertexts
 * because the AES key and nonce are randomly generated each time. */
static void test_hybrid_randomised_encryption(void) {
    RSAKey k = rsa_keygen();
    const uint8_t *msg = (const uint8_t *)"same plaintext";
    size_t mlen = 14;

    /* Do not fix RNG — let it run normally so each call is different. */
    rng_seed();
    Blob ct1 = hybrid_encrypt(msg, mlen, &k);
    Blob ct2 = hybrid_encrypt(msg, mlen, &k);

    ASSERT(ct1.data != NULL);
    ASSERT(ct2.data != NULL);
    ASSERT_EQ(ct1.len, ct2.len);
    /* The two ciphertexts (at minimum the nonce+key section) must differ. */
    ASSERT(count_diffs(ct1.data, ct2.data, ct1.len) > 0);

    blob_free(&ct1);
    blob_free(&ct2);
}

/* A zero-length message round-trips correctly through hybrid encrypt/decrypt. */
static void test_hybrid_empty_message(void) {
    RSAKey k = rsa_keygen();
    seed_fixed_rng();

    Blob ct = hybrid_encrypt(NULL, 0, &k);
    /* Total length must be exactly RSA_BYTES + 16 (key + nonce, no payload). */
    ASSERT(ct.data != NULL);
    ASSERT_EQ(ct.len, (size_t)(RSA_BYTES + 16));

    Blob dec = hybrid_decrypt(ct.data, ct.len, &k);
    ASSERT(dec.data != NULL);
    ASSERT_EQ(dec.len, 0u);

    blob_free(&ct);
    blob_free(&dec);
}

/* =========================================================================
 * Main
 * ========================================================================= */

int main(void) {
    printf("=== AES block cipher adversarial ===\n\n");
    RUN_TEST(test_aes_different_keys_give_different_ct);
    RUN_TEST(test_aes_output_differs_from_input);
    RUN_TEST(test_aes_single_bit_key_change_changes_output);
    RUN_TEST(test_aes_single_bit_pt_change_changes_output);
    RUN_TEST(test_aes_all_zeros_not_identity);

    printf("\n=== AES-CTR adversarial ===\n\n");
    RUN_TEST(test_ctr_wrong_key_gives_wrong_plaintext);
    RUN_TEST(test_ctr_wrong_nonce_gives_wrong_plaintext);
    RUN_TEST(test_ctr_bit_flip_propagates_exactly);
    RUN_TEST(test_ctr_deterministic);
    RUN_TEST(test_ctr_different_nonces_give_different_ct);
    RUN_TEST(test_ctr_output_differs_from_input);
    RUN_TEST(test_ctr_single_byte_roundtrip);

    printf("\n=== RSA adversarial ===\n\n");
    RUN_TEST(test_rsa_fixed_point_zero);
    RUN_TEST(test_rsa_fixed_point_one);
    RUN_TEST(test_rsa_wrong_d_gives_wrong_plaintext);
    RUN_TEST(test_rsa_distinct_messages_give_distinct_ct);

    printf("\n=== BigNum powmod edge cases ===\n\n");
    RUN_TEST(test_powmod_zero_exponent);
    RUN_TEST(test_powmod_zero_base);
    RUN_TEST(test_powmod_one_base);

    printf("\n=== Hybrid tamper adversarial ===\n\n");
    RUN_TEST(test_hybrid_tamper_rsa_key_section);
    RUN_TEST(test_hybrid_tamper_nonce_section);
    RUN_TEST(test_hybrid_tamper_payload_section);
    RUN_TEST(test_hybrid_randomised_encryption);
    RUN_TEST(test_hybrid_empty_message);

    PRINT_SUMMARY();
}
