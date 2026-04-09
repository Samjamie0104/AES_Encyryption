/*
 * test_hybrid.c — Integration and edge-case tests for the hybrid
 *                 RSA+AES-CTR encrypt/decrypt system
 *
 * Covers:
 *   hybrid_encrypt / hybrid_decrypt — normal round-trip
 *   Empty message (len = 0)
 *   Single-byte message
 *   Large message (>1 block)
 *   Ciphertext shorter than RSA_BYTES+16 — should return NULL safely
 *   Decryption with a wrong RSA key — should not crash (produces garbage)
 *   blob_free — double-free safety
 */

#include "../src/main.c"
#include "test_framework.h"

/* Generate the RSA key once for the whole suite. */
static RSAKey g_key;

static void setup_key(void) {
    g_key = rsa_keygen();
}

/* =========================================================================
 * Normal round-trip
 * ========================================================================= */

static void test_roundtrip_typical_message(void) {
    const char *msg = "Hello, hybrid RSA+AES-CTR!";
    size_t mlen = strlen(msg);

    Blob ct = hybrid_encrypt((const uint8_t *)msg, mlen, &g_key);
    ASSERT(ct.data != NULL);
    /* Ciphertext must be longer than plaintext (RSA header + nonce prepended) */
    ASSERT(ct.len > mlen);

    Blob pt = hybrid_decrypt(ct.data, ct.len, &g_key);
    ASSERT(pt.data != NULL);
    ASSERT_EQ(pt.len, mlen);
    ASSERT_MEM_EQ(pt.data, msg, mlen);

    blob_free(&ct);
    blob_free(&pt);
}

static void test_roundtrip_ciphertext_differs_from_plaintext(void) {
    const char *msg = "sensitive data";
    size_t mlen = strlen(msg);

    Blob ct = hybrid_encrypt((const uint8_t *)msg, mlen, &g_key);
    ASSERT(ct.data != NULL);

    /* The ciphertext payload portion (after RSA_BYTES+16 header) must not
     * be equal to the plaintext (with astronomically high probability). */
    int payload_differs = memcmp(ct.data + RSA_BYTES + 16, msg, mlen) != 0;
    ASSERT(payload_differs);

    blob_free(&ct);
}

static void test_roundtrip_two_encryptions_differ(void) {
    /* CTR nonce is random — two encryptions of the same message must yield
     * different ciphertexts (with astronomically high probability). */
    const char *msg = "same plaintext";
    size_t mlen = strlen(msg);

    Blob ct1 = hybrid_encrypt((const uint8_t *)msg, mlen, &g_key);
    Blob ct2 = hybrid_encrypt((const uint8_t *)msg, mlen, &g_key);

    ASSERT(ct1.data != NULL && ct2.data != NULL);
    ASSERT_EQ(ct1.len, ct2.len);
    ASSERT(memcmp(ct1.data, ct2.data, ct1.len) != 0);

    blob_free(&ct1);
    blob_free(&ct2);
}

/* =========================================================================
 * Edge: empty message
 * ========================================================================= */

static void test_empty_message_encrypt_decrypt(void) {
    Blob ct = hybrid_encrypt(NULL, 0, &g_key);
    ASSERT(ct.data != NULL);
    /* Expected size: RSA_BYTES (64) + nonce (16) + 0 payload = 80 bytes */
    ASSERT_EQ(ct.len, (size_t)(RSA_BYTES + 16));

    Blob pt = hybrid_decrypt(ct.data, ct.len, &g_key);
    ASSERT(pt.data != NULL);
    ASSERT_EQ(pt.len, 0u);

    blob_free(&ct);
    blob_free(&pt);
}

/* =========================================================================
 * Edge: single byte
 * ========================================================================= */

static void test_single_byte_roundtrip(void) {
    uint8_t msg[1] = {0x42};
    Blob ct = hybrid_encrypt(msg, 1, &g_key);
    ASSERT(ct.data != NULL);
    ASSERT_EQ(ct.len, (size_t)(RSA_BYTES + 16 + 1));

    Blob pt = hybrid_decrypt(ct.data, ct.len, &g_key);
    ASSERT(pt.data != NULL);
    ASSERT_EQ(pt.len, 1u);
    ASSERT_EQ(pt.data[0], 0x42);

    blob_free(&ct);
    blob_free(&pt);
}

/* =========================================================================
 * Edge: large message (multiple AES-CTR blocks)
 * ========================================================================= */

static void test_large_message_roundtrip(void) {
    /* 1 KiB of data — many AES-CTR blocks */
    const size_t mlen = 1024;
    uint8_t *msg = malloc(mlen);
    for (size_t i = 0; i < mlen; i++) msg[i] = (uint8_t)(i & 0xff);

    Blob ct = hybrid_encrypt(msg, mlen, &g_key);
    ASSERT(ct.data != NULL);
    ASSERT_EQ(ct.len, mlen + RSA_BYTES + 16);

    Blob pt = hybrid_decrypt(ct.data, ct.len, &g_key);
    ASSERT(pt.data != NULL);
    ASSERT_EQ(pt.len, mlen);
    ASSERT_MEM_EQ(pt.data, msg, mlen);

    free(msg);
    blob_free(&ct);
    blob_free(&pt);
}

/* =========================================================================
 * Edge: ciphertext too short — must return NULL gracefully
 * ========================================================================= */

static void test_decrypt_ciphertext_too_short_returns_null(void) {
    /* One byte shorter than the minimum valid header */
    size_t too_short = RSA_BYTES + 16 - 1;
    uint8_t *fake_ct = calloc(too_short, 1);

    Blob pt = hybrid_decrypt(fake_ct, too_short, &g_key);
    ASSERT(pt.data == NULL);
    ASSERT_EQ(pt.len, 0u);

    free(fake_ct);
}

static void test_decrypt_empty_ciphertext_returns_null(void) {
    uint8_t dummy[1] = {0};
    Blob pt = hybrid_decrypt(dummy, 0, &g_key);
    ASSERT(pt.data == NULL);
    ASSERT_EQ(pt.len, 0u);
}

/* =========================================================================
 * Wrong key — should not crash; plaintext should differ
 * ========================================================================= */

static void test_decrypt_with_wrong_key_does_not_crash(void) {
    const char *msg = "secret";
    size_t mlen = strlen(msg);

    Blob ct = hybrid_encrypt((const uint8_t *)msg, mlen, &g_key);
    ASSERT(ct.data != NULL);

    /* Build a second key (different p,q would be ideal but rsa_keygen uses
     * fixed primes — we corrupt the private key instead to simulate a
     * wrong-key scenario while still producing a correctly-sized output). */
    RSAKey bad_key = g_key;
    bad_key.d.d[0] ^= 0x01; /* flip one bit of d */

    Blob pt = hybrid_decrypt(ct.data, ct.len, &bad_key);
    /* Must not crash; return value may be non-NULL (garbage plaintext) */
    ASSERT_EQ(pt.len, mlen); /* length is structural, always correct */
    /* Garbage plaintext must differ from the original (with overwhelming prob) */
    ASSERT(memcmp(pt.data, msg, mlen) != 0);

    blob_free(&ct);
    blob_free(&pt);
}

/* =========================================================================
 * blob_free — double-free safety (data set to NULL after free)
 * ========================================================================= */

static void test_blob_free_nulls_pointer(void) {
    Blob b;
    b.data = malloc(8); b.len = 8;
    ASSERT(b.data != NULL);
    blob_free(&b);
    ASSERT(b.data == NULL);
    ASSERT_EQ(b.len, 0u);
}

/* =========================================================================
 * Wire format: verify header layout
 * ========================================================================= */

static void test_ciphertext_wire_format_size(void) {
    const char *msg = "test";
    size_t mlen = strlen(msg);
    Blob ct = hybrid_encrypt((const uint8_t *)msg, mlen, &g_key);
    /* total = RSA_BYTES (64) + nonce (16) + mlen */
    ASSERT_EQ(ct.len, (size_t)(RSA_BYTES + 16 + mlen));
    blob_free(&ct);
}

/* =========================================================================
 * Main
 * ========================================================================= */

int main(void) {
    rng_seed();
    setup_key();

    printf("=== Hybrid encrypt/decrypt tests ===\n\n");

    printf("Normal round-trip:\n");
    RUN_TEST(test_roundtrip_typical_message);
    RUN_TEST(test_roundtrip_ciphertext_differs_from_plaintext);
    RUN_TEST(test_roundtrip_two_encryptions_differ);

    printf("\nEdge cases:\n");
    RUN_TEST(test_empty_message_encrypt_decrypt);
    RUN_TEST(test_single_byte_roundtrip);
    RUN_TEST(test_large_message_roundtrip);

    printf("\nError handling:\n");
    RUN_TEST(test_decrypt_ciphertext_too_short_returns_null);
    RUN_TEST(test_decrypt_empty_ciphertext_returns_null);

    printf("\nWrong key:\n");
    RUN_TEST(test_decrypt_with_wrong_key_does_not_crash);

    printf("\nblob_free:\n");
    RUN_TEST(test_blob_free_nulls_pointer);

    printf("\nWire format:\n");
    RUN_TEST(test_ciphertext_wire_format_size);

    PRINT_SUMMARY();
}
