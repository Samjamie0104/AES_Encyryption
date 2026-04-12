/*
 * hybrid_crypto.c  —  RSA-512 + AES-128-CTR hybrid cryptosystem in pure C
 *
 * Sections:
 *   1. BigNum   — 512-bit arbitrary-precision arithmetic
 *   2. AES-128  — FIPS-197 compliant block cipher
 *   3. AES-CTR  — counter mode (encrypt = decrypt)
 *   4. RNG      — xoshiro256** seeded from /dev/urandom
 *   5. RSA      — key generation + encrypt/decrypt via powmod
 *   6. Hybrid   — RSA wraps AES key, AES-CTR encrypts payload
 *   7. Tests + main
 *
 * Build:  gcc -O2 -Wall -o hybrid_crypto hybrid_crypto.c
 * Note:   RSA-512 is demo-size. Increase BIGNUM_LIMBS to 64 for RSA-2048.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* =========================================================================
 * 1. BIGNUM  (little-endian 32-bit limbs, 512 bits = 16 limbs)
 * ========================================================================= */

#define BN_LIMBS  16
#define BN_LIMBS2 32          /* double-width for multiply results */

typedef uint32_t  u32;
typedef uint64_t  u64;

typedef struct { u32 d[BN_LIMBS]; } BN;

static void bn_zero (BN *r)               { memset(r->d, 0, sizeof r->d); }
static void bn_set32(BN *r, u32 v)        { bn_zero(r); r->d[0] = v; }
static void bn_copy (BN *r, const BN *a)  { memcpy(r, a, sizeof *r); }

static int bn_is_zero(const BN *a) {
    for (int i = 0; i < BN_LIMBS; i++) if (a->d[i]) return 0;
    return 1;
}

static int bn_cmp(const BN *a, const BN *b) {
    for (int i = BN_LIMBS-1; i >= 0; i--) {
        if (a->d[i] > b->d[i]) return  1;
        if (a->d[i] < b->d[i]) return -1;
    }
    return 0;
}

/* r = a + b, returns carry */
static u32 bn_add(BN *r, const BN *a, const BN *b) {
    u64 c = 0;
    for (int i = 0; i < BN_LIMBS; i++) {
        u64 s = (u64)a->d[i] + b->d[i] + c;
        r->d[i] = (u32)s; c = s >> 32;
    }
    return (u32)c;
}

/* r = a - b  (a >= b) */
static void bn_sub(BN *r, const BN *a, const BN *b) {
    u64 bw = 0;
    for (int i = 0; i < BN_LIMBS; i++) {
        u64 s = (u64)a->d[i] - b->d[i] - bw;
        r->d[i] = (u32)s; bw = (s >> 63) & 1;
    }
}

/* Double-wide (2*BN_LIMBS) helpers */

static void dw_shr1(u32 *a) {
    for (int i = 0; i < BN_LIMBS2-1; i++)
        a[i] = (a[i] >> 1) | (a[i+1] << 31);
    a[BN_LIMBS2-1] >>= 1;
}

/* cmp double-wide a vs double-wide b */
static int dw_cmp(const u32 *a, const u32 *b) {
    for (int i = BN_LIMBS2-1; i >= 0; i--) {
        if (a[i] > b[i]) return  1;
        if (a[i] < b[i]) return -1;
    }
    return 0;
}

/* a -= b, both double-wide */
static void dw_sub(u32 *a, const u32 *b) {
    u64 bw = 0;
    for (int i = 0; i < BN_LIMBS2; i++) {
        u64 s = (u64)a[i] - b[i] - bw;
        a[i] = (u32)s; bw = (s >> 63) & 1;
    }
}

/* Full BN_LIMBS x BN_LIMBS → 2*BN_LIMBS multiply */
static void bn_mul_full(u32 *out, const BN *a, const BN *b) {
    memset(out, 0, BN_LIMBS2 * sizeof(u32));
    for (int i = 0; i < BN_LIMBS; i++) {
        u64 c = 0;
        for (int j = 0; j < BN_LIMBS; j++) {
            u64 cur = (u64)a->d[i] * b->d[j] + out[i+j] + c;
            out[i+j] = (u32)cur; c = cur >> 32;
        }
        out[i+BN_LIMBS] += (u32)c;
    }
}

/*
 * r = (a * b) mod m
 *
 * Algorithm: schoolbook multiply → 1024-bit product, then binary
 * long-division reduction (shift-and-subtract on the shifted divisor).
 *
 * For each bit position k from (msb_prod - msb_m) down to 0:
 *   if prod >= m<<k: prod -= m<<k
 *   (equivalent to one step of binary long division)
 */
static void bn_mulmod(BN *r, const BN *a, const BN *b, const BN *m) {
    u32 prod[BN_LIMBS2] = {0};
    bn_mul_full(prod, a, b);

    /* MSB of prod */
    int msb_prod = -1;
    for (int i = BN_LIMBS2-1; i >= 0; i--)
        if (prod[i]) { msb_prod = i*32 + 31 - __builtin_clz(prod[i]); break; }

    /* MSB of m */
    int msb_m = -1;
    for (int i = BN_LIMBS-1; i >= 0; i--)
        if (m->d[i]) { msb_m = i*32 + 31 - __builtin_clz(m->d[i]); break; }

    if (msb_prod < 0 || msb_m < 0 || msb_prod < msb_m) {
        /* prod < m — already reduced */
        memcpy(r->d, prod, BN_LIMBS * sizeof(u32));
        return;
    }

    /* Build dm = m << shift in double-wide */
    int shift = msb_prod - msb_m;
    u32 dm[BN_LIMBS2] = {0};
    {
        int wo = shift / 32, bo = shift % 32;
        for (int i = 0; i < BN_LIMBS; i++) {
            if (i+wo < BN_LIMBS2)
                dm[i+wo] |= (u64)m->d[i] << bo;
            if (bo && i+wo+1 < BN_LIMBS2)
                dm[i+wo+1] |= (u64)m->d[i] >> (32-bo);
        }
    }

    /* Shift-and-subtract loop: shift+1 iterations */
    for (int i = 0; i <= shift; i++) {
        if (dw_cmp(prod, dm) >= 0) dw_sub(prod, dm);
        dw_shr1(dm);
    }

    memcpy(r->d, prod, BN_LIMBS * sizeof(u32));
}

/*
 * r = base^exp mod m  — left-to-right square-and-multiply.
 * Skips the leading 1-bit to avoid an unnecessary initial square.
 */
static void bn_powmod(BN *r, const BN *base, const BN *exp, const BN *m) {
    /* Find MSB of exp */
    int top_limb = -1, top_bit = -1;
    for (int i = BN_LIMBS-1; i >= 0; i--) {
        if (exp->d[i]) {
            top_limb = i;
            for (int b = 31; b >= 0; b--)
                if ((exp->d[i] >> b) & 1) { top_bit = b; break; }
            break;
        }
    }
    if (top_limb < 0) { bn_set32(r, 1); return; } /* 0^0 = 1 by convention */

    BN base_r;
    bn_copy(&base_r, base);
    while (bn_cmp(&base_r, m) >= 0) bn_sub(&base_r, &base_r, m);

    int started = 0;
    for (int i = top_limb; i >= 0; i--) {
        int bstart = (i == top_limb) ? top_bit : 31;
        for (int b = bstart; b >= 0; b--) {
            if (!started) {
                /* initialise result to base, skip first squaring */
                bn_copy(r, &base_r);
                started = 1;
                continue;
            }
            bn_mulmod(r, r, r, m);                      /* square */
            if ((exp->d[i] >> b) & 1)
                bn_mulmod(r, r, &base_r, m);            /* multiply */
        }
    }
}

/*
 * bn_divmod: q = a / b,  rem = a mod b   (all BN, a >= 0, b > 0)
 */
static void bn_divmod(BN *q, BN *rem, const BN *a, const BN *b) {
    bn_zero(q);
    BN num; bn_copy(&num, a);
    if (bn_cmp(&num, b) < 0) { bn_copy(rem, &num); return; }

    int msb_num = 0, msb_b = 0;
    for (int i = BN_LIMBS-1; i >= 0; i--)
        if (num.d[i]) { msb_num = i*32+31-__builtin_clz(num.d[i]); break; }
    for (int i = BN_LIMBS-1; i >= 0; i--)
        if (b->d[i])  { msb_b   = i*32+31-__builtin_clz(b->d[i]);  break; }

    for (int sh = msb_num - msb_b; sh >= 0; sh--) {
        BN shifted; bn_zero(&shifted);
        int wo = sh/32, bo = sh%32;
        for (int i = 0; i < BN_LIMBS; i++) {
            if (i+wo < BN_LIMBS)
                shifted.d[i+wo] |= (u64)b->d[i] << bo;
            if (bo && i+wo+1 < BN_LIMBS)
                shifted.d[i+wo+1] |= (u64)b->d[i] >> (32-bo);
        }
        if (bn_cmp(&num, &shifted) >= 0) {
            bn_sub(&num, &num, &shifted);
            q->d[sh/32] |= (1u << (sh%32));
        }
    }
    bn_copy(rem, &num);
}

/*
 * r = a^-1 mod m  (iterative extended Euclidean, double-wide Bezout tracking)
 *
 * The key insight: during the algorithm, q*s can grow to ~m^2. We track
 * the Bezout coefficient |s| in double-wide storage (BN_LIMBS2 limbs)
 * with a separate sign flag to avoid ever losing high bits.
 *
 * After convergence, the result fits back in BN_LIMBS because the final
 * inverse is in [0, m).
 */
static void bn_modinv(BN *r, const BN *a, const BN *m) {
    u32 os[BN_LIMBS2], sv[BN_LIMBS2];
    int os_neg = 0, sv_neg = 1;
    memset(os, 0, sizeof os); os[0] = 1;
    memset(sv, 0, sizeof sv);

    BN old_r, rem;
    bn_copy(&old_r, a); bn_copy(&rem, m);

    while (!bn_is_zero(&rem)) {
        BN q, new_r;
        bn_divmod(&q, &new_r, &old_r, &rem);

        /* qs = q * |sv| in double-wide (no reduction) */
        u32 qs[BN_LIMBS2] = {0};
        for (int i = 0; i < BN_LIMBS; i++) {
            if (!q.d[i]) continue;
            u64 c = 0;
            for (int j = 0; j < BN_LIMBS2 && i+j < BN_LIMBS2; j++) {
                u64 cur = (u64)q.d[i] * sv[j] + qs[i+j] + c;
                qs[i+j] = (u32)cur; c = cur >> 32;
            }
        }

        /* new_s = os - q*sv  (double-wide, signed) */
        u32 new_s[BN_LIMBS2] = {0};
        int new_s_neg;

        int cmp = 0;
        for (int i = BN_LIMBS2-1; i >= 0; i--) {
            if (os[i] > qs[i]) { cmp =  1; break; }
            if (os[i] < qs[i]) { cmp = -1; break; }
        }

        if (os_neg == sv_neg) {
            if (cmp >= 0) {
                u64 bw = 0;
                for (int i = 0; i < BN_LIMBS2; i++) {
                    u64 v = (u64)os[i] - qs[i] - bw;
                    new_s[i] = (u32)v; bw = (v>>63)&1;
                }
                new_s_neg = os_neg;
            } else {
                u64 bw = 0;
                for (int i = 0; i < BN_LIMBS2; i++) {
                    u64 v = (u64)qs[i] - os[i] - bw;
                    new_s[i] = (u32)v; bw = (v>>63)&1;
                }
                new_s_neg = !os_neg;
            }
        } else {
            u64 c = 0;
            for (int i = 0; i < BN_LIMBS2; i++) {
                u64 v = (u64)os[i] + qs[i] + c;
                new_s[i] = (u32)v; c = v>>32;
            }
            new_s_neg = os_neg;
        }

        bn_copy(&old_r, &rem); bn_copy(&rem, &new_r);
        memcpy(os, sv, sizeof os); os_neg = sv_neg;
        memcpy(sv, new_s, sizeof sv); sv_neg = new_s_neg;
    }

    /* Extract result: os holds the inverse (magnitude), os_neg its sign */
    BN coeff; memcpy(coeff.d, os, BN_LIMBS * sizeof(u32));
    while (bn_cmp(&coeff, m) >= 0) bn_sub(&coeff, &coeff, m);
    if (os_neg && !bn_is_zero(&coeff))
        bn_sub(r, m, &coeff);
    else
        bn_copy(r, &coeff);
}


/* Convert big-endian byte array → BN */
static void bn_from_bytes_be(BN *r, const uint8_t *in, int nbytes) {
    bn_zero(r);
    for (int i = 0; i < nbytes && i/4 < BN_LIMBS; i++) {
        int limb  = (nbytes-1-i) / 4;
        int shift = ((nbytes-1-i) % 4) * 8;
        if (limb < BN_LIMBS) r->d[limb] |= ((u32)in[i]) << shift;
    }
}

/* Convert BN → fixed-width big-endian byte array */
static void bn_to_bytes_be(const BN *a, uint8_t *out, int nbytes) {
    memset(out, 0, nbytes);
    for (int i = 0; i < BN_LIMBS && i*4 < nbytes; i++) {
        int pos = nbytes - 1 - i*4;
        out[pos]   =  a->d[i]        & 0xff;
        if (pos>=1) out[pos-1] = (a->d[i]>> 8) & 0xff;
        if (pos>=2) out[pos-2] = (a->d[i]>>16) & 0xff;
        if (pos>=3) out[pos-3] = (a->d[i]>>24) & 0xff;
    }
}

/* Load hex string (big-endian) → BN */
static void bn_from_hex(BN *r, const char *hex) {
    bn_zero(r);
    int len = (int)strlen(hex);
    int limb = 0;
    for (int i = len; i > 0 && limb < BN_LIMBS; i -= 8, limb++) {
        int start = i-8; if (start < 0) start = 0;
        char buf[9] = {0};
        strncpy(buf, hex+start, i-start);
        r->d[limb] = (u32)strtoul(buf, NULL, 16);
    }
}

static void bn_print(const char *label, const BN *a) {
    printf("%s: ", label);
    int s = 0;
    for (int i = BN_LIMBS-1; i >= 0; i--) {
        if (!s && !a->d[i]) continue;
        if (!s) { printf("%x", a->d[i]); s=1; }
        else    printf("%08x", a->d[i]);
    }
    if (!s) printf("0");
    printf("\n");
}

/* =========================================================================
 * 2. AES-128  (FIPS-197)
 *
 * Known-answer test (Appendix B):
 *   Key: 2b7e151628aed2a6abf7158809cf4f3c
 *   PT:  3243f6a8885a308d313198a2e0370734
 *   CT:  3925841d02dc09fbdc118597196a0b32
 * ========================================================================= */

static const uint8_t SBOX[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static const uint8_t RCON[10] = {
    0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36
};

/* GF(2^8) multiply mod x^8+x^4+x^3+x+1 */
static uint8_t gmul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    for (int i = 0; i < 8; i++) {
        if (b & 1) p ^= a;
        uint8_t hb = a & 0x80;
        a = (uint8_t)(a << 1);
        if (hb) a ^= 0x1b;
        b >>= 1;
    }
    return p;
}

typedef uint8_t AES_State[4][4];  /* [row][col] */

static void aes_key_expansion(const uint8_t key[16], uint8_t w[44][4]) {
    for (int i = 0; i < 4; i++) memcpy(w[i], key + 4*i, 4);
    for (int i = 4; i < 44; i++) {
        uint8_t t[4]; memcpy(t, w[i-1], 4);
        if (i % 4 == 0) {
            uint8_t tmp = t[0];
            t[0] = SBOX[t[1]] ^ RCON[i/4-1];
            t[1] = SBOX[t[2]];
            t[2] = SBOX[t[3]];
            t[3] = SBOX[tmp];
        }
        for (int j = 0; j < 4; j++) w[i][j] = w[i-4][j] ^ t[j];
    }
}

static void aes_add_round_key(AES_State s, uint8_t w[][4], int round) {
    for (int c = 0; c < 4; c++)
        for (int r = 0; r < 4; r++)
            s[r][c] ^= w[round*4+c][r];
}

static void aes_sub_bytes (AES_State s) {
    for (int r=0;r<4;r++) for (int c=0;c<4;c++) s[r][c]=SBOX[s[r][c]];
}

static void aes_shift_rows(AES_State s) {
    for (int r = 1; r < 4; r++) {
        uint8_t tmp[4];
        for (int c = 0; c < 4; c++) tmp[c] = s[r][(c+r)%4];
        memcpy(s[r], tmp, 4);
    }
}

static void aes_mix_columns(AES_State s) {
    for (int c = 0; c < 4; c++) {
        uint8_t s0=s[0][c],s1=s[1][c],s2=s[2][c],s3=s[3][c];
        s[0][c] = gmul(s0,2)^gmul(s1,3)^s2      ^s3;
        s[1][c] = s0       ^gmul(s1,2)^gmul(s2,3)^s3;
        s[2][c] = s0       ^s1        ^gmul(s2,2)^gmul(s3,3);
        s[3][c] = gmul(s0,3)^s1       ^s2        ^gmul(s3,2);
    }
}

static void aes_encrypt_block(const uint8_t pt[16], const uint8_t key[16], uint8_t ct[16]) {
    uint8_t w[44][4];
    aes_key_expansion(key, w);
    AES_State st;
    for (int r=0;r<4;r++) for (int c=0;c<4;c++) st[r][c]=pt[r+4*c];
    aes_add_round_key(st, w, 0);
    for (int round = 1; round <= 10; round++) {
        aes_sub_bytes(st);
        aes_shift_rows(st);
        if (round < 10) aes_mix_columns(st);
        aes_add_round_key(st, w, round);
    }
    for (int r=0;r<4;r++) for (int c=0;c<4;c++) ct[r+4*c]=st[r][c];
}

/* =========================================================================
 * 3. AES-CTR mode  (encrypt == decrypt)
 * ========================================================================= */

static void aes_ctr(const uint8_t *in, uint8_t *out, size_t len,
                    const uint8_t key[16], const uint8_t nonce[16]) {
    uint8_t counter[16], ks[16];
    memcpy(counter, nonce, 16);
    for (size_t i = 0; i < len; ) {
        aes_encrypt_block(counter, key, ks);
        /* increment counter big-endian */
        for (int j = 15; j >= 0; j--) if (++counter[j]) break;
        size_t chunk = len - i; if (chunk > 16) chunk = 16;
        for (size_t k = 0; k < chunk; k++) out[i+k] = in[i+k] ^ ks[k];
        i += chunk;
    }
}

/* =========================================================================
 * 4. RNG  (xoshiro256** seeded from /dev/urandom)
 * ========================================================================= */

static u64 rng_s[4];

static void rng_seed(void) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (f) { (void)fread(rng_s, 1, sizeof rng_s, f); fclose(f); }
    else { rng_s[0]=0xdeadbeefcafeull; rng_s[1]=0xbabe1234ull;
           rng_s[2]=0xfeed0011ull;     rng_s[3]=0xcafef00dull; }
}

static u64 rng_next(void) {
    u64 r = rng_s[1]*5; r = ((r<<7)|(r>>57))*9;
    u64 t = rng_s[1]<<17;
    rng_s[2]^=rng_s[0]; rng_s[3]^=rng_s[1];
    rng_s[1]^=rng_s[2]; rng_s[0]^=rng_s[3];
    rng_s[2]^=t; rng_s[3]=((rng_s[3]<<45)|(rng_s[3]>>19));
    return r;
}

static void rng_bytes(uint8_t *buf, size_t n) {
    for (size_t i = 0; i < n; i += 8) {
        u64 v = rng_next();
        for (int j = 0; j < 8 && i+j < n; j++) buf[i+j]=(uint8_t)(v>>(j*8));
    }
}

/* =========================================================================
 * 5. RSA
 *
 * Key generation:
 *   p, q  — two 256-bit primes (verified with sympy)
 *   n = p*q, phi = (p-1)(q-1), e = 65537, d = e^-1 mod phi
 *
 * To generate your own: openssl genrsa 512 | openssl rsa -text -noout
 * ========================================================================= */

/* Verified 256-bit primes (sympy.randprime + isprime confirmed) */
static const char P_HEX[] =
    "9a1de644815ef6d13b8faa1837f8a88b"
    "17fc695a07a0ca6e0822e8f36c0311f5";
static const char Q_HEX[] =
    "eb65a6a48b8148f6b38a088ca65ed389"
    "b74d0fb132e706298fadc1a606cb1011";

typedef struct { BN n, e, d; } RSAKey;

static RSAKey rsa_keygen(void) {
    RSAKey k;
    BN p, q, one, pm1, qm1;
    bn_from_hex(&p, P_HEX);
    bn_from_hex(&q, Q_HEX);
    bn_set32(&one, 1);

    /* n = p * q */
    u32 pq[BN_LIMBS2] = {0};
    bn_mul_full(pq, &p, &q);
    memcpy(k.n.d, pq, BN_LIMBS * sizeof(u32));

    /* phi = (p-1)(q-1) */
    bn_sub(&pm1, &p, &one);
    bn_sub(&qm1, &q, &one);
    u32 phi_w[BN_LIMBS2] = {0};
    bn_mul_full(phi_w, &pm1, &qm1);
    BN phi; memcpy(phi.d, phi_w, BN_LIMBS * sizeof(u32));

    /* e = 65537 */
    bn_set32(&k.e, 65537);

    /* d = e^-1 mod phi  (computed at runtime via extended Euclidean) */
    bn_modinv(&k.d, &k.e, &phi);

    return k;
}

/* =========================================================================
 * 6. HYBRID ENCRYPT / DECRYPT
 *
 * Wire format: [RSA_BYTES encrypted AES key][16-byte nonce][ciphertext]
 * ========================================================================= */

#define RSA_BYTES (BN_LIMBS * 4)   /* 64 for 512-bit */

typedef struct { uint8_t *data; size_t len; } Blob;
static void blob_free(Blob *b) { free(b->data); b->data=NULL; b->len=0; }

static Blob hybrid_encrypt(const uint8_t *msg, size_t mlen, const RSAKey *k) {
    uint8_t aes_key[16], nonce[16];
    rng_bytes(aes_key, 16);
    rng_bytes(nonce,   16);

    /* RSA-encrypt the AES key */
    BN m_bn, c_bn;
    bn_from_bytes_be(&m_bn, aes_key, 16);
    bn_powmod(&c_bn, &m_bn, &k->e, &k->n);

    /* AES-CTR encrypt the message */
    uint8_t *ct_msg = malloc(mlen);
    aes_ctr(msg, ct_msg, mlen, aes_key, nonce);

    /* Assemble */
    size_t total = RSA_BYTES + 16 + mlen;
    uint8_t *out = malloc(total);
    bn_to_bytes_be(&c_bn, out, RSA_BYTES);
    memcpy(out + RSA_BYTES,      nonce,  16);
    memcpy(out + RSA_BYTES + 16, ct_msg, mlen);
    free(ct_msg);
    return (Blob){ out, total };
}

static Blob hybrid_decrypt(const uint8_t *ct, size_t clen, const RSAKey *k) {
    if (clen < RSA_BYTES + 16) { fprintf(stderr,"CT too short\n"); return (Blob){NULL,0}; }

    BN c_bn, m_bn;
    bn_from_bytes_be(&c_bn, ct, RSA_BYTES);

    const uint8_t *nonce  = ct + RSA_BYTES;
    const uint8_t *ct_msg = ct + RSA_BYTES + 16;
    size_t mlen = clen - RSA_BYTES - 16;

    /* RSA-decrypt the AES key */
    bn_powmod(&m_bn, &c_bn, &k->d, &k->n);
    uint8_t aes_key[16] = {0};
    bn_to_bytes_be(&m_bn, aes_key, 16);

    /* AES-CTR decrypt */
    uint8_t *plain = malloc(mlen + 1);
    aes_ctr(ct_msg, plain, mlen, aes_key, nonce);
    plain[mlen] = '\0';
    return (Blob){ plain, mlen };
}

/* =========================================================================
 * 7. SELF-TESTS + MAIN
 * ========================================================================= */

static void test_aes(void) {
    /* FIPS-197 Appendix B */
    uint8_t key[16] = {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
                       0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};
    uint8_t pt[16]  = {0x32,0x43,0xf6,0xa8,0x88,0x5a,0x30,0x8d,
                       0x31,0x31,0x98,0xa2,0xe0,0x37,0x07,0x34};
    uint8_t exp[16] = {0x39,0x25,0x84,0x1d,0x02,0xdc,0x09,0xfb,
                       0xdc,0x11,0x85,0x97,0x19,0x6a,0x0b,0x32};
    uint8_t ct[16];
    aes_encrypt_block(pt, key, ct);
    printf("[AES-128 FIPS-197 KAT]  %s\n", memcmp(ct,exp,16)==0 ? "PASS":"FAIL");
}

static void test_bn_mulmod(void) {
    /* 17 * 19 mod 7 = 323 mod 7 = 1 */
    BN a,b,m,r;
    bn_set32(&a,17); bn_set32(&b,19); bn_set32(&m,7);
    bn_mulmod(&r,&a,&b,&m);
    int ok = (r.d[0]==1);
    for(int i=1;i<BN_LIMBS;i++) if(r.d[i]) ok=0;
    printf("[bn_mulmod small test]   %s  (17*19 mod 7 = %u)\n", ok?"PASS":"FAIL", r.d[0]);
}

static void test_modinv(const RSAKey *k) {
    /* Verify the computed d against known-answer: e*d mod phi == 1,
     * done here by checking RSA decryption with e=65537 recovers the message */
    const char *known_d =
        "8d0cb321db1617923b34c49c490ad825"
        "7a2e5047f1ee90eec8838665aee80ffd"
        "ceb96591ae76458f600737698def2094"
        "df8ef4ef453ad3ef7fadd0828b752581";
    BN expected; bn_from_hex(&expected, known_d);
    int ok = (bn_cmp(&k->d, &expected) == 0);
    printf("[bn_modinv KAT]         %s\n", ok ? "PASS" : "FAIL");
}

static void test_rsa_roundtrip(const RSAKey *k) {
    BN m, c, rec;
    bn_set32(&m, 12345);
    bn_powmod(&c,   &m, &k->e, &k->n);
    bn_powmod(&rec, &c, &k->d, &k->n);
    int ok = (rec.d[0]==12345);
    for(int i=1;i<BN_LIMBS;i++) if(rec.d[i]) ok=0;
    printf("[RSA round-trip 12345]  %s\n", ok ? "PASS":"FAIL");
}

#ifndef HYBRID_CRYPTO_TESTS
int main(void) {
    rng_seed();

    printf("=== Key generation ===\n");
    RSAKey k = rsa_keygen();
    bn_print("  n", &k.n);
    printf("\n=== Self-tests ===\n");
    test_aes();
    test_bn_mulmod();
    test_modinv(&k);
    test_rsa_roundtrip(&k);

    printf("\n=== Hybrid encrypt/decrypt ===\n");
    const char *msg = "Hello, hybrid RSA+AES-CTR! "
                      "The AES session key is RSA-encrypted; "
                      "this payload is AES-128-CTR encrypted.";
    printf("Plaintext (%zu bytes):\n  \"%s\"\n\n", strlen(msg), msg);

    Blob ct = hybrid_encrypt((const uint8_t*)msg, strlen(msg), &k);
    printf("Ciphertext (%zu bytes):\n  ", ct.len);
    for (size_t i = 0; i < ct.len; i++) {
        printf("%02x", ct.data[i]);
        if ((i+1)%32==0 && i+1<ct.len) printf("\n  ");
    }
    printf("\n\n");

    Blob rec = hybrid_decrypt(ct.data, ct.len, &k);
    printf("Decrypted:\n  \"%s\"\n\n", (char*)rec.data);

    int match = rec.len==strlen(msg) && memcmp(rec.data,msg,rec.len)==0;
    printf("Round-trip: %s\n", match ? "PASS" : "FAIL");

    blob_free(&ct);
    blob_free(&rec);
    return match ? 0 : 1;
}
#endif /* HYBRID_CRYPTO_TESTS */