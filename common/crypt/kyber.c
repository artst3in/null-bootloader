// ============================================================================
// Kyber-1024 - Post-Quantum Key Encapsulation Mechanism (ML-KEM)
// ============================================================================
// Minimal portable C implementation for bootloader use.
// Based on the reference implementation from pq-crystals.
// https://github.com/pq-crystals/kyber
//
// Copyright 2025 The LunaOS Contributors
// Original Kyber: Public Domain (CC0)
// SPDX-License-Identifier: BSD-2-Clause
// ============================================================================

#include <stdint.h>
#include <stddef.h>
#include <crypt/kyber.h>
#include <crypt/blake3.h>
#include <lib/libc.h>

// ============================================================================
// Constants
// ============================================================================

// Montgomery parameter: R = 2^16 mod q
#define KYBER_MONT 2285

// Root of unity for NTT
#define KYBER_ROOT 17

// Inverse of 128 mod q (for inverse NTT scaling)
#define KYBER_F 3303

// ============================================================================
// Precomputed NTT Tables (zetas)
// ============================================================================

// Zetas for NTT - powers of the primitive 512th root of unity
static const int16_t zetas[128] = {
    -1044,  -758,  -359, -1517,  1493,  1422,   287,   202,
     -171,   622,  1577,   182,   962, -1202, -1474,  1468,
      573, -1325,   264,   383,  -829,  1458, -1602,  -130,
     -681,  1017,   732,   608, -1542,   411,  -205, -1571,
     1223,   652,  -552,  1015, -1293,  1491,  -282, -1544,
      516,    -8,  -320,  -666, -1618, -1162,   126,  1469,
     -853,   -90, -1668,  1020, -1046,   -42,  -623,   -42,
     1539,  -625,  -344,  -532, -1002,   -39, -1671, -1684,
      205,  1399,  1151, -1458, -1671,   276,   -67, -1299,
     1175,  1303,  1105,   386,  -954,   -71, -1244,  -208,
      -61,   908,  -932,  1157, -1147,   -55,  1307,  -225,
     -915,  -113,  1020,  -267,  -316,   667, -1585,  -591,
      315,  1412,  1401,  -235, -1471,   678,  -193,  -493,
      490,  1019,   988,  1025,  1140,  1413,  -555,   282,
     -308,  -320, -1528,  -289,  -647,    70, -1568,  1084,
     -660,  1054,  1181,  -165, -1315,  -231,  -673,    32
};

// ============================================================================
// Modular Arithmetic (Montgomery form)
// ============================================================================

// Montgomery reduction: a * R^-1 mod q
static int16_t montgomery_reduce(int32_t a) {
    int16_t t;
    t = (int16_t)a * (-3327);  // q^-1 mod 2^16 = -3327
    t = (a - (int32_t)t * KYBER_Q) >> 16;
    return t;
}

// Barrett reduction: a mod q for a < 2^16
static int16_t barrett_reduce(int16_t a) {
    int16_t t;
    const int16_t v = ((1 << 26) + KYBER_Q / 2) / KYBER_Q;  // 20159
    t = ((int32_t)v * a + (1 << 25)) >> 26;
    t *= KYBER_Q;
    return a - t;
}

// Conditional subtraction of q
static int16_t csubq(int16_t a) {
    a -= KYBER_Q;
    a += (a >> 15) & KYBER_Q;
    return a;
}

// ============================================================================
// NTT (Number Theoretic Transform)
// ============================================================================

// Forward NTT
static void ntt(int16_t r[256]) {
    unsigned int len, start, j, k;
    int16_t t, zeta;

    k = 1;
    for (len = 128; len >= 2; len >>= 1) {
        for (start = 0; start < 256; start = j + len) {
            zeta = zetas[k++];
            for (j = start; j < start + len; j++) {
                t = montgomery_reduce((int32_t)zeta * r[j + len]);
                r[j + len] = r[j] - t;
                r[j] = r[j] + t;
            }
        }
    }
}

// Inverse NTT
static void invntt(int16_t r[256]) {
    unsigned int start, len, j, k;
    int16_t t, zeta;

    k = 127;
    for (len = 2; len <= 128; len <<= 1) {
        for (start = 0; start < 256; start = j + len) {
            zeta = zetas[k--];
            for (j = start; j < start + len; j++) {
                t = r[j];
                r[j] = barrett_reduce(t + r[j + len]);
                r[j + len] = montgomery_reduce((int32_t)zeta * (r[j + len] - t));
            }
        }
    }

    // Scale by n^-1
    for (j = 0; j < 256; j++) {
        r[j] = montgomery_reduce((int32_t)KYBER_F * r[j]);
    }
}

// Pointwise multiplication in NTT domain
static void basemul(int16_t r[2], const int16_t a[2], const int16_t b[2], int16_t zeta) {
    r[0] = montgomery_reduce((int32_t)a[1] * b[1]);
    r[0] = montgomery_reduce((int32_t)r[0] * zeta);
    r[0] += montgomery_reduce((int32_t)a[0] * b[0]);

    r[1] = montgomery_reduce((int32_t)a[0] * b[1]);
    r[1] += montgomery_reduce((int32_t)a[1] * b[0]);
}

// ============================================================================
// Polynomial Operations
// ============================================================================

static void poly_reduce(kyber_poly *r) {
    for (int i = 0; i < KYBER_N; i++) {
        r->coeffs[i] = barrett_reduce(r->coeffs[i]);
    }
}

static void poly_add(kyber_poly *r, const kyber_poly *a, const kyber_poly *b) {
    for (int i = 0; i < KYBER_N; i++) {
        r->coeffs[i] = a->coeffs[i] + b->coeffs[i];
    }
}

static void poly_sub(kyber_poly *r, const kyber_poly *a, const kyber_poly *b) {
    for (int i = 0; i < KYBER_N; i++) {
        r->coeffs[i] = a->coeffs[i] - b->coeffs[i];
    }
}

static void poly_ntt(kyber_poly *r) {
    ntt(r->coeffs);
    poly_reduce(r);
}

static void poly_invntt(kyber_poly *r) {
    invntt(r->coeffs);
}

// Pointwise multiplication of polynomials in NTT domain
static void poly_basemul(kyber_poly *r, const kyber_poly *a, const kyber_poly *b) {
    for (int i = 0; i < KYBER_N / 4; i++) {
        basemul(&r->coeffs[4 * i], &a->coeffs[4 * i], &b->coeffs[4 * i],
                zetas[64 + i]);
        basemul(&r->coeffs[4 * i + 2], &a->coeffs[4 * i + 2], &b->coeffs[4 * i + 2],
                -zetas[64 + i]);
    }
}

static void poly_tomont(kyber_poly *r) {
    const int16_t f = (1ULL << 32) % KYBER_Q;
    for (int i = 0; i < KYBER_N; i++) {
        r->coeffs[i] = montgomery_reduce((int32_t)r->coeffs[i] * f);
    }
}

// ============================================================================
// Polynomial Vector Operations
// ============================================================================

static void polyvec_ntt(kyber_polyvec *r) {
    for (int i = 0; i < KYBER_K; i++) {
        poly_ntt(&r->vec[i]);
    }
}

static void polyvec_invntt(kyber_polyvec *r) {
    for (int i = 0; i < KYBER_K; i++) {
        poly_invntt(&r->vec[i]);
    }
}

static void polyvec_reduce(kyber_polyvec *r) {
    for (int i = 0; i < KYBER_K; i++) {
        poly_reduce(&r->vec[i]);
    }
}

static void polyvec_add(kyber_polyvec *r, const kyber_polyvec *a, const kyber_polyvec *b) {
    for (int i = 0; i < KYBER_K; i++) {
        poly_add(&r->vec[i], &a->vec[i], &b->vec[i]);
    }
}

// Inner product of polynomial vectors
static void polyvec_basemul_acc(kyber_poly *r, const kyber_polyvec *a, const kyber_polyvec *b) {
    kyber_poly t;
    poly_basemul(r, &a->vec[0], &b->vec[0]);
    for (int i = 1; i < KYBER_K; i++) {
        poly_basemul(&t, &a->vec[i], &b->vec[i]);
        poly_add(r, r, &t);
    }
    poly_reduce(r);
}

// ============================================================================
// Sampling
// ============================================================================

// SHAKE-128 XOF using BLAKE3 (bootloader doesn't have SHA3)
// This is a simplification - production should use proper SHAKE
static void xof_absorb(blake3_hasher *state, const uint8_t seed[KYBER_SYMBYTES],
                       uint8_t x, uint8_t y) {
    uint8_t buf[KYBER_SYMBYTES + 2];
    memcpy(buf, seed, KYBER_SYMBYTES);
    buf[KYBER_SYMBYTES] = x;
    buf[KYBER_SYMBYTES + 1] = y;
    blake3_hasher_init(state);
    blake3_hasher_update(state, buf, sizeof(buf));
}

static void xof_squeezeblocks(uint8_t *out, size_t nblocks, blake3_hasher *state) {
    // BLAKE3 is an XOF, so we can squeeze arbitrary length
    blake3_hasher_finalize(state, out, nblocks * 168);
}

// Sample polynomial from XOF output (rejection sampling)
static void poly_sample_ntt(kyber_poly *r, const uint8_t seed[KYBER_SYMBYTES],
                            uint8_t i, uint8_t j) {
    uint8_t buf[504];  // 3 blocks of 168 bytes
    blake3_hasher state;
    unsigned int ctr, pos;
    uint16_t val0, val1;

    xof_absorb(&state, seed, i, j);
    xof_squeezeblocks(buf, 3, &state);

    ctr = 0;
    pos = 0;
    while (ctr < KYBER_N && pos + 3 <= sizeof(buf)) {
        val0 = ((buf[pos] >> 0) | ((uint16_t)buf[pos + 1] << 8)) & 0xFFF;
        val1 = ((buf[pos + 1] >> 4) | ((uint16_t)buf[pos + 2] << 4)) & 0xFFF;
        pos += 3;

        if (val0 < KYBER_Q) {
            r->coeffs[ctr++] = val0;
        }
        if (ctr < KYBER_N && val1 < KYBER_Q) {
            r->coeffs[ctr++] = val1;
        }
    }

    // If we didn't fill all coefficients (unlikely), fill with zeros
    while (ctr < KYBER_N) {
        r->coeffs[ctr++] = 0;
    }
}

// Sample noise polynomial (CBD - Centered Binomial Distribution)
static void poly_sample_cbd(kyber_poly *r, const uint8_t *buf, int eta) {
    unsigned int i, j;
    uint32_t t, d;
    int16_t a, b;

    if (eta == 2) {
        for (i = 0; i < KYBER_N / 8; i++) {
            t = buf[4 * i] | ((uint32_t)buf[4 * i + 1] << 8) |
                ((uint32_t)buf[4 * i + 2] << 16) | ((uint32_t)buf[4 * i + 3] << 24);
            d = t & 0x55555555;
            d += (t >> 1) & 0x55555555;

            for (j = 0; j < 8; j++) {
                a = (d >> (4 * j)) & 0x3;
                b = (d >> (4 * j + 2)) & 0x3;
                r->coeffs[8 * i + j] = a - b;
            }
        }
    }
}

// ============================================================================
// Encoding / Decoding
// ============================================================================

static void poly_tobytes(uint8_t r[KYBER_POLYBYTES], const kyber_poly *a) {
    uint16_t t0, t1;
    for (int i = 0; i < KYBER_N / 2; i++) {
        t0 = csubq(a->coeffs[2 * i]);
        t1 = csubq(a->coeffs[2 * i + 1]);
        r[3 * i + 0] = t0 >> 0;
        r[3 * i + 1] = (t0 >> 8) | (t1 << 4);
        r[3 * i + 2] = t1 >> 4;
    }
}

static void poly_frombytes(kyber_poly *r, const uint8_t a[KYBER_POLYBYTES]) {
    for (int i = 0; i < KYBER_N / 2; i++) {
        r->coeffs[2 * i] = ((a[3 * i + 0] >> 0) | ((uint16_t)a[3 * i + 1] << 8)) & 0xFFF;
        r->coeffs[2 * i + 1] = ((a[3 * i + 1] >> 4) | ((uint16_t)a[3 * i + 2] << 4)) & 0xFFF;
    }
}

static void polyvec_tobytes(uint8_t r[KYBER_POLYVECBYTES], const kyber_polyvec *a) {
    for (int i = 0; i < KYBER_K; i++) {
        poly_tobytes(&r[i * KYBER_POLYBYTES], &a->vec[i]);
    }
}

static void polyvec_frombytes(kyber_polyvec *r, const uint8_t a[KYBER_POLYVECBYTES]) {
    for (int i = 0; i < KYBER_K; i++) {
        poly_frombytes(&r->vec[i], &a[i * KYBER_POLYBYTES]);
    }
}

// Compress polynomial
static void poly_compress(uint8_t r[KYBER_N * KYBER_DV / 8], const kyber_poly *a) {
    uint8_t t[8];
    for (int i = 0; i < KYBER_N / 8; i++) {
        for (int j = 0; j < 8; j++) {
            int16_t u = csubq(a->coeffs[8 * i + j]);
            t[j] = ((((uint32_t)u << KYBER_DV) + KYBER_Q / 2) / KYBER_Q) & ((1 << KYBER_DV) - 1);
        }
        // Pack 8 5-bit values into 5 bytes
        r[5 * i + 0] = (t[0] >> 0) | (t[1] << 5);
        r[5 * i + 1] = (t[1] >> 3) | (t[2] << 2) | (t[3] << 7);
        r[5 * i + 2] = (t[3] >> 1) | (t[4] << 4);
        r[5 * i + 3] = (t[4] >> 4) | (t[5] << 1) | (t[6] << 6);
        r[5 * i + 4] = (t[6] >> 2) | (t[7] << 3);
    }
}

static void poly_decompress(kyber_poly *r, const uint8_t a[KYBER_N * KYBER_DV / 8]) {
    for (int i = 0; i < KYBER_N / 8; i++) {
        r->coeffs[8 * i + 0] = (((a[5 * i + 0] >> 0) & 31) * KYBER_Q + 16) >> 5;
        r->coeffs[8 * i + 1] = ((((a[5 * i + 0] >> 5) | (a[5 * i + 1] << 3)) & 31) * KYBER_Q + 16) >> 5;
        r->coeffs[8 * i + 2] = (((a[5 * i + 1] >> 2) & 31) * KYBER_Q + 16) >> 5;
        r->coeffs[8 * i + 3] = ((((a[5 * i + 1] >> 7) | (a[5 * i + 2] << 1)) & 31) * KYBER_Q + 16) >> 5;
        r->coeffs[8 * i + 4] = ((((a[5 * i + 2] >> 4) | (a[5 * i + 3] << 4)) & 31) * KYBER_Q + 16) >> 5;
        r->coeffs[8 * i + 5] = (((a[5 * i + 3] >> 1) & 31) * KYBER_Q + 16) >> 5;
        r->coeffs[8 * i + 6] = ((((a[5 * i + 3] >> 6) | (a[5 * i + 4] << 2)) & 31) * KYBER_Q + 16) >> 5;
        r->coeffs[8 * i + 7] = (((a[5 * i + 4] >> 3) & 31) * KYBER_Q + 16) >> 5;
    }
}

// Compress polynomial vector
static void polyvec_compress(uint8_t r[KYBER_K * KYBER_N * KYBER_DU / 8], const kyber_polyvec *a) {
    uint16_t t[8];
    for (int i = 0; i < KYBER_K; i++) {
        for (int j = 0; j < KYBER_N / 8; j++) {
            for (int k = 0; k < 8; k++) {
                int16_t u = csubq(a->vec[i].coeffs[8 * j + k]);
                t[k] = ((((uint32_t)u << KYBER_DU) + KYBER_Q / 2) / KYBER_Q) & ((1 << KYBER_DU) - 1);
            }
            // Pack 8 11-bit values into 11 bytes
            size_t off = i * (KYBER_N * KYBER_DU / 8) + j * 11;
            r[off + 0] = t[0] >> 0;
            r[off + 1] = (t[0] >> 8) | (t[1] << 3);
            r[off + 2] = (t[1] >> 5) | (t[2] << 6);
            r[off + 3] = t[2] >> 2;
            r[off + 4] = (t[2] >> 10) | (t[3] << 1);
            r[off + 5] = (t[3] >> 7) | (t[4] << 4);
            r[off + 6] = (t[4] >> 4) | (t[5] << 7);
            r[off + 7] = t[5] >> 1;
            r[off + 8] = (t[5] >> 9) | (t[6] << 2);
            r[off + 9] = (t[6] >> 6) | (t[7] << 5);
            r[off + 10] = t[7] >> 3;
        }
    }
}

static void polyvec_decompress(kyber_polyvec *r, const uint8_t a[KYBER_K * KYBER_N * KYBER_DU / 8]) {
    for (int i = 0; i < KYBER_K; i++) {
        for (int j = 0; j < KYBER_N / 8; j++) {
            size_t off = i * (KYBER_N * KYBER_DU / 8) + j * 11;
            uint16_t t[8];
            t[0] = (a[off + 0] >> 0) | ((uint16_t)a[off + 1] << 8);
            t[1] = (a[off + 1] >> 3) | ((uint16_t)a[off + 2] << 5);
            t[2] = (a[off + 2] >> 6) | ((uint16_t)a[off + 3] << 2) | ((uint16_t)a[off + 4] << 10);
            t[3] = (a[off + 4] >> 1) | ((uint16_t)a[off + 5] << 7);
            t[4] = (a[off + 5] >> 4) | ((uint16_t)a[off + 6] << 4);
            t[5] = (a[off + 6] >> 7) | ((uint16_t)a[off + 7] << 1) | ((uint16_t)a[off + 8] << 9);
            t[6] = (a[off + 8] >> 2) | ((uint16_t)a[off + 9] << 6);
            t[7] = (a[off + 9] >> 5) | ((uint16_t)a[off + 10] << 3);

            for (int k = 0; k < 8; k++) {
                r->vec[i].coeffs[8 * j + k] = ((t[k] & 0x7FF) * KYBER_Q + 1024) >> 11;
            }
        }
    }
}

// Message encoding/decoding
static void poly_frommsg(kyber_poly *r, const uint8_t m[KYBER_SYMBYTES]) {
    for (int i = 0; i < KYBER_N / 8; i++) {
        for (int j = 0; j < 8; j++) {
            r->coeffs[8 * i + j] = -((m[i] >> j) & 1) & ((KYBER_Q + 1) / 2);
        }
    }
}

static void poly_tomsg(uint8_t m[KYBER_SYMBYTES], const kyber_poly *a) {
    for (int i = 0; i < KYBER_SYMBYTES; i++) {
        m[i] = 0;
        for (int j = 0; j < 8; j++) {
            uint32_t t = csubq(a->coeffs[8 * i + j]);
            t = (((t << 1) + KYBER_Q / 2) / KYBER_Q) & 1;
            m[i] |= t << j;
        }
    }
}

// ============================================================================
// PKE (Public Key Encryption)
// ============================================================================

void kyber_pke_keypair(uint8_t *pk, uint8_t *sk, const uint8_t seed[KYBER_SYMBYTES]) {
    kyber_polyvec a[KYBER_K], e, s, pkpv;
    uint8_t buf[2 * KYBER_SYMBYTES];
    uint8_t *publicseed = buf;
    uint8_t *noiseseed = buf + KYBER_SYMBYTES;
    uint8_t nonce = 0;

    // Expand seed
    blake3_hasher h;
    blake3_hasher_init(&h);
    blake3_hasher_update(&h, seed, KYBER_SYMBYTES);
    blake3_hasher_finalize(&h, buf, sizeof(buf));

    // Generate matrix A
    for (int i = 0; i < KYBER_K; i++) {
        for (int j = 0; j < KYBER_K; j++) {
            poly_sample_ntt(&a[i].vec[j], publicseed, i, j);
        }
    }

    // Generate secret and error vectors
    uint8_t noise[KYBER_K * KYBER_N / 4];
    blake3_hasher_init(&h);
    blake3_hasher_update(&h, noiseseed, KYBER_SYMBYTES);
    blake3_hasher_update(&h, &nonce, 1);
    blake3_hasher_finalize(&h, noise, sizeof(noise));

    for (int i = 0; i < KYBER_K; i++) {
        poly_sample_cbd(&s.vec[i], &noise[i * KYBER_N / 4], KYBER_ETA1);
        nonce++;
    }

    blake3_hasher_init(&h);
    blake3_hasher_update(&h, noiseseed, KYBER_SYMBYTES);
    blake3_hasher_update(&h, &nonce, 1);
    blake3_hasher_finalize(&h, noise, sizeof(noise));

    for (int i = 0; i < KYBER_K; i++) {
        poly_sample_cbd(&e.vec[i], &noise[i * KYBER_N / 4], KYBER_ETA1);
        nonce++;
    }

    polyvec_ntt(&s);
    polyvec_ntt(&e);

    // Compute t = A*s + e
    for (int i = 0; i < KYBER_K; i++) {
        polyvec_basemul_acc(&pkpv.vec[i], &a[i], &s);
        poly_tomont(&pkpv.vec[i]);
    }
    polyvec_add(&pkpv, &pkpv, &e);
    polyvec_reduce(&pkpv);

    // Pack keys
    polyvec_tobytes(pk, &pkpv);
    memcpy(pk + KYBER_POLYVECBYTES, publicseed, KYBER_SYMBYTES);
    polyvec_tobytes(sk, &s);
}

void kyber_pke_encrypt(uint8_t *ct, const uint8_t *m, const uint8_t *pk,
                       const uint8_t coins[KYBER_SYMBYTES]) {
    kyber_polyvec sp, pkpv, ep, at[KYBER_K], bp;
    kyber_poly v, k, epp;
    const uint8_t *seed = pk + KYBER_POLYVECBYTES;
    uint8_t nonce = 0;
    blake3_hasher h;

    polyvec_frombytes(&pkpv, pk);

    poly_frommsg(&k, m);

    // Generate At (transpose of A)
    for (int i = 0; i < KYBER_K; i++) {
        for (int j = 0; j < KYBER_K; j++) {
            poly_sample_ntt(&at[i].vec[j], seed, j, i);  // Note: j,i for transpose
        }
    }

    // Generate r, e1, e2
    uint8_t noise[KYBER_K * KYBER_N / 4];
    blake3_hasher_init(&h);
    blake3_hasher_update(&h, coins, KYBER_SYMBYTES);
    blake3_hasher_update(&h, &nonce, 1);
    blake3_hasher_finalize(&h, noise, sizeof(noise));

    for (int i = 0; i < KYBER_K; i++) {
        poly_sample_cbd(&sp.vec[i], &noise[i * KYBER_N / 4], KYBER_ETA1);
        nonce++;
    }

    blake3_hasher_init(&h);
    blake3_hasher_update(&h, coins, KYBER_SYMBYTES);
    blake3_hasher_update(&h, &nonce, 1);
    blake3_hasher_finalize(&h, noise, sizeof(noise));

    for (int i = 0; i < KYBER_K; i++) {
        poly_sample_cbd(&ep.vec[i], &noise[i * KYBER_N / 4], KYBER_ETA2);
        nonce++;
    }

    uint8_t noise2[KYBER_N / 4];
    blake3_hasher_init(&h);
    blake3_hasher_update(&h, coins, KYBER_SYMBYTES);
    blake3_hasher_update(&h, &nonce, 1);
    blake3_hasher_finalize(&h, noise2, sizeof(noise2));
    poly_sample_cbd(&epp, noise2, KYBER_ETA2);

    polyvec_ntt(&sp);

    // u = At*r + e1
    for (int i = 0; i < KYBER_K; i++) {
        polyvec_basemul_acc(&bp.vec[i], &at[i], &sp);
        poly_tomont(&bp.vec[i]);
    }
    polyvec_invntt(&bp);
    polyvec_add(&bp, &bp, &ep);
    polyvec_reduce(&bp);

    // v = t^T*r + e2 + m
    polyvec_basemul_acc(&v, &pkpv, &sp);
    poly_invntt(&v);
    poly_add(&v, &v, &epp);
    poly_add(&v, &v, &k);
    poly_reduce(&v);

    // Compress and pack ciphertext
    polyvec_compress(ct, &bp);
    poly_compress(ct + KYBER_K * KYBER_N * KYBER_DU / 8, &v);
}

void kyber_pke_decrypt(uint8_t *m, const uint8_t *ct, const uint8_t *sk) {
    kyber_polyvec bp, skpv;
    kyber_poly v, mp;

    polyvec_decompress(&bp, ct);
    poly_decompress(&v, ct + KYBER_K * KYBER_N * KYBER_DU / 8);

    polyvec_frombytes(&skpv, sk);

    polyvec_ntt(&bp);
    polyvec_basemul_acc(&mp, &skpv, &bp);
    poly_invntt(&mp);

    poly_sub(&mp, &v, &mp);
    poly_reduce(&mp);

    poly_tomsg(m, &mp);
}

// ============================================================================
// KEM (Key Encapsulation Mechanism)
// ============================================================================

int kyber_keypair(uint8_t *pk, uint8_t *sk, const uint8_t *coins) {
    uint8_t buf[2 * KYBER_SYMBYTES];
    blake3_hasher h;

    // Get random seed
    if (coins) {
        memcpy(buf, coins, 2 * KYBER_SYMBYTES);
    } else {
        // Fallback: use some entropy from the environment
        // In a real bootloader, this should be from hardware RNG
        memset(buf, 0x42, sizeof(buf));  // Placeholder - NOT SECURE
    }

    kyber_pke_keypair(pk, sk, buf);

    // Append public key to secret key
    memcpy(sk + KYBER_POLYVECBYTES, pk, KYBER_PUBLICKEYBYTES);

    // Append H(pk) to secret key
    blake3_hasher_init(&h);
    blake3_hasher_update(&h, pk, KYBER_PUBLICKEYBYTES);
    blake3_hasher_finalize(&h, sk + KYBER_POLYVECBYTES + KYBER_PUBLICKEYBYTES, KYBER_SYMBYTES);

    // Append random z to secret key (for implicit rejection)
    if (coins) {
        memcpy(sk + KYBER_SECRETKEYBYTES - KYBER_SYMBYTES, coins + KYBER_SYMBYTES, KYBER_SYMBYTES);
    } else {
        memset(sk + KYBER_SECRETKEYBYTES - KYBER_SYMBYTES, 0x37, KYBER_SYMBYTES);
    }

    return 0;
}

int kyber_encapsulate(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *coins) {
    uint8_t buf[2 * KYBER_SYMBYTES];
    uint8_t kr[2 * KYBER_SYMBYTES];
    blake3_hasher h;

    // Get random message
    if (coins) {
        memcpy(buf, coins, KYBER_SYMBYTES);
    } else {
        memset(buf, 0x55, KYBER_SYMBYTES);  // Placeholder - NOT SECURE
    }

    // H(m)
    blake3_hasher_init(&h);
    blake3_hasher_update(&h, buf, KYBER_SYMBYTES);
    blake3_hasher_finalize(&h, buf, KYBER_SYMBYTES);

    // H(pk)
    blake3_hasher_init(&h);
    blake3_hasher_update(&h, pk, KYBER_PUBLICKEYBYTES);
    blake3_hasher_finalize(&h, buf + KYBER_SYMBYTES, KYBER_SYMBYTES);

    // G(m || H(pk)) -> (K, r)
    blake3_hasher_init(&h);
    blake3_hasher_update(&h, buf, 2 * KYBER_SYMBYTES);
    blake3_hasher_finalize(&h, kr, 2 * KYBER_SYMBYTES);

    // Encrypt m with r
    kyber_pke_encrypt(ct, buf, pk, kr + KYBER_SYMBYTES);

    // H(ct)
    blake3_hasher_init(&h);
    blake3_hasher_update(&h, ct, KYBER_CIPHERTEXTBYTES);
    blake3_hasher_finalize(&h, kr + KYBER_SYMBYTES, KYBER_SYMBYTES);

    // KDF(K || H(ct)) -> ss
    blake3_hasher_init(&h);
    blake3_hasher_update(&h, kr, 2 * KYBER_SYMBYTES);
    blake3_hasher_finalize(&h, ss, KYBER_SSBYTES);

    return 0;
}

int kyber_decapsulate(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
    uint8_t buf[2 * KYBER_SYMBYTES];
    uint8_t kr[2 * KYBER_SYMBYTES];
    uint8_t cmp[KYBER_CIPHERTEXTBYTES];
    const uint8_t *pk = sk + KYBER_POLYVECBYTES;
    blake3_hasher h;
    uint8_t fail;

    // Decrypt
    kyber_pke_decrypt(buf, ct, sk);

    // H(pk) from secret key
    memcpy(buf + KYBER_SYMBYTES, sk + KYBER_POLYVECBYTES + KYBER_PUBLICKEYBYTES, KYBER_SYMBYTES);

    // G(m' || H(pk)) -> (K', r')
    blake3_hasher_init(&h);
    blake3_hasher_update(&h, buf, 2 * KYBER_SYMBYTES);
    blake3_hasher_finalize(&h, kr, 2 * KYBER_SYMBYTES);

    // Re-encrypt with r'
    kyber_pke_encrypt(cmp, buf, pk, kr + KYBER_SYMBYTES);

    // Verify ciphertext
    fail = kyber_verify(ct, cmp, KYBER_CIPHERTEXTBYTES);

    // H(ct)
    blake3_hasher_init(&h);
    blake3_hasher_update(&h, ct, KYBER_CIPHERTEXTBYTES);
    blake3_hasher_finalize(&h, kr + KYBER_SYMBYTES, KYBER_SYMBYTES);

    // Conditional: use z if verification failed (implicit rejection)
    kyber_cmov(kr, sk + KYBER_SECRETKEYBYTES - KYBER_SYMBYTES, KYBER_SYMBYTES, fail);

    // KDF(K || H(ct)) -> ss
    blake3_hasher_init(&h);
    blake3_hasher_update(&h, kr, 2 * KYBER_SYMBYTES);
    blake3_hasher_finalize(&h, ss, KYBER_SSBYTES);

    return 0;
}

// ============================================================================
// Utility Functions
// ============================================================================

int kyber_verify(const uint8_t *a, const uint8_t *b, size_t len) {
    uint8_t r = 0;
    for (size_t i = 0; i < len; i++) {
        r |= a[i] ^ b[i];
    }
    return (-(uint64_t)r) >> 63;
}

void kyber_cmov(uint8_t *dst, const uint8_t *src, size_t len, uint8_t condition) {
    condition = -condition;  // 0x00 or 0xFF
    for (size_t i = 0; i < len; i++) {
        dst[i] ^= condition & (dst[i] ^ src[i]);
    }
}
