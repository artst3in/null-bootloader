// ============================================================================
// Dilithium-3 - Post-Quantum Digital Signatures (ML-DSA)
// ============================================================================
// Minimal portable C implementation for bootloader use.
// Based on the reference implementation from pq-crystals.
// https://github.com/pq-crystals/dilithium
//
// Uses SHAKE128/SHAKE256 as required by NIST FIPS 204 specification.
//
// Copyright 2025 The LunaOS Contributors
// Original Dilithium: Public Domain (CC0)
// SPDX-License-Identifier: BSD-2-Clause
// ============================================================================

#include <stdint.h>
#include <stddef.h>
#include <crypt/dilithium.h>
#include <crypt/shake.h>
#include <lib/libc.h>

// ============================================================================
// Constants
// ============================================================================

#define MONT 4193792U       // 2^32 mod Q
#define QINV 58728449U      // q^-1 mod 2^32

// ============================================================================
// NTT Tables (precomputed zetas for Dilithium)
// ============================================================================

static const int32_t zetas[DILITHIUM_N] = {
         0,    25847, -2608894,  -518909,   237124,  -777960,  -876248,   466468,
   1826347,  2353451,  -359251, -2091905,  3119733, -2884855,  3111497,  2680103,
   2725464,  1024112, -1079900,  3585928,  -549488, -1119584,  2619752, -2108549,
  -2118186, -3859737, -1399561, -3277672,  1757237,   -19422,  4010497,   280005,
   2706023,    95776,  3077325,  3530437, -1661693, -3592148, -2537516,  3915439,
  -3861115, -3043716,  3574422, -2867647,  3539968,  -300467,  2348700,  -539299,
  -1699267, -1643818,  3505694, -3821735,  3507263, -2140649, -1600420,  3699596,
    811944,   531354,   954230,  3881043,  3900724, -2556880,  2071892, -2797779,
  -3930395, -1528703, -3677745, -3041255, -1452451,  3475950,  2176455, -1585221,
  -1257611,  1939314, -4083598, -1000202, -3190144, -3157330, -3632928,   126922,
   3412210,  -983419,  2147896,  2715295, -2967645, -3693493,  -411027, -2477047,
   -671102, -1228525,   -22981, -1308169,  -381987,  1349076,  1852771, -1430430,
  -3343383,   264944,   508951,  3097992,    44288, -1100098,   904516,  3958618,
  -3724342,    -8578,  1653064, -3249728,  2389356,  -210977,   759969, -1316856,
    189548, -3553272,  3159746, -1851402, -2409325,  -177440,  1315589,  1341330,
   1285669, -1315186, -1241729, -3820907, -2114028, -2049655,   -48306, -3564486,
   3354479, -3502926,  2544682, -3037576,  -396612,  2106608,   -17504, -1720305,
  -3632428,  -497057, -1403627,  1428291,  1611063,   -80466,  -102169,  -237038,
   1192321,  -821460, -3052608,  2521819, -2119965,   652621,   878215, -1636015,
   -154548,  3475738,    64455,   432212, -1305345, -2106396, -2133815,  -992216,
  -2243340,  1265552,  3878450,  -151088,  2200466,   -38594,   420708, -3000970,
   1309290,   451097, -2014312, -2044696,   -12016,  -316461,  1962642,  2508613,
   3098264,   882282,  -579668,  -549647,  1820416, -1396062,   405178,  -819503,
   3271462,  -598494,   -36462,   -48687, -1024890,  1952655,  1969680, -1460912,
   3716946,  3143840,  -163096, -3187479,  1867633, -1401055, -1020067,  3181795,
  -1401672, -3535191,  3154746, -1950675, -1803090,  1730338,  -898719,  -869498,
   -240449, -3772899,  1315037,  3259530,  2261505,  -339629,  -621018,  2678278,
   -434397,  2962115,   -98054,  1942317,  1348842,  -628052,  1008981,  -336538,
    846711,  -684403,  2992157, -1961662, -1455995, -1022428, -1083692,  1845438,
  -1382069, -2222209,  -549199,  2998219, -1345618,   994995, -1712037,  2712289,
  -2040572,  -264610,  -674619,   315345, -3288534, -1063428,  2547417, -2511135,
  -2167565,  -754524, -1258403,  2650777,  -158337,  -222425,  -310097,   348722
};

// ============================================================================
// Modular Arithmetic
// ============================================================================

static int32_t montgomery_reduce(int64_t a) {
    int32_t t;
    t = (int32_t)((uint64_t)a * QINV);
    t = (a - (int64_t)t * DILITHIUM_Q) >> 32;
    return t;
}

static int32_t reduce32(int32_t a) {
    int32_t t;
    t = (a + (1 << 22)) >> 23;
    t = a - t * DILITHIUM_Q;
    return t;
}

static int32_t caddq(int32_t a) {
    a += (a >> 31) & DILITHIUM_Q;
    return a;
}

static int32_t freeze(int32_t a) {
    a = reduce32(a);
    a = caddq(a);
    return a;
}

// ============================================================================
// NTT Operations
// ============================================================================

void dilithium_poly_ntt(dilithium_poly *a) {
    unsigned int len, start, j, k;
    int32_t zeta, t;

    k = 0;
    for (len = 128; len > 0; len >>= 1) {
        for (start = 0; start < DILITHIUM_N; start = j + len) {
            zeta = zetas[++k];
            for (j = start; j < start + len; j++) {
                t = montgomery_reduce((int64_t)zeta * a->coeffs[j + len]);
                a->coeffs[j + len] = a->coeffs[j] - t;
                a->coeffs[j] = a->coeffs[j] + t;
            }
        }
    }
}

void dilithium_poly_invntt_tomont(dilithium_poly *a) {
    unsigned int start, len, j, k;
    int32_t t, zeta;
    const int32_t f = 41978;  // mont^2/256

    k = 256;
    for (len = 1; len < DILITHIUM_N; len <<= 1) {
        for (start = 0; start < DILITHIUM_N; start = j + len) {
            zeta = -zetas[--k];
            for (j = start; j < start + len; j++) {
                t = a->coeffs[j];
                a->coeffs[j] = t + a->coeffs[j + len];
                a->coeffs[j + len] = t - a->coeffs[j + len];
                a->coeffs[j + len] = montgomery_reduce((int64_t)zeta * a->coeffs[j + len]);
            }
        }
    }

    for (j = 0; j < DILITHIUM_N; j++) {
        a->coeffs[j] = montgomery_reduce((int64_t)f * a->coeffs[j]);
    }
}

void dilithium_poly_pointwise_montgomery(dilithium_poly *c,
                                         const dilithium_poly *a,
                                         const dilithium_poly *b) {
    for (unsigned int i = 0; i < DILITHIUM_N; i++) {
        c->coeffs[i] = montgomery_reduce((int64_t)a->coeffs[i] * b->coeffs[i]);
    }
}

// ============================================================================
// Polynomial Operations
// ============================================================================

static void poly_reduce(dilithium_poly *a) {
    for (unsigned int i = 0; i < DILITHIUM_N; i++) {
        a->coeffs[i] = reduce32(a->coeffs[i]);
    }
}

static void poly_caddq(dilithium_poly *a) {
    for (unsigned int i = 0; i < DILITHIUM_N; i++) {
        a->coeffs[i] = caddq(a->coeffs[i]);
    }
}

static void poly_add(dilithium_poly *c, const dilithium_poly *a, const dilithium_poly *b) {
    for (unsigned int i = 0; i < DILITHIUM_N; i++) {
        c->coeffs[i] = a->coeffs[i] + b->coeffs[i];
    }
}

static void poly_sub(dilithium_poly *c, const dilithium_poly *a, const dilithium_poly *b) {
    for (unsigned int i = 0; i < DILITHIUM_N; i++) {
        c->coeffs[i] = a->coeffs[i] - b->coeffs[i];
    }
}

static void poly_shiftl(dilithium_poly *a) {
    for (unsigned int i = 0; i < DILITHIUM_N; i++) {
        a->coeffs[i] <<= DILITHIUM_D;
    }
}

// ============================================================================
// Decomposition Functions
// ============================================================================

static int32_t power2round(int32_t *a0, int32_t a) {
    int32_t a1;
    a1 = (a + (1 << (DILITHIUM_D - 1)) - 1) >> DILITHIUM_D;
    *a0 = a - (a1 << DILITHIUM_D);
    return a1;
}

static int32_t decompose(int32_t *a0, int32_t a) {
    int32_t a1;
    a1 = (a + 127) >> 7;
    a1 = (a1 * 1025 + (1 << 21)) >> 22;
    a1 &= 15;

    *a0 = a - a1 * 2 * DILITHIUM_GAMMA2;
    *a0 -= (((DILITHIUM_Q - 1) / 2 - *a0) >> 31) & DILITHIUM_Q;
    return a1;
}

static unsigned int make_hint(int32_t a0, int32_t a1) {
    if (a0 > DILITHIUM_GAMMA2 || a0 < -DILITHIUM_GAMMA2 ||
        (a0 == -DILITHIUM_GAMMA2 && a1 != 0))
        return 1;
    return 0;
}

static int32_t use_hint(int32_t a, unsigned int hint) {
    int32_t a0, a1;
    a1 = decompose(&a0, a);
    if (hint == 0)
        return a1;

    if (a0 > 0)
        return (a1 + 1) & 15;
    else
        return (a1 - 1) & 15;
}

// ============================================================================
// Polynomial Power2Round and Decompose
// ============================================================================

static void poly_power2round(dilithium_poly *a1, dilithium_poly *a0, const dilithium_poly *a) {
    for (unsigned int i = 0; i < DILITHIUM_N; i++) {
        a1->coeffs[i] = power2round(&a0->coeffs[i], a->coeffs[i]);
    }
}

static void poly_decompose(dilithium_poly *a1, dilithium_poly *a0, const dilithium_poly *a) {
    for (unsigned int i = 0; i < DILITHIUM_N; i++) {
        a1->coeffs[i] = decompose(&a0->coeffs[i], a->coeffs[i]);
    }
}

static unsigned int poly_make_hint(dilithium_poly *h, const dilithium_poly *a0,
                                   const dilithium_poly *a1) {
    unsigned int s = 0;
    for (unsigned int i = 0; i < DILITHIUM_N; i++) {
        h->coeffs[i] = make_hint(a0->coeffs[i], a1->coeffs[i]);
        s += h->coeffs[i];
    }
    return s;
}

static void poly_use_hint(dilithium_poly *b, const dilithium_poly *a, const dilithium_poly *h) {
    for (unsigned int i = 0; i < DILITHIUM_N; i++) {
        b->coeffs[i] = use_hint(a->coeffs[i], h->coeffs[i]);
    }
}

// ============================================================================
// Norm Checking
// ============================================================================

static int poly_chknorm(const dilithium_poly *a, int32_t B) {
    int32_t t;
    for (unsigned int i = 0; i < DILITHIUM_N; i++) {
        t = a->coeffs[i] >> 31;
        t = a->coeffs[i] - (t & 2 * a->coeffs[i]);
        if (t >= B)
            return 1;
    }
    return 0;
}

// ============================================================================
// Packing Functions
// ============================================================================

static void polyt1_pack(uint8_t *r, const dilithium_poly *a) {
    for (unsigned int i = 0; i < DILITHIUM_N / 4; i++) {
        r[5 * i + 0] = (a->coeffs[4 * i + 0] >> 0);
        r[5 * i + 1] = (a->coeffs[4 * i + 0] >> 8) | (a->coeffs[4 * i + 1] << 2);
        r[5 * i + 2] = (a->coeffs[4 * i + 1] >> 6) | (a->coeffs[4 * i + 2] << 4);
        r[5 * i + 3] = (a->coeffs[4 * i + 2] >> 4) | (a->coeffs[4 * i + 3] << 6);
        r[5 * i + 4] = (a->coeffs[4 * i + 3] >> 2);
    }
}

static void polyt1_unpack(dilithium_poly *r, const uint8_t *a) {
    for (unsigned int i = 0; i < DILITHIUM_N / 4; i++) {
        r->coeffs[4 * i + 0] = ((a[5 * i + 0] >> 0) | ((uint32_t)a[5 * i + 1] << 8)) & 0x3FF;
        r->coeffs[4 * i + 1] = ((a[5 * i + 1] >> 2) | ((uint32_t)a[5 * i + 2] << 6)) & 0x3FF;
        r->coeffs[4 * i + 2] = ((a[5 * i + 2] >> 4) | ((uint32_t)a[5 * i + 3] << 4)) & 0x3FF;
        r->coeffs[4 * i + 3] = ((a[5 * i + 3] >> 6) | ((uint32_t)a[5 * i + 4] << 2)) & 0x3FF;
    }
}

static void polyt0_pack(uint8_t *r, const dilithium_poly *a) {
    uint32_t t[8];
    for (unsigned int i = 0; i < DILITHIUM_N / 8; i++) {
        t[0] = (1 << (DILITHIUM_D - 1)) - a->coeffs[8 * i + 0];
        t[1] = (1 << (DILITHIUM_D - 1)) - a->coeffs[8 * i + 1];
        t[2] = (1 << (DILITHIUM_D - 1)) - a->coeffs[8 * i + 2];
        t[3] = (1 << (DILITHIUM_D - 1)) - a->coeffs[8 * i + 3];
        t[4] = (1 << (DILITHIUM_D - 1)) - a->coeffs[8 * i + 4];
        t[5] = (1 << (DILITHIUM_D - 1)) - a->coeffs[8 * i + 5];
        t[6] = (1 << (DILITHIUM_D - 1)) - a->coeffs[8 * i + 6];
        t[7] = (1 << (DILITHIUM_D - 1)) - a->coeffs[8 * i + 7];

        r[13 * i + 0] = t[0];
        r[13 * i + 1] = t[0] >> 8;
        r[13 * i + 1] |= t[1] << 5;
        r[13 * i + 2] = t[1] >> 3;
        r[13 * i + 3] = t[1] >> 11;
        r[13 * i + 3] |= t[2] << 2;
        r[13 * i + 4] = t[2] >> 6;
        r[13 * i + 4] |= t[3] << 7;
        r[13 * i + 5] = t[3] >> 1;
        r[13 * i + 6] = t[3] >> 9;
        r[13 * i + 6] |= t[4] << 4;
        r[13 * i + 7] = t[4] >> 4;
        r[13 * i + 8] = t[4] >> 12;
        r[13 * i + 8] |= t[5] << 1;
        r[13 * i + 9] = t[5] >> 7;
        r[13 * i + 9] |= t[6] << 6;
        r[13 * i + 10] = t[6] >> 2;
        r[13 * i + 11] = t[6] >> 10;
        r[13 * i + 11] |= t[7] << 3;
        r[13 * i + 12] = t[7] >> 5;
    }
}

static void polyt0_unpack(dilithium_poly *r, const uint8_t *a) {
    for (unsigned int i = 0; i < DILITHIUM_N / 8; i++) {
        r->coeffs[8 * i + 0] = a[13 * i + 0];
        r->coeffs[8 * i + 0] |= (uint32_t)a[13 * i + 1] << 8;
        r->coeffs[8 * i + 0] &= 0x1FFF;

        r->coeffs[8 * i + 1] = a[13 * i + 1] >> 5;
        r->coeffs[8 * i + 1] |= (uint32_t)a[13 * i + 2] << 3;
        r->coeffs[8 * i + 1] |= (uint32_t)a[13 * i + 3] << 11;
        r->coeffs[8 * i + 1] &= 0x1FFF;

        r->coeffs[8 * i + 2] = a[13 * i + 3] >> 2;
        r->coeffs[8 * i + 2] |= (uint32_t)a[13 * i + 4] << 6;
        r->coeffs[8 * i + 2] &= 0x1FFF;

        r->coeffs[8 * i + 3] = a[13 * i + 4] >> 7;
        r->coeffs[8 * i + 3] |= (uint32_t)a[13 * i + 5] << 1;
        r->coeffs[8 * i + 3] |= (uint32_t)a[13 * i + 6] << 9;
        r->coeffs[8 * i + 3] &= 0x1FFF;

        r->coeffs[8 * i + 4] = a[13 * i + 6] >> 4;
        r->coeffs[8 * i + 4] |= (uint32_t)a[13 * i + 7] << 4;
        r->coeffs[8 * i + 4] |= (uint32_t)a[13 * i + 8] << 12;
        r->coeffs[8 * i + 4] &= 0x1FFF;

        r->coeffs[8 * i + 5] = a[13 * i + 8] >> 1;
        r->coeffs[8 * i + 5] |= (uint32_t)a[13 * i + 9] << 7;
        r->coeffs[8 * i + 5] &= 0x1FFF;

        r->coeffs[8 * i + 6] = a[13 * i + 9] >> 6;
        r->coeffs[8 * i + 6] |= (uint32_t)a[13 * i + 10] << 2;
        r->coeffs[8 * i + 6] |= (uint32_t)a[13 * i + 11] << 10;
        r->coeffs[8 * i + 6] &= 0x1FFF;

        r->coeffs[8 * i + 7] = a[13 * i + 11] >> 3;
        r->coeffs[8 * i + 7] |= (uint32_t)a[13 * i + 12] << 5;
        r->coeffs[8 * i + 7] &= 0x1FFF;

        for (int j = 0; j < 8; j++) {
            r->coeffs[8 * i + j] = (1 << (DILITHIUM_D - 1)) - r->coeffs[8 * i + j];
        }
    }
}

static void polyeta_pack(uint8_t *r, const dilithium_poly *a) {
    uint8_t t[8];
    for (unsigned int i = 0; i < DILITHIUM_N / 8; i++) {
        t[0] = DILITHIUM_ETA - a->coeffs[8 * i + 0];
        t[1] = DILITHIUM_ETA - a->coeffs[8 * i + 1];
        t[2] = DILITHIUM_ETA - a->coeffs[8 * i + 2];
        t[3] = DILITHIUM_ETA - a->coeffs[8 * i + 3];
        t[4] = DILITHIUM_ETA - a->coeffs[8 * i + 4];
        t[5] = DILITHIUM_ETA - a->coeffs[8 * i + 5];
        t[6] = DILITHIUM_ETA - a->coeffs[8 * i + 6];
        t[7] = DILITHIUM_ETA - a->coeffs[8 * i + 7];

        r[4 * i + 0] = (t[0] >> 0) | (t[1] << 4);
        r[4 * i + 1] = (t[2] >> 0) | (t[3] << 4);
        r[4 * i + 2] = (t[4] >> 0) | (t[5] << 4);
        r[4 * i + 3] = (t[6] >> 0) | (t[7] << 4);
    }
}

static void polyeta_unpack(dilithium_poly *r, const uint8_t *a) {
    for (unsigned int i = 0; i < DILITHIUM_N / 8; i++) {
        r->coeffs[8 * i + 0] = (a[4 * i + 0] >> 0) & 0x0F;
        r->coeffs[8 * i + 1] = (a[4 * i + 0] >> 4) & 0x0F;
        r->coeffs[8 * i + 2] = (a[4 * i + 1] >> 0) & 0x0F;
        r->coeffs[8 * i + 3] = (a[4 * i + 1] >> 4) & 0x0F;
        r->coeffs[8 * i + 4] = (a[4 * i + 2] >> 0) & 0x0F;
        r->coeffs[8 * i + 5] = (a[4 * i + 2] >> 4) & 0x0F;
        r->coeffs[8 * i + 6] = (a[4 * i + 3] >> 0) & 0x0F;
        r->coeffs[8 * i + 7] = (a[4 * i + 3] >> 4) & 0x0F;

        r->coeffs[8 * i + 0] = DILITHIUM_ETA - r->coeffs[8 * i + 0];
        r->coeffs[8 * i + 1] = DILITHIUM_ETA - r->coeffs[8 * i + 1];
        r->coeffs[8 * i + 2] = DILITHIUM_ETA - r->coeffs[8 * i + 2];
        r->coeffs[8 * i + 3] = DILITHIUM_ETA - r->coeffs[8 * i + 3];
        r->coeffs[8 * i + 4] = DILITHIUM_ETA - r->coeffs[8 * i + 4];
        r->coeffs[8 * i + 5] = DILITHIUM_ETA - r->coeffs[8 * i + 5];
        r->coeffs[8 * i + 6] = DILITHIUM_ETA - r->coeffs[8 * i + 6];
        r->coeffs[8 * i + 7] = DILITHIUM_ETA - r->coeffs[8 * i + 7];
    }
}

static void polyz_pack(uint8_t *r, const dilithium_poly *a) {
    uint32_t t[4];
    for (unsigned int i = 0; i < DILITHIUM_N / 2; i++) {
        t[0] = DILITHIUM_GAMMA1 - a->coeffs[2 * i + 0];
        t[1] = DILITHIUM_GAMMA1 - a->coeffs[2 * i + 1];

        r[5 * i + 0] = t[0];
        r[5 * i + 1] = t[0] >> 8;
        r[5 * i + 2] = t[0] >> 16;
        r[5 * i + 2] |= t[1] << 4;
        r[5 * i + 3] = t[1] >> 4;
        r[5 * i + 4] = t[1] >> 12;
    }
}

static void polyz_unpack(dilithium_poly *r, const uint8_t *a) {
    for (unsigned int i = 0; i < DILITHIUM_N / 2; i++) {
        r->coeffs[2 * i + 0] = a[5 * i + 0];
        r->coeffs[2 * i + 0] |= (uint32_t)a[5 * i + 1] << 8;
        r->coeffs[2 * i + 0] |= (uint32_t)a[5 * i + 2] << 16;
        r->coeffs[2 * i + 0] &= 0xFFFFF;

        r->coeffs[2 * i + 1] = a[5 * i + 2] >> 4;
        r->coeffs[2 * i + 1] |= (uint32_t)a[5 * i + 3] << 4;
        r->coeffs[2 * i + 1] |= (uint32_t)a[5 * i + 4] << 12;

        r->coeffs[2 * i + 0] = DILITHIUM_GAMMA1 - r->coeffs[2 * i + 0];
        r->coeffs[2 * i + 1] = DILITHIUM_GAMMA1 - r->coeffs[2 * i + 1];
    }
}

static void polyw1_pack(uint8_t *r, const dilithium_poly *a) {
    for (unsigned int i = 0; i < DILITHIUM_N / 2; i++) {
        r[i] = a->coeffs[2 * i + 0] | (a->coeffs[2 * i + 1] << 4);
    }
}

// ============================================================================
// Vector Packing
// ============================================================================

void dilithium_pack_pk(uint8_t *pk, const uint8_t rho[DILITHIUM_SEEDBYTES],
                       const dilithium_polyveck *t1) {
    memcpy(pk, rho, DILITHIUM_SEEDBYTES);
    for (unsigned int i = 0; i < DILITHIUM_K; i++) {
        polyt1_pack(pk + DILITHIUM_SEEDBYTES + i * DILITHIUM_POLYT1_PACKEDBYTES, &t1->vec[i]);
    }
}

void dilithium_unpack_pk(uint8_t rho[DILITHIUM_SEEDBYTES], dilithium_polyveck *t1,
                         const uint8_t *pk) {
    memcpy(rho, pk, DILITHIUM_SEEDBYTES);
    for (unsigned int i = 0; i < DILITHIUM_K; i++) {
        polyt1_unpack(&t1->vec[i], pk + DILITHIUM_SEEDBYTES + i * DILITHIUM_POLYT1_PACKEDBYTES);
    }
}

void dilithium_pack_sk(uint8_t *sk, const uint8_t rho[DILITHIUM_SEEDBYTES],
                       const uint8_t tr[DILITHIUM_TRBYTES],
                       const uint8_t key[DILITHIUM_SEEDBYTES],
                       const dilithium_polyveck *t0,
                       const dilithium_polyvecl *s1,
                       const dilithium_polyveck *s2) {
    unsigned int off = 0;

    memcpy(sk + off, rho, DILITHIUM_SEEDBYTES);
    off += DILITHIUM_SEEDBYTES;

    memcpy(sk + off, key, DILITHIUM_SEEDBYTES);
    off += DILITHIUM_SEEDBYTES;

    memcpy(sk + off, tr, DILITHIUM_TRBYTES);
    off += DILITHIUM_TRBYTES;

    for (unsigned int i = 0; i < DILITHIUM_L; i++) {
        polyeta_pack(sk + off, &s1->vec[i]);
        off += DILITHIUM_POLYETA_PACKEDBYTES;
    }

    for (unsigned int i = 0; i < DILITHIUM_K; i++) {
        polyeta_pack(sk + off, &s2->vec[i]);
        off += DILITHIUM_POLYETA_PACKEDBYTES;
    }

    for (unsigned int i = 0; i < DILITHIUM_K; i++) {
        polyt0_pack(sk + off, &t0->vec[i]);
        off += DILITHIUM_POLYT0_PACKEDBYTES;
    }
}

void dilithium_unpack_sk(uint8_t rho[DILITHIUM_SEEDBYTES],
                         uint8_t tr[DILITHIUM_TRBYTES],
                         uint8_t key[DILITHIUM_SEEDBYTES],
                         dilithium_polyveck *t0,
                         dilithium_polyvecl *s1,
                         dilithium_polyveck *s2,
                         const uint8_t *sk) {
    unsigned int off = 0;

    memcpy(rho, sk + off, DILITHIUM_SEEDBYTES);
    off += DILITHIUM_SEEDBYTES;

    memcpy(key, sk + off, DILITHIUM_SEEDBYTES);
    off += DILITHIUM_SEEDBYTES;

    memcpy(tr, sk + off, DILITHIUM_TRBYTES);
    off += DILITHIUM_TRBYTES;

    for (unsigned int i = 0; i < DILITHIUM_L; i++) {
        polyeta_unpack(&s1->vec[i], sk + off);
        off += DILITHIUM_POLYETA_PACKEDBYTES;
    }

    for (unsigned int i = 0; i < DILITHIUM_K; i++) {
        polyeta_unpack(&s2->vec[i], sk + off);
        off += DILITHIUM_POLYETA_PACKEDBYTES;
    }

    for (unsigned int i = 0; i < DILITHIUM_K; i++) {
        polyt0_unpack(&t0->vec[i], sk + off);
        off += DILITHIUM_POLYT0_PACKEDBYTES;
    }
}

// ============================================================================
// Signature Packing
// ============================================================================

static void pack_sig(uint8_t *sig, const uint8_t c[DILITHIUM_SEEDBYTES],
                     const dilithium_polyvecl *z, const dilithium_polyveck *h) {
    unsigned int off = 0, k;

    memcpy(sig, c, DILITHIUM_SEEDBYTES);
    off += DILITHIUM_SEEDBYTES;

    for (unsigned int i = 0; i < DILITHIUM_L; i++) {
        polyz_pack(sig + off, &z->vec[i]);
        off += DILITHIUM_POLYZ_PACKEDBYTES;
    }

    // Encode h
    k = 0;
    for (unsigned int i = 0; i < DILITHIUM_K; i++) {
        for (unsigned int j = 0; j < DILITHIUM_N; j++) {
            if (h->vec[i].coeffs[j] != 0) {
                sig[off + k++] = j;
            }
        }
        sig[off + DILITHIUM_OMEGA + i] = k;
    }
    while (k < DILITHIUM_OMEGA) {
        sig[off + k++] = 0;
    }
}

static int unpack_sig(uint8_t c[DILITHIUM_SEEDBYTES], dilithium_polyvecl *z,
                      dilithium_polyveck *h, const uint8_t *sig) {
    unsigned int off = 0, k;

    memcpy(c, sig, DILITHIUM_SEEDBYTES);
    off += DILITHIUM_SEEDBYTES;

    for (unsigned int i = 0; i < DILITHIUM_L; i++) {
        polyz_unpack(&z->vec[i], sig + off);
        off += DILITHIUM_POLYZ_PACKEDBYTES;
    }

    // Decode h
    k = 0;
    for (unsigned int i = 0; i < DILITHIUM_K; i++) {
        for (unsigned int j = 0; j < DILITHIUM_N; j++) {
            h->vec[i].coeffs[j] = 0;
        }

        if (sig[off + DILITHIUM_OMEGA + i] < k ||
            sig[off + DILITHIUM_OMEGA + i] > DILITHIUM_OMEGA) {
            return 1;
        }

        for (unsigned int j = k; j < sig[off + DILITHIUM_OMEGA + i]; j++) {
            if (j > k && sig[off + j] <= sig[off + j - 1])
                return 1;
            h->vec[i].coeffs[sig[off + j]] = 1;
        }

        k = sig[off + DILITHIUM_OMEGA + i];
    }

    for (unsigned int j = k; j < DILITHIUM_OMEGA; j++) {
        if (sig[off + j])
            return 1;
    }

    return 0;
}

// ============================================================================
// Sampling Functions (using SHAKE as required by NIST spec)
// ============================================================================

// Number of blocks to initially squeeze for rejection sampling
#define POLY_UNIFORM_NBLOCKS ((768 + SHAKE128_RATE - 1) / SHAKE128_RATE)

static void poly_uniform(dilithium_poly *a, const uint8_t seed[DILITHIUM_SEEDBYTES],
                         uint16_t nonce) {
    uint8_t buf[POLY_UNIFORM_NBLOCKS * SHAKE128_RATE + 2];
    shake128_ctx state;
    unsigned int ctr, pos, buflen;

    // Initialize SHAKE128 with seed || nonce
    shake128_absorb_once(&state, seed, DILITHIUM_SEEDBYTES, nonce);

    // Initial squeeze
    buflen = POLY_UNIFORM_NBLOCKS * SHAKE128_RATE;
    shake128_squeeze(&state, buf, buflen);

    ctr = 0;
    pos = 0;
    while (ctr < DILITHIUM_N && pos + 3 <= buflen) {
        uint32_t t = buf[pos++];
        t |= (uint32_t)buf[pos++] << 8;
        t |= (uint32_t)buf[pos++] << 16;
        t &= 0x7FFFFF;

        if (t < DILITHIUM_Q) {
            a->coeffs[ctr++] = t;
        }
    }

    // Rare: need more samples (rejection sampling)
    while (ctr < DILITHIUM_N) {
        shake128_squeeze(&state, buf, SHAKE128_RATE);
        pos = 0;
        while (ctr < DILITHIUM_N && pos + 3 <= SHAKE128_RATE) {
            uint32_t t = buf[pos++];
            t |= (uint32_t)buf[pos++] << 8;
            t |= (uint32_t)buf[pos++] << 16;
            t &= 0x7FFFFF;

            if (t < DILITHIUM_Q) {
                a->coeffs[ctr++] = t;
            }
        }
    }
}

// Rejection bound for eta=4 sampling
#define POLY_UNIFORM_ETA_NBLOCKS ((136 + SHAKE256_RATE - 1) / SHAKE256_RATE)

static void poly_uniform_eta(dilithium_poly *a, const uint8_t seed[DILITHIUM_CRHBYTES],
                             uint16_t nonce) {
    uint8_t buf[POLY_UNIFORM_ETA_NBLOCKS * SHAKE256_RATE];
    shake256_ctx state;
    unsigned int ctr, pos;

    // Initialize SHAKE256 with seed || nonce
    shake256_absorb_once(&state, seed, DILITHIUM_CRHBYTES, nonce);
    shake256_squeeze(&state, buf, sizeof(buf));

    ctr = 0;
    pos = 0;

    // Rejection sampling for coefficients in [-eta, eta]
    while (ctr < DILITHIUM_N) {
        uint32_t t0 = buf[pos] & 0x0F;
        uint32_t t1 = buf[pos++] >> 4;

        if (t0 < 9) {
            a->coeffs[ctr++] = 4 - t0;  // eta=4, so range is [0,8] -> [-4,4]
        }
        if (t1 < 9 && ctr < DILITHIUM_N) {
            a->coeffs[ctr++] = 4 - t1;
        }

        if (pos >= sizeof(buf) && ctr < DILITHIUM_N) {
            shake256_squeeze(&state, buf, sizeof(buf));
            pos = 0;
        }
    }
}

static void poly_uniform_gamma1(dilithium_poly *a, const uint8_t seed[DILITHIUM_CRHBYTES],
                                uint16_t nonce) {
    uint8_t buf[DILITHIUM_POLYZ_PACKEDBYTES];
    shake256_ctx state;

    // Initialize SHAKE256 with seed || nonce
    shake256_absorb_once(&state, seed, DILITHIUM_CRHBYTES, nonce);
    shake256_squeeze(&state, buf, sizeof(buf));

    polyz_unpack(a, buf);
}

// ============================================================================
// Challenge Polynomial
// ============================================================================

static void poly_challenge(dilithium_poly *c, const uint8_t seed[DILITHIUM_SEEDBYTES]) {
    uint8_t buf[SHAKE256_RATE];
    shake256_ctx state;
    uint64_t signs;
    unsigned int pos, b;

    // Use SHAKE256 to expand the seed
    shake256_init(&state);
    shake256_absorb(&state, seed, DILITHIUM_SEEDBYTES);
    shake256_finalize(&state);
    shake256_squeeze(&state, buf, sizeof(buf));

    signs = 0;
    for (unsigned int i = 0; i < 8; i++) {
        signs |= (uint64_t)buf[i] << (8 * i);
    }

    for (unsigned int i = 0; i < DILITHIUM_N; i++) {
        c->coeffs[i] = 0;
    }

    pos = 8;
    for (unsigned int i = DILITHIUM_N - DILITHIUM_TAU; i < DILITHIUM_N; i++) {
        do {
            if (pos >= sizeof(buf)) {
                shake256_squeeze(&state, buf, sizeof(buf));
                pos = 0;
            }
            b = buf[pos++];
        } while (b > i);

        c->coeffs[i] = c->coeffs[b];
        c->coeffs[b] = 1 - 2 * (signs & 1);
        signs >>= 1;
    }
}

// ============================================================================
// Vector Operations
// ============================================================================

static void polyvec_matrix_expand(dilithium_polyveck mat[DILITHIUM_L],
                                  const uint8_t rho[DILITHIUM_SEEDBYTES]) {
    for (unsigned int i = 0; i < DILITHIUM_K; i++) {
        for (unsigned int j = 0; j < DILITHIUM_L; j++) {
            poly_uniform(&mat[j].vec[i], rho, (i << 8) + j);
        }
    }
}

static void polyvecl_uniform_eta(dilithium_polyvecl *v, const uint8_t seed[DILITHIUM_CRHBYTES],
                                 uint16_t nonce) {
    for (unsigned int i = 0; i < DILITHIUM_L; i++) {
        poly_uniform_eta(&v->vec[i], seed, nonce++);
    }
}

static void polyveck_uniform_eta(dilithium_polyveck *v, const uint8_t seed[DILITHIUM_CRHBYTES],
                                 uint16_t nonce) {
    for (unsigned int i = 0; i < DILITHIUM_K; i++) {
        poly_uniform_eta(&v->vec[i], seed, nonce++);
    }
}

static void polyvecl_uniform_gamma1(dilithium_polyvecl *v, const uint8_t seed[DILITHIUM_CRHBYTES],
                                    uint16_t nonce) {
    for (unsigned int i = 0; i < DILITHIUM_L; i++) {
        poly_uniform_gamma1(&v->vec[i], seed, DILITHIUM_L * nonce + i);
    }
}

static void polyvecl_ntt(dilithium_polyvecl *v) {
    for (unsigned int i = 0; i < DILITHIUM_L; i++) {
        dilithium_poly_ntt(&v->vec[i]);
    }
}

static void polyveck_ntt(dilithium_polyveck *v) {
    for (unsigned int i = 0; i < DILITHIUM_K; i++) {
        dilithium_poly_ntt(&v->vec[i]);
    }
}

static void polyvecl_invntt_tomont(dilithium_polyvecl *v) {
    for (unsigned int i = 0; i < DILITHIUM_L; i++) {
        dilithium_poly_invntt_tomont(&v->vec[i]);
    }
}

static void polyveck_invntt_tomont(dilithium_polyveck *v) {
    for (unsigned int i = 0; i < DILITHIUM_K; i++) {
        dilithium_poly_invntt_tomont(&v->vec[i]);
    }
}

static void polyveck_add(dilithium_polyveck *w, const dilithium_polyveck *u,
                         const dilithium_polyveck *v) {
    for (unsigned int i = 0; i < DILITHIUM_K; i++) {
        poly_add(&w->vec[i], &u->vec[i], &v->vec[i]);
    }
}

static void polyveck_sub(dilithium_polyveck *w, const dilithium_polyveck *u,
                         const dilithium_polyveck *v) {
    for (unsigned int i = 0; i < DILITHIUM_K; i++) {
        poly_sub(&w->vec[i], &u->vec[i], &v->vec[i]);
    }
}

static void polyveck_shiftl(dilithium_polyveck *v) {
    for (unsigned int i = 0; i < DILITHIUM_K; i++) {
        poly_shiftl(&v->vec[i]);
    }
}

static void polyveck_reduce(dilithium_polyveck *v) {
    for (unsigned int i = 0; i < DILITHIUM_K; i++) {
        poly_reduce(&v->vec[i]);
    }
}

static void polyveck_caddq(dilithium_polyveck *v) {
    for (unsigned int i = 0; i < DILITHIUM_K; i++) {
        poly_caddq(&v->vec[i]);
    }
}

static void polyveck_power2round(dilithium_polyveck *v1, dilithium_polyveck *v0,
                                 const dilithium_polyveck *v) {
    for (unsigned int i = 0; i < DILITHIUM_K; i++) {
        poly_power2round(&v1->vec[i], &v0->vec[i], &v->vec[i]);
    }
}

static void polyveck_decompose(dilithium_polyveck *v1, dilithium_polyveck *v0,
                               const dilithium_polyveck *v) {
    for (unsigned int i = 0; i < DILITHIUM_K; i++) {
        poly_decompose(&v1->vec[i], &v0->vec[i], &v->vec[i]);
    }
}

static unsigned int polyveck_make_hint(dilithium_polyveck *h, const dilithium_polyveck *v0,
                                       const dilithium_polyveck *v1) {
    unsigned int s = 0;
    for (unsigned int i = 0; i < DILITHIUM_K; i++) {
        s += poly_make_hint(&h->vec[i], &v0->vec[i], &v1->vec[i]);
    }
    return s;
}

static void polyveck_use_hint(dilithium_polyveck *w, const dilithium_polyveck *u,
                              const dilithium_polyveck *h) {
    for (unsigned int i = 0; i < DILITHIUM_K; i++) {
        poly_use_hint(&w->vec[i], &u->vec[i], &h->vec[i]);
    }
}

static void polyveck_pack_w1(uint8_t *r, const dilithium_polyveck *w1) {
    for (unsigned int i = 0; i < DILITHIUM_K; i++) {
        polyw1_pack(r + i * DILITHIUM_POLYW1_PACKEDBYTES, &w1->vec[i]);
    }
}

static int polyvecl_chknorm(const dilithium_polyvecl *v, int32_t B) {
    for (unsigned int i = 0; i < DILITHIUM_L; i++) {
        if (poly_chknorm(&v->vec[i], B))
            return 1;
    }
    return 0;
}

static int polyveck_chknorm(const dilithium_polyveck *v, int32_t B) {
    for (unsigned int i = 0; i < DILITHIUM_K; i++) {
        if (poly_chknorm(&v->vec[i], B))
            return 1;
    }
    return 0;
}

// Matrix-vector multiplication
static void polyvec_matrix_pointwise_montgomery(dilithium_polyveck *t,
                                                const dilithium_polyveck mat[DILITHIUM_L],
                                                const dilithium_polyvecl *v) {
    for (unsigned int i = 0; i < DILITHIUM_K; i++) {
        dilithium_poly_pointwise_montgomery(&t->vec[i], &mat[0].vec[i], &v->vec[0]);
        for (unsigned int j = 1; j < DILITHIUM_L; j++) {
            dilithium_poly tmp;
            dilithium_poly_pointwise_montgomery(&tmp, &mat[j].vec[i], &v->vec[j]);
            poly_add(&t->vec[i], &t->vec[i], &tmp);
        }
    }
}

// ============================================================================
// Key Generation
// ============================================================================

int dilithium_keypair(uint8_t *pk, uint8_t *sk, const uint8_t *seed) {
    uint8_t seedbuf[2 * DILITHIUM_SEEDBYTES + DILITHIUM_CRHBYTES];
    uint8_t *rho, *rhoprime, *key;
    dilithium_polyveck mat[DILITHIUM_L];
    dilithium_polyvecl s1, s1hat;
    dilithium_polyveck s2, t1, t0;

    if (seed) {
        memcpy(seedbuf, seed, DILITHIUM_SEEDBYTES);
    } else {
        memset(seedbuf, 0x42, DILITHIUM_SEEDBYTES);  // Placeholder
    }

    // Expand seed using SHAKE256
    shake256(seedbuf, sizeof(seedbuf), seedbuf, DILITHIUM_SEEDBYTES);

    rho = seedbuf;
    rhoprime = rho + DILITHIUM_SEEDBYTES;
    key = rhoprime + DILITHIUM_CRHBYTES;

    // Expand matrix
    polyvec_matrix_expand(mat, rho);

    // Sample short vectors s1, s2
    polyvecl_uniform_eta(&s1, rhoprime, 0);
    polyveck_uniform_eta(&s2, rhoprime, DILITHIUM_L);

    // s1hat = NTT(s1)
    s1hat = s1;
    polyvecl_ntt(&s1hat);

    // t = A*s1 + s2
    polyvec_matrix_pointwise_montgomery(&t1, mat, &s1hat);
    polyveck_reduce(&t1);
    polyveck_invntt_tomont(&t1);
    polyveck_add(&t1, &t1, &s2);
    polyveck_caddq(&t1);

    // t1, t0 = Power2Round(t)
    polyveck_power2round(&t1, &t0, &t1);

    // Pack public key
    dilithium_pack_pk(pk, rho, &t1);

    // Compute tr = H(pk) using SHAKE256
    uint8_t tr[DILITHIUM_TRBYTES];
    shake256(tr, DILITHIUM_TRBYTES, pk, DILITHIUM_PUBLICKEYBYTES);

    // Pack secret key
    dilithium_pack_sk(sk, rho, tr, key, &t0, &s1, &s2);

    return 0;
}

// ============================================================================
// Signing
// ============================================================================

int dilithium_sign(uint8_t *sig, size_t *siglen,
                   const uint8_t *m, size_t mlen,
                   const uint8_t *sk) {
    uint8_t seedbuf[3 * DILITHIUM_SEEDBYTES + 2 * DILITHIUM_CRHBYTES];
    uint8_t *rho, *tr, *key, *mu, *rhoprime;
    uint16_t nonce = 0;
    dilithium_polyveck mat[DILITHIUM_L], s2, t0;
    dilithium_polyvecl s1, y, z;
    dilithium_polyveck w1, w0, h;
    dilithium_poly cp;
    shake256_ctx state;

    rho = seedbuf;
    tr = rho + DILITHIUM_SEEDBYTES;
    key = tr + DILITHIUM_TRBYTES;
    mu = key + DILITHIUM_SEEDBYTES;
    rhoprime = mu + DILITHIUM_CRHBYTES;

    dilithium_unpack_sk(rho, tr, key, &t0, &s1, &s2, sk);

    // Compute mu = H(tr || m) using SHAKE256
    shake256_init(&state);
    shake256_absorb(&state, tr, DILITHIUM_TRBYTES);
    shake256_absorb(&state, m, mlen);
    shake256_finalize(&state);
    shake256_squeeze(&state, mu, DILITHIUM_CRHBYTES);

    // Compute rhoprime = H(key || mu) using SHAKE256
    shake256_init(&state);
    shake256_absorb(&state, key, DILITHIUM_SEEDBYTES);
    shake256_absorb(&state, mu, DILITHIUM_CRHBYTES);
    shake256_finalize(&state);
    shake256_squeeze(&state, rhoprime, DILITHIUM_CRHBYTES);

    // Expand matrix
    polyvec_matrix_expand(mat, rho);

    // Transform s1, s2, t0 to NTT domain
    polyvecl_ntt(&s1);
    polyveck_ntt(&s2);
    polyveck_ntt(&t0);

rej:
    // Sample y
    polyvecl_uniform_gamma1(&y, rhoprime, nonce++);
    z = y;
    polyvecl_ntt(&z);

    // w = A*y
    polyvec_matrix_pointwise_montgomery(&w1, mat, &z);
    polyveck_reduce(&w1);
    polyveck_invntt_tomont(&w1);
    polyveck_caddq(&w1);

    // Decompose w
    polyveck_decompose(&w1, &w0, &w1);

    // Compute challenge hash using SHAKE256
    uint8_t w1_packed[DILITHIUM_K * DILITHIUM_POLYW1_PACKEDBYTES];
    polyveck_pack_w1(w1_packed, &w1);

    uint8_t c_seed[DILITHIUM_SEEDBYTES];
    shake256_init(&state);
    shake256_absorb(&state, mu, DILITHIUM_CRHBYTES);
    shake256_absorb(&state, w1_packed, sizeof(w1_packed));
    shake256_finalize(&state);
    shake256_squeeze(&state, c_seed, DILITHIUM_SEEDBYTES);

    poly_challenge(&cp, c_seed);
    dilithium_poly_ntt(&cp);

    // Compute z = y + c*s1
    for (unsigned int i = 0; i < DILITHIUM_L; i++) {
        dilithium_poly_pointwise_montgomery(&z.vec[i], &cp, &s1.vec[i]);
        dilithium_poly_invntt_tomont(&z.vec[i]);
    }
    polyvecl_invntt_tomont(&y);
    for (unsigned int i = 0; i < DILITHIUM_L; i++) {
        poly_add(&z.vec[i], &z.vec[i], &y.vec[i]);
    }
    poly_reduce(&z.vec[0]);

    // Check norm of z
    if (polyvecl_chknorm(&z, DILITHIUM_GAMMA1 - DILITHIUM_BETA))
        goto rej;

    // Compute w - c*s2
    for (unsigned int i = 0; i < DILITHIUM_K; i++) {
        dilithium_poly tmp;
        dilithium_poly_pointwise_montgomery(&tmp, &cp, &s2.vec[i]);
        dilithium_poly_invntt_tomont(&tmp);
        poly_sub(&w0.vec[i], &w0.vec[i], &tmp);
    }
    polyveck_reduce(&w0);

    // Check norm
    if (polyveck_chknorm(&w0, DILITHIUM_GAMMA2 - DILITHIUM_BETA))
        goto rej;

    // Compute hint
    for (unsigned int i = 0; i < DILITHIUM_K; i++) {
        dilithium_poly tmp;
        dilithium_poly_pointwise_montgomery(&tmp, &cp, &t0.vec[i]);
        dilithium_poly_invntt_tomont(&tmp);
        poly_reduce(&tmp);
        if (poly_chknorm(&tmp, DILITHIUM_GAMMA2))
            goto rej;
        poly_add(&w0.vec[i], &w0.vec[i], &tmp);
    }
    polyveck_caddq(&w0);

    unsigned int n = polyveck_make_hint(&h, &w0, &w1);
    if (n > DILITHIUM_OMEGA)
        goto rej;

    // Pack signature
    pack_sig(sig, c_seed, &z, &h);
    *siglen = DILITHIUM_SIGNATUREBYTES;

    return 0;
}

// ============================================================================
// Verification
// ============================================================================

int dilithium_verify(const uint8_t *sig, size_t siglen,
                     const uint8_t *m, size_t mlen,
                     const uint8_t *pk) {
    uint8_t rho[DILITHIUM_SEEDBYTES];
    uint8_t mu[DILITHIUM_CRHBYTES];
    uint8_t c_seed[DILITHIUM_SEEDBYTES], c_seed2[DILITHIUM_SEEDBYTES];
    dilithium_polyveck mat[DILITHIUM_L], t1, w1, h;
    dilithium_polyvecl z;
    dilithium_poly cp;
    shake256_ctx state;

    if (siglen != DILITHIUM_SIGNATUREBYTES)
        return -1;

    dilithium_unpack_pk(rho, &t1, pk);
    if (unpack_sig(c_seed, &z, &h, sig))
        return -1;
    if (polyvecl_chknorm(&z, DILITHIUM_GAMMA1 - DILITHIUM_BETA))
        return -1;

    // Compute tr = H(pk) using SHAKE256
    uint8_t tr[DILITHIUM_TRBYTES];
    shake256(tr, DILITHIUM_TRBYTES, pk, DILITHIUM_PUBLICKEYBYTES);

    // Compute mu = H(tr || m) using SHAKE256
    shake256_init(&state);
    shake256_absorb(&state, tr, DILITHIUM_TRBYTES);
    shake256_absorb(&state, m, mlen);
    shake256_finalize(&state);
    shake256_squeeze(&state, mu, DILITHIUM_CRHBYTES);

    // Compute challenge
    poly_challenge(&cp, c_seed);

    // Matrix expansion
    polyvec_matrix_expand(mat, rho);

    // z in NTT domain
    polyvecl_ntt(&z);

    // A*z
    polyvec_matrix_pointwise_montgomery(&w1, mat, &z);

    // t1 in NTT domain, then compute -c*t1*2^d
    dilithium_poly_ntt(&cp);
    polyveck_shiftl(&t1);
    polyveck_ntt(&t1);
    for (unsigned int i = 0; i < DILITHIUM_K; i++) {
        dilithium_poly_pointwise_montgomery(&t1.vec[i], &cp, &t1.vec[i]);
    }

    // A*z - c*t1*2^d
    polyveck_sub(&w1, &w1, &t1);
    polyveck_reduce(&w1);
    polyveck_invntt_tomont(&w1);
    polyveck_caddq(&w1);

    // UseHint
    polyveck_use_hint(&w1, &w1, &h);

    // Recompute challenge using SHAKE256
    uint8_t w1_packed[DILITHIUM_K * DILITHIUM_POLYW1_PACKEDBYTES];
    polyveck_pack_w1(w1_packed, &w1);

    shake256_init(&state);
    shake256_absorb(&state, mu, DILITHIUM_CRHBYTES);
    shake256_absorb(&state, w1_packed, sizeof(w1_packed));
    shake256_finalize(&state);
    shake256_squeeze(&state, c_seed2, DILITHIUM_SEEDBYTES);

    // Compare challenges (constant-time)
    uint8_t diff = 0;
    for (unsigned int i = 0; i < DILITHIUM_SEEDBYTES; i++) {
        diff |= c_seed[i] ^ c_seed2[i];
    }

    return diff ? -1 : 0;
}
