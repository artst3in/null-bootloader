// ============================================================================
// Dilithium-3 - Post-Quantum Digital Signatures (ML-DSA)
// ============================================================================
// NIST FIPS 204 (ML-DSA) standardized post-quantum signature scheme.
// Dilithium-3 provides NIST Security Level 3 (~128-bit post-quantum).
//
// This is a minimal, portable C implementation for bootloader use.
// Reference: https://pq-crystals.org/dilithium/
//
// Copyright 2025 The LunaOS Contributors
// SPDX-License-Identifier: BSD-2-Clause
// ============================================================================

#ifndef CRYPT__DILITHIUM_H__
#define CRYPT__DILITHIUM_H__

#include <stddef.h>
#include <stdint.h>

// ============================================================================
// Dilithium-3 Parameters (NIST Security Level 3)
// ============================================================================

#define DILITHIUM_K 6                   // Rows in matrix A
#define DILITHIUM_L 5                   // Columns in matrix A
#define DILITHIUM_N 256                 // Polynomial degree
#define DILITHIUM_Q 8380417             // Modulus (2^23 - 2^13 + 1)
#define DILITHIUM_D 13                  // Dropped bits in t
#define DILITHIUM_TAU 49                // Number of ±1s in challenge
#define DILITHIUM_GAMMA1 (1 << 19)      // y coefficient range
#define DILITHIUM_GAMMA2 ((DILITHIUM_Q - 1) / 32)  // Low-order rounding range
#define DILITHIUM_ETA 4                 // Private key range
#define DILITHIUM_BETA 196              // tau * eta bound
#define DILITHIUM_OMEGA 55              // Maximum # of 1s in hint

// Derived sizes
#define DILITHIUM_SEEDBYTES 32
#define DILITHIUM_CRHBYTES 64
#define DILITHIUM_TRBYTES 64

// Polynomial sizes
#define DILITHIUM_POLYT1_PACKEDBYTES 320
#define DILITHIUM_POLYT0_PACKEDBYTES 416
#define DILITHIUM_POLYVECH_PACKEDBYTES (DILITHIUM_OMEGA + DILITHIUM_K)
#define DILITHIUM_POLYZ_PACKEDBYTES 640
#define DILITHIUM_POLYW1_PACKEDBYTES 128
#define DILITHIUM_POLYETA_PACKEDBYTES 128

// Key and signature sizes
#define DILITHIUM_PUBLICKEYBYTES (DILITHIUM_SEEDBYTES + DILITHIUM_K * DILITHIUM_POLYT1_PACKEDBYTES)  // 1952
#define DILITHIUM_SECRETKEYBYTES (2*DILITHIUM_SEEDBYTES + DILITHIUM_TRBYTES + \
                                  DILITHIUM_L * DILITHIUM_POLYETA_PACKEDBYTES + \
                                  DILITHIUM_K * DILITHIUM_POLYETA_PACKEDBYTES + \
                                  DILITHIUM_K * DILITHIUM_POLYT0_PACKEDBYTES)  // 4032
#define DILITHIUM_SIGNATUREBYTES (DILITHIUM_SEEDBYTES + DILITHIUM_L * DILITHIUM_POLYZ_PACKEDBYTES + \
                                  DILITHIUM_POLYVECH_PACKEDBYTES)  // 3293

// ============================================================================
// Core Types
// ============================================================================

// Polynomial in Z_q[X]/(X^n + 1)
typedef struct {
    int32_t coeffs[DILITHIUM_N];
} dilithium_poly;

// Vector of k polynomials
typedef struct {
    dilithium_poly vec[DILITHIUM_K];
} dilithium_polyveck;

// Vector of l polynomials
typedef struct {
    dilithium_poly vec[DILITHIUM_L];
} dilithium_polyvecl;

// ============================================================================
// Digital Signature API
// ============================================================================

/**
 * Generate a Dilithium-3 keypair.
 *
 * @param pk    Output: Public key (DILITHIUM_PUBLICKEYBYTES bytes)
 * @param sk    Output: Secret key (DILITHIUM_SECRETKEYBYTES bytes)
 * @param seed  Random seed (DILITHIUM_SEEDBYTES bytes), or NULL for internal RNG
 * @return 0 on success
 */
int dilithium_keypair(uint8_t *pk, uint8_t *sk, const uint8_t *seed);

/**
 * Sign a message.
 *
 * @param sig     Output: Signature (DILITHIUM_SIGNATUREBYTES bytes)
 * @param siglen  Output: Signature length (always DILITHIUM_SIGNATUREBYTES)
 * @param m       Input: Message to sign
 * @param mlen    Input: Message length
 * @param sk      Input: Secret key
 * @return 0 on success
 */
int dilithium_sign(uint8_t *sig, size_t *siglen,
                   const uint8_t *m, size_t mlen,
                   const uint8_t *sk);

/**
 * Verify a signature.
 *
 * @param sig     Input: Signature
 * @param siglen  Input: Signature length
 * @param m       Input: Message
 * @param mlen    Input: Message length
 * @param pk      Input: Public key
 * @return 0 if valid, -1 if invalid
 */
int dilithium_verify(const uint8_t *sig, size_t siglen,
                     const uint8_t *m, size_t mlen,
                     const uint8_t *pk);

// ============================================================================
// Internal Functions (for advanced use)
// ============================================================================

// Pack/unpack functions
void dilithium_pack_pk(uint8_t *pk, const uint8_t rho[DILITHIUM_SEEDBYTES],
                       const dilithium_polyveck *t1);
void dilithium_unpack_pk(uint8_t rho[DILITHIUM_SEEDBYTES], dilithium_polyveck *t1,
                         const uint8_t *pk);
void dilithium_pack_sk(uint8_t *sk, const uint8_t rho[DILITHIUM_SEEDBYTES],
                       const uint8_t tr[DILITHIUM_TRBYTES],
                       const uint8_t key[DILITHIUM_SEEDBYTES],
                       const dilithium_polyveck *t0,
                       const dilithium_polyvecl *s1,
                       const dilithium_polyveck *s2);
void dilithium_unpack_sk(uint8_t rho[DILITHIUM_SEEDBYTES],
                         uint8_t tr[DILITHIUM_TRBYTES],
                         uint8_t key[DILITHIUM_SEEDBYTES],
                         dilithium_polyveck *t0,
                         dilithium_polyvecl *s1,
                         dilithium_polyveck *s2,
                         const uint8_t *sk);

// Polynomial operations
void dilithium_poly_ntt(dilithium_poly *a);
void dilithium_poly_invntt_tomont(dilithium_poly *a);
void dilithium_poly_pointwise_montgomery(dilithium_poly *c,
                                         const dilithium_poly *a,
                                         const dilithium_poly *b);

#endif // CRYPT__DILITHIUM_H__
