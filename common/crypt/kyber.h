// ============================================================================
// Kyber-1024 - Post-Quantum Key Encapsulation Mechanism (ML-KEM)
// ============================================================================
// NIST FIPS 203 (ML-KEM) standardized post-quantum cryptography.
// Kyber-1024 provides ~192-bit classical / ~256-bit quantum security.
//
// This is a minimal, portable C implementation for bootloader use.
// Reference: https://pq-crystals.org/kyber/
//
// Copyright 2025 The LunaOS Contributors
// SPDX-License-Identifier: BSD-2-Clause
// ============================================================================

#ifndef CRYPT__KYBER_H__
#define CRYPT__KYBER_H__

#include <stddef.h>
#include <stdint.h>

// ============================================================================
// Kyber-1024 Parameters (highest security level)
// ============================================================================

// Kyber-1024 constants
#define KYBER_K 4                       // Module dimension
#define KYBER_N 256                     // Polynomial degree
#define KYBER_Q 3329                    // Modulus

// Derived sizes
#define KYBER_SYMBYTES 32               // Size of shared key, seeds, hashes
#define KYBER_POLYBYTES 384             // Bytes per polynomial
#define KYBER_POLYVECBYTES (KYBER_K * KYBER_POLYBYTES)

// Kyber-1024 specific sizes
#define KYBER_ETA1 2                    // Noise parameter for key generation
#define KYBER_ETA2 2                    // Noise parameter for encryption
#define KYBER_DU 11                     // Compression parameter
#define KYBER_DV 5                      // Compression parameter

// Public key: t + rho
#define KYBER_PUBLICKEYBYTES (KYBER_POLYVECBYTES + KYBER_SYMBYTES)  // 1568

// Secret key: s + pk + H(pk) + z
#define KYBER_SECRETKEYBYTES (KYBER_POLYVECBYTES + KYBER_PUBLICKEYBYTES + 2*KYBER_SYMBYTES)  // 3168

// Ciphertext: c1 + c2
#define KYBER_CIPHERTEXTBYTES (KYBER_K * (KYBER_N * KYBER_DU / 8) + KYBER_N * KYBER_DV / 8)  // 1568

// Shared secret size
#define KYBER_SSBYTES 32

// ============================================================================
// Core Types
// ============================================================================

// Polynomial in Z_q[X]/(X^n + 1)
typedef struct {
    int16_t coeffs[KYBER_N];
} kyber_poly;

// Vector of k polynomials
typedef struct {
    kyber_poly vec[KYBER_K];
} kyber_polyvec;

// ============================================================================
// Key Encapsulation Mechanism (KEM) API
// ============================================================================

/**
 * Generate a Kyber-1024 keypair.
 *
 * @param pk    Output: Public key (KYBER_PUBLICKEYBYTES bytes)
 * @param sk    Output: Secret key (KYBER_SECRETKEYBYTES bytes)
 * @param coins Random bytes for deterministic generation (KYBER_SYMBYTES * 2)
 *              If NULL, uses internal RNG (not recommended in bootloader)
 * @return 0 on success
 */
int kyber_keypair(uint8_t *pk, uint8_t *sk, const uint8_t *coins);

/**
 * Encapsulate: Generate ciphertext and shared secret from public key.
 *
 * @param ct    Output: Ciphertext (KYBER_CIPHERTEXTBYTES bytes)
 * @param ss    Output: Shared secret (KYBER_SSBYTES bytes)
 * @param pk    Input: Public key (KYBER_PUBLICKEYBYTES bytes)
 * @param coins Random bytes for deterministic encapsulation (KYBER_SYMBYTES)
 *              If NULL, uses internal RNG (not recommended in bootloader)
 * @return 0 on success
 */
int kyber_encapsulate(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *coins);

/**
 * Decapsulate: Recover shared secret from ciphertext using secret key.
 *
 * @param ss    Output: Shared secret (KYBER_SSBYTES bytes)
 * @param ct    Input: Ciphertext (KYBER_CIPHERTEXTBYTES bytes)
 * @param sk    Input: Secret key (KYBER_SECRETKEYBYTES bytes)
 * @return 0 on success (always succeeds due to implicit rejection)
 */
int kyber_decapsulate(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

// ============================================================================
// Internal PKE API (for advanced use)
// ============================================================================

/**
 * PKE Key Generation (internal)
 */
void kyber_pke_keypair(uint8_t *pk, uint8_t *sk, const uint8_t seed[KYBER_SYMBYTES]);

/**
 * PKE Encryption (internal)
 */
void kyber_pke_encrypt(uint8_t *ct, const uint8_t *m, const uint8_t *pk,
                       const uint8_t coins[KYBER_SYMBYTES]);

/**
 * PKE Decryption (internal)
 */
void kyber_pke_decrypt(uint8_t *m, const uint8_t *ct, const uint8_t *sk);

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Verify that two byte arrays are equal in constant time.
 * Returns 0 if equal, non-zero otherwise.
 */
int kyber_verify(const uint8_t *a, const uint8_t *b, size_t len);

/**
 * Copy src to dst if condition is 0, otherwise keep dst unchanged.
 * Constant-time conditional move.
 */
void kyber_cmov(uint8_t *dst, const uint8_t *src, size_t len, uint8_t condition);

#endif // CRYPT__KYBER_H__
