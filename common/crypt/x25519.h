// ============================================================================
// X25519 - Elliptic Curve Diffie-Hellman Key Exchange
// ============================================================================
// Implementation based on RFC 7748.
// Uses Montgomery curve Curve25519.
//
// Copyright 2026 The LunaOS Contributors
// SPDX-License-Identifier: BSD-2-Clause
// ============================================================================

#ifndef CRYPT__X25519_H__
#define CRYPT__X25519_H__

#include <stdint.h>
#include <stddef.h>

// ============================================================================
// Constants
// ============================================================================

#define X25519_PUBLICKEYBYTES  32
#define X25519_SECRETKEYBYTES  32
#define X25519_SHAREDSECRETBYTES 32

// ============================================================================
// API Functions
// ============================================================================

/**
 * Perform X25519 scalar multiplication (Diffie-Hellman).
 *
 * @param shared_secret  Output: 32-byte shared secret
 * @param secret_key     32-byte secret key (clamped scalar)
 * @param public_key     32-byte public key (point on curve)
 * @return 0 on success, -1 on invalid input
 */
int x25519(uint8_t *shared_secret,
           const uint8_t *secret_key,
           const uint8_t *public_key);

/**
 * Generate X25519 public key from secret key.
 *
 * @param public_key   Output: 32-byte public key
 * @param secret_key   32-byte secret key
 */
void x25519_public_key(uint8_t *public_key, const uint8_t *secret_key);

/**
 * Clamp a 32-byte random value to a valid X25519 secret key.
 *
 * @param key  32-byte key to clamp (modified in place)
 */
void x25519_clamp(uint8_t *key);

#endif // CRYPT__X25519_H__
