// ============================================================================
// Ed25519 - Edwards-curve Digital Signature Algorithm
// ============================================================================
// High-speed, high-security signatures using Curve25519.
// Based on RFC 8032.
//
// Copyright 2026 The LunaOS Contributors
// SPDX-License-Identifier: BSD-2-Clause
// ============================================================================

#ifndef CRYPT__ED25519_H__
#define CRYPT__ED25519_H__

#include <stdint.h>
#include <stddef.h>

// ============================================================================
// Constants
// ============================================================================

#define ED25519_PUBLICKEYBYTES  32
#define ED25519_SECRETKEYBYTES  64  // 32-byte seed + 32-byte public key
#define ED25519_SEEDBYTES       32
#define ED25519_SIGNATUREBYTES  64

// ============================================================================
// API Functions
// ============================================================================

/**
 * Verify an Ed25519 signature.
 *
 * @param signature   64-byte signature
 * @param message     Message that was signed
 * @param message_len Length of message
 * @param public_key  32-byte public key
 * @return 0 if valid, -1 if invalid
 */
int ed25519_verify(const uint8_t *signature,
                   const uint8_t *message, size_t message_len,
                   const uint8_t *public_key);

/**
 * Create an Ed25519 signature.
 *
 * @param signature   Output: 64-byte signature
 * @param message     Message to sign
 * @param message_len Length of message
 * @param secret_key  64-byte secret key (seed + public key)
 * @return 0 on success
 */
int ed25519_sign(uint8_t *signature,
                 const uint8_t *message, size_t message_len,
                 const uint8_t *secret_key);

/**
 * Generate an Ed25519 keypair from a seed.
 *
 * @param public_key  Output: 32-byte public key
 * @param secret_key  Output: 64-byte secret key
 * @param seed        32-byte random seed
 */
void ed25519_keypair_from_seed(uint8_t *public_key,
                               uint8_t *secret_key,
                               const uint8_t *seed);

#endif // CRYPT__ED25519_H__
