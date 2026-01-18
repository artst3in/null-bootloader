// ============================================================================
// SHA-512 - Secure Hash Algorithm 512
// ============================================================================
// Implementation based on FIPS 180-4.
//
// Copyright 2026 The LunaOS Contributors
// SPDX-License-Identifier: BSD-2-Clause
// ============================================================================

#ifndef CRYPT__SHA512_H__
#define CRYPT__SHA512_H__

#include <stdint.h>
#include <stddef.h>

// ============================================================================
// Constants
// ============================================================================

#define SHA512_BLOCK_SIZE  128
#define SHA512_DIGEST_SIZE 64

// ============================================================================
// Context Structure
// ============================================================================

typedef struct {
    uint64_t state[8];
    uint64_t count[2];
    uint8_t buffer[SHA512_BLOCK_SIZE];
} sha512_ctx;

// ============================================================================
// API Functions
// ============================================================================

/**
 * Initialize SHA-512 context.
 */
void sha512_init(sha512_ctx *ctx);

/**
 * Update SHA-512 context with data.
 */
void sha512_update(sha512_ctx *ctx, const uint8_t *data, size_t len);

/**
 * Finalize SHA-512 and output digest.
 */
void sha512_final(sha512_ctx *ctx, uint8_t *digest);

/**
 * One-shot SHA-512 hash.
 */
void sha512(uint8_t *digest, const uint8_t *data, size_t len);

#endif // CRYPT__SHA512_H__
