// ============================================================================
// SHAKE128/SHAKE256 - Extendable Output Functions (XOF)
// ============================================================================
// FIPS 202 (SHA-3) implementation for Dilithium signature scheme.
// Based on the Keccak sponge construction with SHAKE mode.
//
// SHAKE128: 256-bit security, 168-byte rate
// SHAKE256: 512-bit security, 136-byte rate
//
// Copyright 2025 The LunaOS Contributors
// SPDX-License-Identifier: BSD-2-Clause
// ============================================================================

#ifndef CRYPT__SHAKE_H__
#define CRYPT__SHAKE_H__

#include <stddef.h>
#include <stdint.h>

// ============================================================================
// Constants
// ============================================================================

#define KECCAK_STATE_SIZE   200     // 1600 bits = 200 bytes
#define KECCAK_ROUNDS       24

// SHAKE128: capacity = 256 bits, rate = 168 bytes
#define SHAKE128_RATE       168

// SHAKE256: capacity = 512 bits, rate = 136 bytes
#define SHAKE256_RATE       136

// ============================================================================
// Keccak State
// ============================================================================

typedef struct {
    uint64_t state[25];     // 5x5 state matrix (1600 bits)
    uint8_t buf[200];       // Buffer for absorb/squeeze
    size_t pos;             // Current position in buffer
    size_t rate;            // Rate in bytes (depends on variant)
} keccak_ctx;

typedef keccak_ctx shake128_ctx;
typedef keccak_ctx shake256_ctx;

// ============================================================================
// SHAKE128 API
// ============================================================================

/**
 * Initialize SHAKE128 context.
 *
 * @param ctx   Output: SHAKE128 context
 */
void shake128_init(shake128_ctx *ctx);

/**
 * Absorb data into SHAKE128.
 *
 * @param ctx   SHAKE128 context
 * @param in    Input data
 * @param inlen Length of input data
 */
void shake128_absorb(shake128_ctx *ctx, const uint8_t *in, size_t inlen);

/**
 * Finalize absorb phase and prepare for squeezing.
 *
 * @param ctx   SHAKE128 context
 */
void shake128_finalize(shake128_ctx *ctx);

/**
 * Squeeze output from SHAKE128.
 *
 * @param ctx    SHAKE128 context
 * @param out    Output buffer
 * @param outlen Desired output length
 */
void shake128_squeeze(shake128_ctx *ctx, uint8_t *out, size_t outlen);

/**
 * One-shot SHAKE128: absorb and squeeze.
 *
 * @param out    Output buffer
 * @param outlen Desired output length
 * @param in     Input data
 * @param inlen  Length of input data
 */
void shake128(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen);

/**
 * Initialize SHAKE128 with seed and nonce (for Dilithium).
 * Absorbs seed || nonce where nonce is 2 bytes.
 *
 * @param ctx       SHAKE128 context
 * @param seed      32-byte seed
 * @param nonce     2-byte nonce
 */
void shake128_absorb_once(shake128_ctx *ctx, const uint8_t *seed,
                          size_t seedlen, uint16_t nonce);

// ============================================================================
// SHAKE256 API
// ============================================================================

/**
 * Initialize SHAKE256 context.
 *
 * @param ctx   Output: SHAKE256 context
 */
void shake256_init(shake256_ctx *ctx);

/**
 * Absorb data into SHAKE256.
 *
 * @param ctx   SHAKE256 context
 * @param in    Input data
 * @param inlen Length of input data
 */
void shake256_absorb(shake256_ctx *ctx, const uint8_t *in, size_t inlen);

/**
 * Finalize absorb phase and prepare for squeezing.
 *
 * @param ctx   SHAKE256 context
 */
void shake256_finalize(shake256_ctx *ctx);

/**
 * Squeeze output from SHAKE256.
 *
 * @param ctx    SHAKE256 context
 * @param out    Output buffer
 * @param outlen Desired output length
 */
void shake256_squeeze(shake256_ctx *ctx, uint8_t *out, size_t outlen);

/**
 * One-shot SHAKE256: absorb and squeeze.
 *
 * @param out    Output buffer
 * @param outlen Desired output length
 * @param in     Input data
 * @param inlen  Length of input data
 */
void shake256(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen);

/**
 * Initialize SHAKE256 with seed and nonce (for Dilithium).
 * Absorbs seed || nonce where nonce is 2 bytes.
 *
 * @param ctx       SHAKE256 context
 * @param seed      Seed data
 * @param seedlen   Length of seed
 * @param nonce     2-byte nonce
 */
void shake256_absorb_once(shake256_ctx *ctx, const uint8_t *seed,
                          size_t seedlen, uint16_t nonce);

// ============================================================================
// Stream API (for Dilithium sampling)
// ============================================================================

/**
 * SHAKE128 incremental squeeze for rejection sampling.
 * Returns next block of output without reinitializing.
 *
 * @param ctx   SHAKE128 context (must be finalized)
 * @param out   Output buffer
 * @param nblocks Number of rate-sized blocks to squeeze
 */
void shake128_squeezeblocks(shake128_ctx *ctx, uint8_t *out, size_t nblocks);

/**
 * SHAKE256 incremental squeeze for rejection sampling.
 *
 * @param ctx   SHAKE256 context (must be finalized)
 * @param out   Output buffer
 * @param nblocks Number of rate-sized blocks to squeeze
 */
void shake256_squeezeblocks(shake256_ctx *ctx, uint8_t *out, size_t nblocks);

// ============================================================================
// Low-level Keccak API
// ============================================================================

/**
 * Keccak-f[1600] permutation.
 *
 * @param state 25 x 64-bit state array
 */
void keccak_f1600(uint64_t state[25]);

/**
 * Initialize Keccak context.
 *
 * @param ctx   Output: Keccak context
 * @param rate  Rate in bytes
 */
void keccak_init(keccak_ctx *ctx, size_t rate);

/**
 * Absorb data into Keccak sponge.
 *
 * @param ctx   Keccak context
 * @param in    Input data
 * @param inlen Length of input data
 */
void keccak_absorb(keccak_ctx *ctx, const uint8_t *in, size_t inlen);

/**
 * Finalize absorb with domain separator.
 *
 * @param ctx       Keccak context
 * @param domain    Domain separator byte (0x1F for SHAKE)
 */
void keccak_finalize(keccak_ctx *ctx, uint8_t domain);

/**
 * Squeeze output from Keccak sponge.
 *
 * @param ctx    Keccak context
 * @param out    Output buffer
 * @param outlen Desired output length
 */
void keccak_squeeze(keccak_ctx *ctx, uint8_t *out, size_t outlen);

#endif // CRYPT__SHAKE_H__
