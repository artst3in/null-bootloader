// ============================================================================
// SHAKE128/SHAKE256 - Extendable Output Functions (XOF)
// ============================================================================
// FIPS 202 (SHA-3) implementation for Dilithium signature scheme.
// Minimal, portable C implementation for bootloader use.
//
// Copyright 2025 The LunaOS Contributors
// SPDX-License-Identifier: BSD-2-Clause
// ============================================================================

#include <stdint.h>
#include <stddef.h>
#include <crypt/shake.h>
#include <lib/libc.h>

// ============================================================================
// Keccak Round Constants
// ============================================================================

static const uint64_t keccak_rc[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL,
    0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL,
    0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL,
    0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL,
    0x0000000080000001ULL, 0x8000000080008008ULL
};

// ============================================================================
// Rotation offsets for Keccak rho step
// ============================================================================

static const unsigned int keccak_rotc[24] = {
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
    27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44
};

// ============================================================================
// Pi step permutation indices
// ============================================================================

static const unsigned int keccak_piln[24] = {
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
    15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1
};

// ============================================================================
// Utility Macros
// ============================================================================

#define ROTL64(x, n) (((x) << (n)) | ((x) >> (64 - (n))))

// ============================================================================
// Keccak-f[1600] Permutation
// ============================================================================

void keccak_f1600(uint64_t state[25]) {
    uint64_t t, bc[5];
    int round, i, j;

    for (round = 0; round < KECCAK_ROUNDS; round++) {
        // Theta step
        for (i = 0; i < 5; i++) {
            bc[i] = state[i] ^ state[i + 5] ^ state[i + 10] ^
                    state[i + 15] ^ state[i + 20];
        }
        for (i = 0; i < 5; i++) {
            t = bc[(i + 4) % 5] ^ ROTL64(bc[(i + 1) % 5], 1);
            for (j = 0; j < 25; j += 5) {
                state[j + i] ^= t;
            }
        }

        // Rho and Pi steps
        t = state[1];
        for (i = 0; i < 24; i++) {
            j = keccak_piln[i];
            bc[0] = state[j];
            state[j] = ROTL64(t, keccak_rotc[i]);
            t = bc[0];
        }

        // Chi step
        for (j = 0; j < 25; j += 5) {
            for (i = 0; i < 5; i++) {
                bc[i] = state[j + i];
            }
            for (i = 0; i < 5; i++) {
                state[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
            }
        }

        // Iota step
        state[0] ^= keccak_rc[round];
    }
}

// ============================================================================
// Generic Keccak Sponge
// ============================================================================

void keccak_init(keccak_ctx *ctx, size_t rate) {
    memset(ctx->state, 0, sizeof(ctx->state));
    memset(ctx->buf, 0, sizeof(ctx->buf));
    ctx->pos = 0;
    ctx->rate = rate;
}

void keccak_absorb(keccak_ctx *ctx, const uint8_t *in, size_t inlen) {
    size_t i;

    while (inlen > 0) {
        size_t chunk = ctx->rate - ctx->pos;
        if (chunk > inlen) chunk = inlen;

        for (i = 0; i < chunk; i++) {
            ctx->buf[ctx->pos + i] ^= in[i];
        }

        ctx->pos += chunk;
        in += chunk;
        inlen -= chunk;

        if (ctx->pos == ctx->rate) {
            // XOR buffer into state
            for (i = 0; i < ctx->rate / 8; i++) {
                ctx->state[i] ^= ((uint64_t *)ctx->buf)[i];
            }
            keccak_f1600(ctx->state);
            memset(ctx->buf, 0, ctx->rate);
            ctx->pos = 0;
        }
    }
}

void keccak_finalize(keccak_ctx *ctx, uint8_t domain) {
    size_t i;

    // Apply domain separator and padding
    ctx->buf[ctx->pos] ^= domain;
    ctx->buf[ctx->rate - 1] ^= 0x80;

    // XOR buffer into state
    for (i = 0; i < ctx->rate / 8; i++) {
        ctx->state[i] ^= ((uint64_t *)ctx->buf)[i];
    }

    keccak_f1600(ctx->state);
    ctx->pos = 0;
}

void keccak_squeeze(keccak_ctx *ctx, uint8_t *out, size_t outlen) {
    size_t i;
    uint8_t *state_bytes = (uint8_t *)ctx->state;

    while (outlen > 0) {
        if (ctx->pos == ctx->rate) {
            keccak_f1600(ctx->state);
            ctx->pos = 0;
        }

        size_t chunk = ctx->rate - ctx->pos;
        if (chunk > outlen) chunk = outlen;

        for (i = 0; i < chunk; i++) {
            out[i] = state_bytes[ctx->pos + i];
        }

        ctx->pos += chunk;
        out += chunk;
        outlen -= chunk;
    }
}

// ============================================================================
// SHAKE128
// ============================================================================

void shake128_init(shake128_ctx *ctx) {
    keccak_init(ctx, SHAKE128_RATE);
}

void shake128_absorb(shake128_ctx *ctx, const uint8_t *in, size_t inlen) {
    keccak_absorb(ctx, in, inlen);
}

void shake128_finalize(shake128_ctx *ctx) {
    keccak_finalize(ctx, 0x1F);  // SHAKE domain separator
}

void shake128_squeeze(shake128_ctx *ctx, uint8_t *out, size_t outlen) {
    keccak_squeeze(ctx, out, outlen);
}

void shake128(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen) {
    shake128_ctx ctx;
    shake128_init(&ctx);
    shake128_absorb(&ctx, in, inlen);
    shake128_finalize(&ctx);
    shake128_squeeze(&ctx, out, outlen);
}

void shake128_absorb_once(shake128_ctx *ctx, const uint8_t *seed,
                          size_t seedlen, uint16_t nonce) {
    uint8_t nonce_bytes[2];
    nonce_bytes[0] = nonce & 0xFF;
    nonce_bytes[1] = (nonce >> 8) & 0xFF;

    shake128_init(ctx);
    shake128_absorb(ctx, seed, seedlen);
    shake128_absorb(ctx, nonce_bytes, 2);
    shake128_finalize(ctx);
}

void shake128_squeezeblocks(shake128_ctx *ctx, uint8_t *out, size_t nblocks) {
    uint8_t *state_bytes = (uint8_t *)ctx->state;

    while (nblocks > 0) {
        keccak_f1600(ctx->state);
        memcpy(out, state_bytes, SHAKE128_RATE);
        out += SHAKE128_RATE;
        nblocks--;
    }
}

// ============================================================================
// SHAKE256
// ============================================================================

void shake256_init(shake256_ctx *ctx) {
    keccak_init(ctx, SHAKE256_RATE);
}

void shake256_absorb(shake256_ctx *ctx, const uint8_t *in, size_t inlen) {
    keccak_absorb(ctx, in, inlen);
}

void shake256_finalize(shake256_ctx *ctx) {
    keccak_finalize(ctx, 0x1F);  // SHAKE domain separator
}

void shake256_squeeze(shake256_ctx *ctx, uint8_t *out, size_t outlen) {
    keccak_squeeze(ctx, out, outlen);
}

void shake256(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen) {
    shake256_ctx ctx;
    shake256_init(&ctx);
    shake256_absorb(&ctx, in, inlen);
    shake256_finalize(&ctx);
    shake256_squeeze(&ctx, out, outlen);
}

void shake256_absorb_once(shake256_ctx *ctx, const uint8_t *seed,
                          size_t seedlen, uint16_t nonce) {
    uint8_t nonce_bytes[2];
    nonce_bytes[0] = nonce & 0xFF;
    nonce_bytes[1] = (nonce >> 8) & 0xFF;

    shake256_init(ctx);
    shake256_absorb(ctx, seed, seedlen);
    shake256_absorb(ctx, nonce_bytes, 2);
    shake256_finalize(ctx);
}

void shake256_squeezeblocks(shake256_ctx *ctx, uint8_t *out, size_t nblocks) {
    uint8_t *state_bytes = (uint8_t *)ctx->state;

    while (nblocks > 0) {
        keccak_f1600(ctx->state);
        memcpy(out, state_bytes, SHAKE256_RATE);
        out += SHAKE256_RATE;
        nblocks--;
    }
}
