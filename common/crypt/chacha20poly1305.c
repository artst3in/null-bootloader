// ============================================================================
// ChaCha20-Poly1305 - Authenticated Encryption with Associated Data (AEAD)
// ============================================================================
// RFC 8439 implementation for bootloader use.
// Minimal, portable C implementation.
//
// Copyright 2025 The LunaOS Contributors
// SPDX-License-Identifier: BSD-2-Clause
// ============================================================================

#include <stdint.h>
#include <stddef.h>
#include <crypt/chacha20poly1305.h>
#include <lib/libc.h>

// ============================================================================
// Utility Macros
// ============================================================================

#define ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

#define U8TO32_LE(p) \
    (((uint32_t)(p)[0]) | ((uint32_t)(p)[1] << 8) | \
     ((uint32_t)(p)[2] << 16) | ((uint32_t)(p)[3] << 24))

#define U32TO8_LE(p, v) do { \
    (p)[0] = (uint8_t)((v)); \
    (p)[1] = (uint8_t)((v) >> 8); \
    (p)[2] = (uint8_t)((v) >> 16); \
    (p)[3] = (uint8_t)((v) >> 24); \
} while (0)

#define U64TO8_LE(p, v) do { \
    U32TO8_LE((p), (uint32_t)(v)); \
    U32TO8_LE((p) + 4, (uint32_t)((v) >> 32)); \
} while (0)

// ============================================================================
// ChaCha20 Quarter Round
// ============================================================================

#define QUARTERROUND(a, b, c, d) do { \
    a += b; d ^= a; d = ROTL32(d, 16); \
    c += d; b ^= c; b = ROTL32(b, 12); \
    a += b; d ^= a; d = ROTL32(d, 8); \
    c += d; b ^= c; b = ROTL32(b, 7); \
} while (0)

// ============================================================================
// ChaCha20 Implementation
// ============================================================================

// "expand 32-byte k" as little-endian words
static const uint32_t chacha_constants[4] = {
    0x61707865, 0x3320646e, 0x79622d32, 0x6b206574
};

void chacha20_init(chacha20_ctx *ctx, const uint8_t key[32],
                   const uint8_t nonce[12], uint32_t counter) {
    // Constants
    ctx->state[0] = chacha_constants[0];
    ctx->state[1] = chacha_constants[1];
    ctx->state[2] = chacha_constants[2];
    ctx->state[3] = chacha_constants[3];

    // Key (256 bits)
    ctx->state[4] = U8TO32_LE(key);
    ctx->state[5] = U8TO32_LE(key + 4);
    ctx->state[6] = U8TO32_LE(key + 8);
    ctx->state[7] = U8TO32_LE(key + 12);
    ctx->state[8] = U8TO32_LE(key + 16);
    ctx->state[9] = U8TO32_LE(key + 20);
    ctx->state[10] = U8TO32_LE(key + 24);
    ctx->state[11] = U8TO32_LE(key + 28);

    // Counter
    ctx->state[12] = counter;

    // Nonce (96 bits)
    ctx->state[13] = U8TO32_LE(nonce);
    ctx->state[14] = U8TO32_LE(nonce + 4);
    ctx->state[15] = U8TO32_LE(nonce + 8);
}

void chacha20_block(chacha20_ctx *ctx, uint8_t out[64]) {
    uint32_t x[16];
    int i;

    // Copy state to working array
    for (i = 0; i < 16; i++) {
        x[i] = ctx->state[i];
    }

    // 20 rounds (10 double-rounds)
    for (i = 0; i < 10; i++) {
        // Column rounds
        QUARTERROUND(x[0], x[4], x[8], x[12]);
        QUARTERROUND(x[1], x[5], x[9], x[13]);
        QUARTERROUND(x[2], x[6], x[10], x[14]);
        QUARTERROUND(x[3], x[7], x[11], x[15]);
        // Diagonal rounds
        QUARTERROUND(x[0], x[5], x[10], x[15]);
        QUARTERROUND(x[1], x[6], x[11], x[12]);
        QUARTERROUND(x[2], x[7], x[8], x[13]);
        QUARTERROUND(x[3], x[4], x[9], x[14]);
    }

    // Add original state
    for (i = 0; i < 16; i++) {
        x[i] += ctx->state[i];
        U32TO8_LE(out + (i * 4), x[i]);
    }

    // Increment counter
    ctx->state[12]++;
}

void chacha20_encrypt(chacha20_ctx *ctx, uint8_t *out,
                      const uint8_t *in, size_t len) {
    uint8_t block[64];
    size_t i;

    while (len >= 64) {
        chacha20_block(ctx, block);
        for (i = 0; i < 64; i++) {
            out[i] = in[i] ^ block[i];
        }
        out += 64;
        in += 64;
        len -= 64;
    }

    if (len > 0) {
        chacha20_block(ctx, block);
        for (i = 0; i < len; i++) {
            out[i] = in[i] ^ block[i];
        }
    }
}

// ============================================================================
// Poly1305 Implementation
// ============================================================================

void poly1305_init(poly1305_ctx *ctx, const uint8_t key[32]) {
    // r = key[0..15] with clamping
    uint32_t t0, t1, t2, t3;

    t0 = U8TO32_LE(key);
    t1 = U8TO32_LE(key + 4);
    t2 = U8TO32_LE(key + 8);
    t3 = U8TO32_LE(key + 12);

    // Clamp r
    ctx->r[0] = t0 & 0x03ffffff;
    ctx->r[1] = ((t0 >> 26) | (t1 << 6)) & 0x03ffff03;
    ctx->r[2] = ((t1 >> 20) | (t2 << 12)) & 0x03ffc0ff;
    ctx->r[3] = ((t2 >> 14) | (t3 << 18)) & 0x03f03fff;
    ctx->r[4] = (t3 >> 8) & 0x000fffff;

    // s = key[16..31]
    ctx->pad[0] = U8TO32_LE(key + 16);
    ctx->pad[1] = U8TO32_LE(key + 20);
    ctx->pad[2] = U8TO32_LE(key + 24);
    ctx->pad[3] = U8TO32_LE(key + 28);

    // h = 0
    ctx->h[0] = 0;
    ctx->h[1] = 0;
    ctx->h[2] = 0;
    ctx->h[3] = 0;
    ctx->h[4] = 0;

    ctx->leftover = 0;
    ctx->final = 0;
}

static void poly1305_blocks(poly1305_ctx *ctx, const uint8_t *m, size_t len) {
    const uint32_t hibit = ctx->final ? 0 : (1 << 24);  // 2^128

    uint32_t r0, r1, r2, r3, r4;
    uint32_t s1, s2, s3, s4;
    uint32_t h0, h1, h2, h3, h4;
    uint64_t d0, d1, d2, d3, d4;
    uint32_t c;

    r0 = ctx->r[0];
    r1 = ctx->r[1];
    r2 = ctx->r[2];
    r3 = ctx->r[3];
    r4 = ctx->r[4];

    s1 = r1 * 5;
    s2 = r2 * 5;
    s3 = r3 * 5;
    s4 = r4 * 5;

    h0 = ctx->h[0];
    h1 = ctx->h[1];
    h2 = ctx->h[2];
    h3 = ctx->h[3];
    h4 = ctx->h[4];

    while (len >= 16) {
        // h += m[i]
        uint32_t t0, t1, t2, t3;
        t0 = U8TO32_LE(m);
        t1 = U8TO32_LE(m + 4);
        t2 = U8TO32_LE(m + 8);
        t3 = U8TO32_LE(m + 12);

        h0 += t0 & 0x03ffffff;
        h1 += ((t0 >> 26) | (t1 << 6)) & 0x03ffffff;
        h2 += ((t1 >> 20) | (t2 << 12)) & 0x03ffffff;
        h3 += ((t2 >> 14) | (t3 << 18)) & 0x03ffffff;
        h4 += (t3 >> 8) | hibit;

        // h *= r
        d0 = ((uint64_t)h0 * r0) + ((uint64_t)h1 * s4) + ((uint64_t)h2 * s3) +
             ((uint64_t)h3 * s2) + ((uint64_t)h4 * s1);
        d1 = ((uint64_t)h0 * r1) + ((uint64_t)h1 * r0) + ((uint64_t)h2 * s4) +
             ((uint64_t)h3 * s3) + ((uint64_t)h4 * s2);
        d2 = ((uint64_t)h0 * r2) + ((uint64_t)h1 * r1) + ((uint64_t)h2 * r0) +
             ((uint64_t)h3 * s4) + ((uint64_t)h4 * s3);
        d3 = ((uint64_t)h0 * r3) + ((uint64_t)h1 * r2) + ((uint64_t)h2 * r1) +
             ((uint64_t)h3 * r0) + ((uint64_t)h4 * s4);
        d4 = ((uint64_t)h0 * r4) + ((uint64_t)h1 * r3) + ((uint64_t)h2 * r2) +
             ((uint64_t)h3 * r1) + ((uint64_t)h4 * r0);

        // Partial reduction mod 2^130-5
        c = (uint32_t)(d0 >> 26); h0 = (uint32_t)d0 & 0x03ffffff;
        d1 += c; c = (uint32_t)(d1 >> 26); h1 = (uint32_t)d1 & 0x03ffffff;
        d2 += c; c = (uint32_t)(d2 >> 26); h2 = (uint32_t)d2 & 0x03ffffff;
        d3 += c; c = (uint32_t)(d3 >> 26); h3 = (uint32_t)d3 & 0x03ffffff;
        d4 += c; c = (uint32_t)(d4 >> 26); h4 = (uint32_t)d4 & 0x03ffffff;
        h0 += c * 5; c = h0 >> 26; h0 &= 0x03ffffff;
        h1 += c;

        m += 16;
        len -= 16;
    }

    ctx->h[0] = h0;
    ctx->h[1] = h1;
    ctx->h[2] = h2;
    ctx->h[3] = h3;
    ctx->h[4] = h4;
}

void poly1305_update(poly1305_ctx *ctx, const uint8_t *m, size_t len) {
    size_t i;

    // Handle leftover
    if (ctx->leftover) {
        size_t want = 16 - ctx->leftover;
        if (want > len) want = len;
        for (i = 0; i < want; i++) {
            ctx->buffer[ctx->leftover + i] = m[i];
        }
        m += want;
        len -= want;
        ctx->leftover += want;
        if (ctx->leftover < 16) return;
        poly1305_blocks(ctx, ctx->buffer, 16);
        ctx->leftover = 0;
    }

    // Process full blocks
    if (len >= 16) {
        size_t blocks = len & ~15;
        poly1305_blocks(ctx, m, blocks);
        m += blocks;
        len -= blocks;
    }

    // Store leftover
    if (len > 0) {
        for (i = 0; i < len; i++) {
            ctx->buffer[i] = m[i];
        }
        ctx->leftover = len;
    }
}

void poly1305_finish(poly1305_ctx *ctx, uint8_t tag[16]) {
    uint32_t h0, h1, h2, h3, h4, c;
    uint32_t g0, g1, g2, g3, g4;
    uint64_t f;
    uint32_t mask;

    // Process remaining block
    if (ctx->leftover) {
        size_t i = ctx->leftover;
        ctx->buffer[i++] = 1;  // Padding
        for (; i < 16; i++) {
            ctx->buffer[i] = 0;
        }
        ctx->final = 1;
        poly1305_blocks(ctx, ctx->buffer, 16);
    }

    // Fully reduce h
    h0 = ctx->h[0];
    h1 = ctx->h[1];
    h2 = ctx->h[2];
    h3 = ctx->h[3];
    h4 = ctx->h[4];

    c = h1 >> 26; h1 &= 0x03ffffff;
    h2 += c; c = h2 >> 26; h2 &= 0x03ffffff;
    h3 += c; c = h3 >> 26; h3 &= 0x03ffffff;
    h4 += c; c = h4 >> 26; h4 &= 0x03ffffff;
    h0 += c * 5; c = h0 >> 26; h0 &= 0x03ffffff;
    h1 += c;

    // Compute h + -p
    g0 = h0 + 5; c = g0 >> 26; g0 &= 0x03ffffff;
    g1 = h1 + c; c = g1 >> 26; g1 &= 0x03ffffff;
    g2 = h2 + c; c = g2 >> 26; g2 &= 0x03ffffff;
    g3 = h3 + c; c = g3 >> 26; g3 &= 0x03ffffff;
    g4 = h4 + c - (1 << 26);

    // Select h if h < p, else h - p
    mask = (g4 >> 31) - 1;
    g0 &= mask;
    g1 &= mask;
    g2 &= mask;
    g3 &= mask;
    g4 &= mask;
    mask = ~mask;
    h0 = (h0 & mask) | g0;
    h1 = (h1 & mask) | g1;
    h2 = (h2 & mask) | g2;
    h3 = (h3 & mask) | g3;
    h4 = (h4 & mask) | g4;

    // h = h mod 2^128
    h0 = (h0 | (h1 << 26)) & 0xffffffff;
    h1 = ((h1 >> 6) | (h2 << 20)) & 0xffffffff;
    h2 = ((h2 >> 12) | (h3 << 14)) & 0xffffffff;
    h3 = ((h3 >> 18) | (h4 << 8)) & 0xffffffff;

    // h = h + s
    f = (uint64_t)h0 + ctx->pad[0]; h0 = (uint32_t)f;
    f = (uint64_t)h1 + ctx->pad[1] + (f >> 32); h1 = (uint32_t)f;
    f = (uint64_t)h2 + ctx->pad[2] + (f >> 32); h2 = (uint32_t)f;
    f = (uint64_t)h3 + ctx->pad[3] + (f >> 32); h3 = (uint32_t)f;

    U32TO8_LE(tag, h0);
    U32TO8_LE(tag + 4, h1);
    U32TO8_LE(tag + 8, h2);
    U32TO8_LE(tag + 12, h3);
}

void poly1305_auth(uint8_t tag[16], const uint8_t *m, size_t mlen,
                   const uint8_t key[32]) {
    poly1305_ctx ctx;
    poly1305_init(&ctx, key);
    poly1305_update(&ctx, m, mlen);
    poly1305_finish(&ctx, tag);
}

// ============================================================================
// ChaCha20-Poly1305 AEAD
// ============================================================================

// Pad to 16-byte boundary
static void pad16(poly1305_ctx *ctx, size_t len) {
    static const uint8_t zeros[16] = {0};
    size_t padlen = (16 - (len & 15)) & 15;
    if (padlen) {
        poly1305_update(ctx, zeros, padlen);
    }
}

int chacha20poly1305_encrypt(uint8_t *ct, uint8_t tag[16],
                             const uint8_t *pt, size_t pt_len,
                             const uint8_t *aad, size_t aad_len,
                             const uint8_t nonce[12],
                             const uint8_t key[32]) {
    chacha20_ctx chacha;
    poly1305_ctx poly;
    uint8_t poly_key[64];
    uint8_t len_block[16];

    // Generate Poly1305 key (block 0)
    chacha20_init(&chacha, key, nonce, 0);
    chacha20_block(&chacha, poly_key);

    // Initialize Poly1305 with first 32 bytes
    poly1305_init(&poly, poly_key);

    // Authenticate AAD
    if (aad_len > 0) {
        poly1305_update(&poly, aad, aad_len);
        pad16(&poly, aad_len);
    }

    // Encrypt plaintext (starting from block 1)
    chacha20_init(&chacha, key, nonce, 1);
    chacha20_encrypt(&chacha, ct, pt, pt_len);

    // Authenticate ciphertext
    poly1305_update(&poly, ct, pt_len);
    pad16(&poly, pt_len);

    // Authenticate lengths (little-endian)
    U64TO8_LE(len_block, aad_len);
    U64TO8_LE(len_block + 8, pt_len);
    poly1305_update(&poly, len_block, 16);

    // Finalize tag
    poly1305_finish(&poly, tag);

    return 0;
}

int chacha20poly1305_decrypt(uint8_t *pt,
                             const uint8_t *ct, size_t ct_len,
                             const uint8_t tag[16],
                             const uint8_t *aad, size_t aad_len,
                             const uint8_t nonce[12],
                             const uint8_t key[32]) {
    chacha20_ctx chacha;
    poly1305_ctx poly;
    uint8_t poly_key[64];
    uint8_t len_block[16];
    uint8_t computed_tag[16];

    // Generate Poly1305 key (block 0)
    chacha20_init(&chacha, key, nonce, 0);
    chacha20_block(&chacha, poly_key);

    // Initialize Poly1305 with first 32 bytes
    poly1305_init(&poly, poly_key);

    // Authenticate AAD
    if (aad_len > 0) {
        poly1305_update(&poly, aad, aad_len);
        pad16(&poly, aad_len);
    }

    // Authenticate ciphertext
    poly1305_update(&poly, ct, ct_len);
    pad16(&poly, ct_len);

    // Authenticate lengths (little-endian)
    U64TO8_LE(len_block, aad_len);
    U64TO8_LE(len_block + 8, ct_len);
    poly1305_update(&poly, len_block, 16);

    // Finalize and verify tag
    poly1305_finish(&poly, computed_tag);

    if (chacha20poly1305_verify(tag, computed_tag, 16) != 0) {
        // Authentication failed - clear output
        memset(pt, 0, ct_len);
        return -1;
    }

    // Decrypt ciphertext (starting from block 1)
    chacha20_init(&chacha, key, nonce, 1);
    chacha20_encrypt(&chacha, pt, ct, ct_len);

    return 0;
}

// ============================================================================
// Streaming AEAD API
// ============================================================================

void chacha20poly1305_encrypt_init(chacha20poly1305_ctx *ctx,
                                   const uint8_t nonce[12],
                                   const uint8_t key[32]) {
    uint8_t block[64];

    // Generate Poly1305 key (block 0)
    chacha20_init(&ctx->chacha, key, nonce, 0);
    chacha20_block(&ctx->chacha, block);
    memcpy(ctx->poly_key, block, 32);

    // Initialize Poly1305
    poly1305_init(&ctx->poly, ctx->poly_key);

    // Reset counters
    ctx->aad_len = 0;
    ctx->ct_len = 0;

    // Reinitialize ChaCha20 for encryption (starting at block 1)
    chacha20_init(&ctx->chacha, key, nonce, 1);
}

void chacha20poly1305_encrypt_aad(chacha20poly1305_ctx *ctx,
                                  const uint8_t *aad, size_t aad_len) {
    poly1305_update(&ctx->poly, aad, aad_len);
    ctx->aad_len += aad_len;
}

void chacha20poly1305_encrypt_update(chacha20poly1305_ctx *ctx,
                                     uint8_t *ct,
                                     const uint8_t *pt, size_t len) {
    // Pad AAD if this is first plaintext
    if (ctx->ct_len == 0 && ctx->aad_len > 0) {
        pad16(&ctx->poly, ctx->aad_len);
    }

    // Encrypt
    chacha20_encrypt(&ctx->chacha, ct, pt, len);

    // Authenticate ciphertext
    poly1305_update(&ctx->poly, ct, len);
    ctx->ct_len += len;
}

void chacha20poly1305_encrypt_final(chacha20poly1305_ctx *ctx,
                                    uint8_t tag[16]) {
    uint8_t len_block[16];

    // Pad ciphertext
    pad16(&ctx->poly, ctx->ct_len);

    // Authenticate lengths
    U64TO8_LE(len_block, ctx->aad_len);
    U64TO8_LE(len_block + 8, ctx->ct_len);
    poly1305_update(&ctx->poly, len_block, 16);

    // Finalize
    poly1305_finish(&ctx->poly, tag);
}

void chacha20poly1305_decrypt_init(chacha20poly1305_ctx *ctx,
                                   const uint8_t nonce[12],
                                   const uint8_t key[32]) {
    // Same as encrypt_init
    chacha20poly1305_encrypt_init(ctx, nonce, key);
}

void chacha20poly1305_decrypt_aad(chacha20poly1305_ctx *ctx,
                                  const uint8_t *aad, size_t aad_len) {
    poly1305_update(&ctx->poly, aad, aad_len);
    ctx->aad_len += aad_len;
}

void chacha20poly1305_decrypt_update(chacha20poly1305_ctx *ctx,
                                     uint8_t *pt,
                                     const uint8_t *ct, size_t len) {
    // Pad AAD if this is first ciphertext
    if (ctx->ct_len == 0 && ctx->aad_len > 0) {
        pad16(&ctx->poly, ctx->aad_len);
    }

    // Authenticate ciphertext first
    poly1305_update(&ctx->poly, ct, len);
    ctx->ct_len += len;

    // Decrypt
    chacha20_encrypt(&ctx->chacha, pt, ct, len);
}

int chacha20poly1305_decrypt_final(chacha20poly1305_ctx *ctx,
                                   const uint8_t tag[16]) {
    uint8_t len_block[16];
    uint8_t computed_tag[16];

    // Pad ciphertext
    pad16(&ctx->poly, ctx->ct_len);

    // Authenticate lengths
    U64TO8_LE(len_block, ctx->aad_len);
    U64TO8_LE(len_block + 8, ctx->ct_len);
    poly1305_update(&ctx->poly, len_block, 16);

    // Finalize
    poly1305_finish(&ctx->poly, computed_tag);

    // Verify
    return chacha20poly1305_verify(tag, computed_tag, 16);
}

// ============================================================================
// Utility Functions
// ============================================================================

int chacha20poly1305_verify(const uint8_t *a, const uint8_t *b, size_t len) {
    size_t i;
    uint8_t diff = 0;

    for (i = 0; i < len; i++) {
        diff |= a[i] ^ b[i];
    }

    return diff;
}

void chacha20poly1305_cleanse(void *ptr, size_t len) {
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (len--) {
        *p++ = 0;
    }
}
