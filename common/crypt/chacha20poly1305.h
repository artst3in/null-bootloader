// ============================================================================
// ChaCha20-Poly1305 - Authenticated Encryption with Associated Data (AEAD)
// ============================================================================
// RFC 8439 implementation for bootloader use.
// Provides authenticated encryption using ChaCha20 stream cipher and
// Poly1305 message authentication code.
//
// Security: 256-bit key, 96-bit nonce, 128-bit authentication tag
//
// Copyright 2025 The LunaOS Contributors
// SPDX-License-Identifier: BSD-2-Clause
// ============================================================================

#ifndef CRYPT__CHACHA20POLY1305_H__
#define CRYPT__CHACHA20POLY1305_H__

#include <stddef.h>
#include <stdint.h>

// ============================================================================
// Constants
// ============================================================================

#define CHACHA20_KEY_SIZE       32      // 256-bit key
#define CHACHA20_NONCE_SIZE     12      // 96-bit nonce (RFC 8439)
#define CHACHA20_BLOCK_SIZE     64      // 512-bit block

#define POLY1305_KEY_SIZE       32      // 256-bit key (r + s)
#define POLY1305_TAG_SIZE       16      // 128-bit tag

#define CHACHA20POLY1305_KEY_SIZE   CHACHA20_KEY_SIZE
#define CHACHA20POLY1305_NONCE_SIZE CHACHA20_NONCE_SIZE
#define CHACHA20POLY1305_TAG_SIZE   POLY1305_TAG_SIZE

// ============================================================================
// ChaCha20 Stream Cipher
// ============================================================================

/**
 * ChaCha20 state (16 x 32-bit words)
 */
typedef struct {
    uint32_t state[16];
} chacha20_ctx;

/**
 * Initialize ChaCha20 context with key and nonce.
 *
 * @param ctx   Output: ChaCha20 context
 * @param key   256-bit key (32 bytes)
 * @param nonce 96-bit nonce (12 bytes)
 * @param counter Initial block counter (usually 0 or 1)
 */
void chacha20_init(chacha20_ctx *ctx, const uint8_t key[32],
                   const uint8_t nonce[12], uint32_t counter);

/**
 * Generate keystream block.
 *
 * @param ctx   ChaCha20 context (counter incremented after call)
 * @param out   Output: 64-byte keystream block
 */
void chacha20_block(chacha20_ctx *ctx, uint8_t out[64]);

/**
 * Encrypt/decrypt data using ChaCha20.
 * XORs input with keystream - same function for encrypt and decrypt.
 *
 * @param ctx   ChaCha20 context
 * @param out   Output: ciphertext/plaintext
 * @param in    Input: plaintext/ciphertext
 * @param len   Length of data
 */
void chacha20_encrypt(chacha20_ctx *ctx, uint8_t *out,
                      const uint8_t *in, size_t len);

// ============================================================================
// Poly1305 Message Authentication Code
// ============================================================================

/**
 * Poly1305 authenticator state
 */
typedef struct {
    uint32_t r[5];      // Clamped key r
    uint32_t h[5];      // Accumulator
    uint32_t pad[4];    // One-time key s
    size_t leftover;
    uint8_t buffer[16];
    uint8_t final;
} poly1305_ctx;

/**
 * Initialize Poly1305 context with one-time key.
 *
 * @param ctx   Output: Poly1305 context
 * @param key   One-time key (32 bytes: r || s)
 */
void poly1305_init(poly1305_ctx *ctx, const uint8_t key[32]);

/**
 * Add data to Poly1305 computation.
 *
 * @param ctx   Poly1305 context
 * @param m     Input data
 * @param len   Length of data
 */
void poly1305_update(poly1305_ctx *ctx, const uint8_t *m, size_t len);

/**
 * Finalize Poly1305 and output tag.
 *
 * @param ctx   Poly1305 context
 * @param tag   Output: 16-byte authentication tag
 */
void poly1305_finish(poly1305_ctx *ctx, uint8_t tag[16]);

/**
 * One-shot Poly1305 MAC computation.
 *
 * @param tag   Output: 16-byte authentication tag
 * @param m     Input message
 * @param mlen  Length of message
 * @param key   One-time key (32 bytes)
 */
void poly1305_auth(uint8_t tag[16], const uint8_t *m, size_t mlen,
                   const uint8_t key[32]);

// ============================================================================
// ChaCha20-Poly1305 AEAD
// ============================================================================

/**
 * AEAD context for ChaCha20-Poly1305
 */
typedef struct {
    chacha20_ctx chacha;
    poly1305_ctx poly;
    uint8_t poly_key[32];
    uint64_t aad_len;
    uint64_t ct_len;
} chacha20poly1305_ctx;

/**
 * Encrypt with ChaCha20-Poly1305 AEAD.
 *
 * @param ct        Output: Ciphertext (same length as pt)
 * @param tag       Output: Authentication tag (16 bytes)
 * @param pt        Input: Plaintext
 * @param pt_len    Length of plaintext
 * @param aad       Associated data (authenticated but not encrypted)
 * @param aad_len   Length of associated data
 * @param nonce     96-bit nonce (12 bytes)
 * @param key       256-bit key (32 bytes)
 * @return 0 on success
 */
int chacha20poly1305_encrypt(uint8_t *ct, uint8_t tag[16],
                             const uint8_t *pt, size_t pt_len,
                             const uint8_t *aad, size_t aad_len,
                             const uint8_t nonce[12],
                             const uint8_t key[32]);

/**
 * Decrypt with ChaCha20-Poly1305 AEAD.
 *
 * @param pt        Output: Plaintext (same length as ct)
 * @param ct        Input: Ciphertext
 * @param ct_len    Length of ciphertext
 * @param tag       Input: Authentication tag (16 bytes)
 * @param aad       Associated data (must match encryption)
 * @param aad_len   Length of associated data
 * @param nonce     96-bit nonce (12 bytes)
 * @param key       256-bit key (32 bytes)
 * @return 0 on success, -1 if authentication fails
 */
int chacha20poly1305_decrypt(uint8_t *pt,
                             const uint8_t *ct, size_t ct_len,
                             const uint8_t tag[16],
                             const uint8_t *aad, size_t aad_len,
                             const uint8_t nonce[12],
                             const uint8_t key[32]);

/**
 * Encrypt with detached tag (same as chacha20poly1305_encrypt).
 * Alias for clarity when tag storage is separate from ciphertext.
 */
#define chacha20poly1305_encrypt_detached chacha20poly1305_encrypt

/**
 * Decrypt with detached tag (same as chacha20poly1305_decrypt).
 * Alias for clarity when tag storage is separate from ciphertext.
 */
#define chacha20poly1305_decrypt_detached chacha20poly1305_decrypt

// ============================================================================
// Streaming AEAD API (for large files)
// ============================================================================

/**
 * Initialize streaming encryption.
 *
 * @param ctx       Output: AEAD context
 * @param nonce     96-bit nonce (12 bytes)
 * @param key       256-bit key (32 bytes)
 */
void chacha20poly1305_encrypt_init(chacha20poly1305_ctx *ctx,
                                   const uint8_t nonce[12],
                                   const uint8_t key[32]);

/**
 * Add associated data (must be called before encrypt_update).
 *
 * @param ctx       AEAD context
 * @param aad       Associated data
 * @param aad_len   Length of associated data
 */
void chacha20poly1305_encrypt_aad(chacha20poly1305_ctx *ctx,
                                  const uint8_t *aad, size_t aad_len);

/**
 * Encrypt data chunk.
 *
 * @param ctx       AEAD context
 * @param ct        Output: Ciphertext
 * @param pt        Input: Plaintext
 * @param len       Length of data
 */
void chacha20poly1305_encrypt_update(chacha20poly1305_ctx *ctx,
                                     uint8_t *ct,
                                     const uint8_t *pt, size_t len);

/**
 * Finalize encryption and output tag.
 *
 * @param ctx       AEAD context
 * @param tag       Output: Authentication tag (16 bytes)
 */
void chacha20poly1305_encrypt_final(chacha20poly1305_ctx *ctx,
                                    uint8_t tag[16]);

/**
 * Initialize streaming decryption.
 *
 * @param ctx       Output: AEAD context
 * @param nonce     96-bit nonce (12 bytes)
 * @param key       256-bit key (32 bytes)
 */
void chacha20poly1305_decrypt_init(chacha20poly1305_ctx *ctx,
                                   const uint8_t nonce[12],
                                   const uint8_t key[32]);

/**
 * Add associated data (must be called before decrypt_update).
 *
 * @param ctx       AEAD context
 * @param aad       Associated data
 * @param aad_len   Length of associated data
 */
void chacha20poly1305_decrypt_aad(chacha20poly1305_ctx *ctx,
                                  const uint8_t *aad, size_t aad_len);

/**
 * Decrypt data chunk (does not verify tag).
 *
 * @param ctx       AEAD context
 * @param pt        Output: Plaintext
 * @param ct        Input: Ciphertext
 * @param len       Length of data
 */
void chacha20poly1305_decrypt_update(chacha20poly1305_ctx *ctx,
                                     uint8_t *pt,
                                     const uint8_t *ct, size_t len);

/**
 * Finalize decryption and verify tag.
 *
 * @param ctx       AEAD context
 * @param tag       Input: Expected authentication tag (16 bytes)
 * @return 0 if tag matches, -1 if authentication fails
 */
int chacha20poly1305_decrypt_final(chacha20poly1305_ctx *ctx,
                                   const uint8_t tag[16]);

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Constant-time comparison of two tags.
 *
 * @param a     First tag
 * @param b     Second tag
 * @param len   Length to compare
 * @return 0 if equal, non-zero otherwise
 */
int chacha20poly1305_verify(const uint8_t *a, const uint8_t *b, size_t len);

/**
 * Securely clear memory.
 *
 * @param ptr   Pointer to memory
 * @param len   Length to clear
 */
void chacha20poly1305_cleanse(void *ptr, size_t len);

#endif // CRYPT__CHACHA20POLY1305_H__
