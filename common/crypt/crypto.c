// ============================================================================
// Crypto - Classical Cryptography Integration Layer
// ============================================================================
// Unified interface for bootloader cryptographic operations.
//
// Copyright 2026 The LunaOS Contributors
// SPDX-License-Identifier: BSD-2-Clause
// ============================================================================

#include <stdint.h>
#include <stddef.h>
#include <crypt/crypto.h>
#include <lib/libc.h>

// ============================================================================
// Embedded Keys
// ============================================================================

// Try to include generated keys (created by luna_sign export)
#if __has_include("embedded_keys_classical.h")
#include "embedded_keys_classical.h"
#define HAVE_EMBEDDED_KEYS 1
#else
#define HAVE_EMBEDDED_KEYS 0
static const uint8_t ED25519_PUBLIC_KEY[ED25519_PUBLICKEYBYTES] = {0};
#endif

// Provide default for X25519_SECRET_KEY if not defined
#ifndef HAVE_X25519_KEY
#define HAVE_X25519_KEY 0
#endif

#if !HAVE_X25519_KEY
static const uint8_t X25519_SECRET_KEY[X25519_SECRETKEYBYTES] = {0};
#endif

// Keys are copied from embedded arrays in crypto_init()
crypto_keys crypto_embedded_keys = {
    .ed25519_pk = {0},
    .x25519_sk = {0},
    .valid = 0,
    .has_encryption = 0
};

// Magic bytes to identify encrypted kernel
static const uint8_t ENCRYPTED_MAGIC[8] = {
    'L', 'U', 'N', 'A', 'E', 'N', 'C', '2'  // Version 2 for classical crypto
};

// ============================================================================
// Utility Functions
// ============================================================================

void crypto_cleanse(void *ptr, size_t len) {
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (len--) {
        *p++ = 0;
    }
}

int crypto_verify_equal(const uint8_t *a, const uint8_t *b, size_t len) {
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= a[i] ^ b[i];
    }
    return diff;
}

// ============================================================================
// Key Management
// ============================================================================

int crypto_keys_available(void) {
    return crypto_embedded_keys.valid != 0;
}

int crypto_init(void) {
    // Copy Ed25519 public key to runtime structure
    memcpy(crypto_embedded_keys.ed25519_pk, ED25519_PUBLIC_KEY,
           ED25519_PUBLICKEYBYTES);

    // Validate Ed25519 key is present (has non-zero bytes)
    uint8_t any_nonzero = 0;
    for (size_t i = 0; i < ED25519_PUBLICKEYBYTES; i++) {
        any_nonzero |= crypto_embedded_keys.ed25519_pk[i];
    }

    if (any_nonzero) {
        crypto_embedded_keys.valid = 1;
    }

    // Copy X25519 secret key if available
#if HAVE_X25519_KEY
    memcpy(crypto_embedded_keys.x25519_sk, X25519_SECRET_KEY,
           X25519_SECRETKEYBYTES);

    // Validate X25519 key is present
    any_nonzero = 0;
    for (size_t i = 0; i < X25519_SECRETKEYBYTES; i++) {
        any_nonzero |= crypto_embedded_keys.x25519_sk[i];
    }
    if (any_nonzero) {
        crypto_embedded_keys.has_encryption = 1;
    }
#endif

    return crypto_embedded_keys.valid ? CRYPTO_OK : CRYPTO_ERR_NO_KEY;
}

// ============================================================================
// Kernel Verification
// ============================================================================

int crypto_verify_kernel(const uint8_t *kernel, size_t kernel_size,
                         const uint8_t *signature, size_t sig_size) {
    if (!crypto_embedded_keys.valid) {
        return CRYPTO_ERR_NO_KEY;
    }

    if (sig_size != CRYPTO_SIG_SIZE) {
        return CRYPTO_ERR_INVALID_SIZE;
    }

    int result = ed25519_verify(signature, kernel, kernel_size,
                                crypto_embedded_keys.ed25519_pk);

    return (result == 0) ? CRYPTO_OK : CRYPTO_ERR_SIGNATURE;
}

int crypto_verify_kernel_appended(const uint8_t *kernel_image,
                                  size_t total_size,
                                  size_t *kernel_size) {
    if (total_size < CRYPTO_SIG_SIZE) {
        return CRYPTO_ERR_INVALID_SIZE;
    }

    size_t ksize = total_size - CRYPTO_SIG_SIZE;
    const uint8_t *signature = kernel_image + ksize;

    int result = crypto_verify_kernel(kernel_image, ksize, signature, CRYPTO_SIG_SIZE);
    if (result == CRYPTO_OK) {
        if (kernel_size) {
            *kernel_size = ksize;
        }
    }

    return result;
}

// ============================================================================
// Kernel Decryption
// ============================================================================

int crypto_is_encrypted(const uint8_t *data, size_t size) {
    if (size < sizeof(ENCRYPTED_MAGIC)) {
        return 0;
    }
    return memcmp(data, ENCRYPTED_MAGIC, sizeof(ENCRYPTED_MAGIC)) == 0;
}

int crypto_decrypt_kernel(const uint8_t *encrypted, size_t encrypted_size,
                          uint8_t *plaintext, size_t *plaintext_size) {
    if (!crypto_embedded_keys.has_encryption) {
        return CRYPTO_ERR_NO_KEY;
    }

    // Encrypted format:
    // [Magic (8)][Ephemeral X25519 pubkey (32)][Nonce (12)][Tag (16)][Encrypted data]
    const size_t header_size = 8 + X25519_PUBLICKEYBYTES +
                               CRYPTO_NONCE_SIZE + CRYPTO_TAG_SIZE;

    if (encrypted_size < header_size) {
        return CRYPTO_ERR_INVALID_SIZE;
    }

    // Verify magic
    if (memcmp(encrypted, ENCRYPTED_MAGIC, sizeof(ENCRYPTED_MAGIC)) != 0) {
        return CRYPTO_ERR_DECRYPTION;
    }

    const uint8_t *ephemeral_pk = encrypted + 8;
    const uint8_t *nonce = ephemeral_pk + X25519_PUBLICKEYBYTES;
    const uint8_t *tag = nonce + CRYPTO_NONCE_SIZE;
    const uint8_t *ciphertext = tag + CRYPTO_TAG_SIZE;
    size_t ciphertext_len = encrypted_size - header_size;

    // Step 1: Derive shared secret via X25519
    uint8_t shared_secret[X25519_SHAREDSECRETBYTES];
    int result = x25519(shared_secret, crypto_embedded_keys.x25519_sk, ephemeral_pk);
    if (result != 0) {
        crypto_cleanse(shared_secret, sizeof(shared_secret));
        return CRYPTO_ERR_DECRYPTION;
    }

    // Step 2: Decrypt with ChaCha20-Poly1305
    result = chacha20poly1305_decrypt(plaintext, ciphertext, ciphertext_len,
                                      tag, NULL, 0, nonce, shared_secret);

    crypto_cleanse(shared_secret, sizeof(shared_secret));

    if (result != 0) {
        return CRYPTO_ERR_DECRYPTION;
    }

    if (plaintext_size) {
        *plaintext_size = ciphertext_len;
    }

    return CRYPTO_OK;
}

// ============================================================================
// Combined Operations
// ============================================================================

int crypto_load_kernel(const uint8_t *kernel_image, size_t image_size,
                       uint8_t *output, size_t *output_size,
                       int *was_encrypted) {
    int encrypted = crypto_is_encrypted(kernel_image, image_size);

    if (was_encrypted) {
        *was_encrypted = encrypted;
    }

    if (encrypted) {
        // Decrypt first
        size_t decrypted_size = 0;
        int result = crypto_decrypt_kernel(kernel_image, image_size,
                                           output, &decrypted_size);
        if (result != CRYPTO_OK) {
            return result;
        }

        // Now verify the decrypted kernel (signature should be appended)
        size_t kernel_size = 0;
        result = crypto_verify_kernel_appended(output, decrypted_size,
                                               &kernel_size);
        if (result != CRYPTO_OK) {
            crypto_cleanse(output, decrypted_size);
            return result;
        }

        if (output_size) {
            *output_size = kernel_size;
        }
    } else {
        // Not encrypted - just verify signature
        size_t kernel_size = 0;
        int result = crypto_verify_kernel_appended(kernel_image, image_size,
                                                   &kernel_size);
        if (result != CRYPTO_OK) {
            return result;
        }

        // Copy to output buffer (without signature)
        if (output && output != kernel_image) {
            memcpy(output, kernel_image, kernel_size);
        }

        if (output_size) {
            *output_size = kernel_size;
        }
    }

    return CRYPTO_OK;
}
