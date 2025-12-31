// ============================================================================
// PQCrypto - Post-Quantum Cryptography Integration Layer
// ============================================================================
// Unified interface for bootloader cryptographic operations.
//
// Copyright 2025 The LunaOS Contributors
// SPDX-License-Identifier: BSD-2-Clause
// ============================================================================

#include <stdint.h>
#include <stddef.h>
#include <crypt/pqcrypto.h>
#include <lib/libc.h>

// ============================================================================
// Embedded Keys
// ============================================================================

// Try to include generated keys (created by luna_sign export)
#if __has_include("embedded_keys.h")
#include "embedded_keys.h"
#define HAVE_EMBEDDED_KEYS 1
#else
#define HAVE_EMBEDDED_KEYS 0
static const uint8_t DILITHIUM_PUBLIC_KEY[DILITHIUM_PUBLICKEYBYTES] = {0};
#endif

// Keys are copied from DILITHIUM_PUBLIC_KEY in pqcrypto_init()
pqcrypto_keys pqcrypto_embedded_keys = {
    .dilithium_pk = {0},
    .kyber_sk = {0},
    .valid = 0
};

// Magic bytes to identify encrypted kernel
static const uint8_t ENCRYPTED_MAGIC[8] = {
    'L', 'U', 'N', 'A', 'E', 'N', 'C', '1'
};

// ============================================================================
// Utility Functions
// ============================================================================

void pqcrypto_cleanse(void *ptr, size_t len) {
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (len--) {
        *p++ = 0;
    }
}

int pqcrypto_verify_equal(const uint8_t *a, const uint8_t *b, size_t len) {
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= a[i] ^ b[i];
    }
    return diff;
}

// ============================================================================
// Key Management
// ============================================================================

int pqcrypto_keys_available(void) {
    return pqcrypto_embedded_keys.valid != 0;
}

int pqcrypto_init(void) {
    // Copy embedded key to runtime structure
    memcpy(pqcrypto_embedded_keys.dilithium_pk, DILITHIUM_PUBLIC_KEY,
           DILITHIUM_PUBLICKEYBYTES);

    // Validate that keys are present
    // Check if dilithium public key has any non-zero bytes
    uint8_t any_nonzero = 0;
    for (size_t i = 0; i < DILITHIUM_PUBLICKEYBYTES; i++) {
        any_nonzero |= pqcrypto_embedded_keys.dilithium_pk[i];
    }

    if (any_nonzero) {
        pqcrypto_embedded_keys.valid = 1;
    }

    return pqcrypto_embedded_keys.valid ? PQCRYPTO_OK : PQCRYPTO_ERR_NO_KEY;
}

// ============================================================================
// Kernel Verification
// ============================================================================

int pqcrypto_verify_kernel(const uint8_t *kernel, size_t kernel_size,
                           const uint8_t *signature, size_t sig_size) {
    if (!pqcrypto_keys_available()) {
        return PQCRYPTO_ERR_NO_KEY;
    }

    if (sig_size != PQCRYPTO_SIG_SIZE) {
        return PQCRYPTO_ERR_INVALID_SIZE;
    }

    int result = dilithium_verify(signature, sig_size,
                                  kernel, kernel_size,
                                  pqcrypto_embedded_keys.dilithium_pk);

    return (result == 0) ? PQCRYPTO_OK : PQCRYPTO_ERR_SIGNATURE;
}

int pqcrypto_verify_kernel_appended(const uint8_t *kernel_image,
                                    size_t total_size,
                                    size_t *kernel_size) {
    if (total_size < PQCRYPTO_SIG_SIZE) {
        return PQCRYPTO_ERR_INVALID_SIZE;
    }

    size_t ksize = total_size - PQCRYPTO_SIG_SIZE;
    const uint8_t *signature = kernel_image + ksize;

    int result = pqcrypto_verify_kernel(kernel_image, ksize, signature, PQCRYPTO_SIG_SIZE);
    if (result == PQCRYPTO_OK) {
        if (kernel_size) {
            *kernel_size = ksize;
        }
    }

    return result;
}

// ============================================================================
// Kernel Decryption
// ============================================================================

int pqcrypto_is_encrypted(const uint8_t *data, size_t size) {
    if (size < sizeof(ENCRYPTED_MAGIC)) {
        return 0;
    }
    return memcmp(data, ENCRYPTED_MAGIC, sizeof(ENCRYPTED_MAGIC)) == 0;
}

int pqcrypto_decrypt_kernel(const uint8_t *encrypted, size_t encrypted_size,
                            uint8_t *plaintext, size_t *plaintext_size) {
    if (!pqcrypto_keys_available()) {
        return PQCRYPTO_ERR_NO_KEY;
    }

    // Encrypted format:
    // [Magic (8)][Kyber ciphertext (1568)][Nonce (12)][Tag (16)][Encrypted data]
    const size_t header_size = 8 + KYBER_CIPHERTEXTBYTES +
                               PQCRYPTO_NONCE_SIZE + PQCRYPTO_TAG_SIZE;

    if (encrypted_size < header_size) {
        return PQCRYPTO_ERR_INVALID_SIZE;
    }

    // Verify magic
    if (memcmp(encrypted, ENCRYPTED_MAGIC, sizeof(ENCRYPTED_MAGIC)) != 0) {
        return PQCRYPTO_ERR_DECRYPTION;
    }

    const uint8_t *kyber_ct = encrypted + 8;
    const uint8_t *nonce = kyber_ct + KYBER_CIPHERTEXTBYTES;
    const uint8_t *tag = nonce + PQCRYPTO_NONCE_SIZE;
    const uint8_t *ciphertext = tag + PQCRYPTO_TAG_SIZE;
    size_t ciphertext_len = encrypted_size - header_size;

    // Step 1: Decapsulate to get symmetric key
    uint8_t symmetric_key[KYBER_SSBYTES];
    int result = kyber_decapsulate(symmetric_key, kyber_ct,
                                   pqcrypto_embedded_keys.kyber_sk);
    if (result != 0) {
        pqcrypto_cleanse(symmetric_key, sizeof(symmetric_key));
        return PQCRYPTO_ERR_DECRYPTION;
    }

    // Step 2: Decrypt with ChaCha20-Poly1305
    result = chacha20poly1305_decrypt(plaintext, ciphertext, ciphertext_len,
                                      tag, NULL, 0, nonce, symmetric_key);

    pqcrypto_cleanse(symmetric_key, sizeof(symmetric_key));

    if (result != 0) {
        return PQCRYPTO_ERR_DECRYPTION;
    }

    if (plaintext_size) {
        *plaintext_size = ciphertext_len;
    }

    return PQCRYPTO_OK;
}

// ============================================================================
// Combined Operations
// ============================================================================

int pqcrypto_load_kernel(const uint8_t *kernel_image, size_t image_size,
                         uint8_t *output, size_t *output_size,
                         int *was_encrypted) {
    int encrypted = pqcrypto_is_encrypted(kernel_image, image_size);

    if (was_encrypted) {
        *was_encrypted = encrypted;
    }

    if (encrypted) {
        // Decrypt first
        size_t decrypted_size = 0;
        int result = pqcrypto_decrypt_kernel(kernel_image, image_size,
                                             output, &decrypted_size);
        if (result != PQCRYPTO_OK) {
            return result;
        }

        // Now verify the decrypted kernel (signature should be appended)
        size_t kernel_size = 0;
        result = pqcrypto_verify_kernel_appended(output, decrypted_size,
                                                 &kernel_size);
        if (result != PQCRYPTO_OK) {
            pqcrypto_cleanse(output, decrypted_size);
            return result;
        }

        if (output_size) {
            *output_size = kernel_size;
        }
    } else {
        // Not encrypted - just verify signature
        size_t kernel_size = 0;
        int result = pqcrypto_verify_kernel_appended(kernel_image, image_size,
                                                     &kernel_size);
        if (result != PQCRYPTO_OK) {
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

    return PQCRYPTO_OK;
}
