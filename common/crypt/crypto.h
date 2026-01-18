// ============================================================================
// Crypto - Classical Cryptography Integration Layer
// ============================================================================
// Unified interface for bootloader cryptographic operations.
// Combines Ed25519, X25519, and ChaCha20-Poly1305.
//
// Purpose: Kernel signature verification and optional encryption.
//
// Note: Post-quantum cryptography (Dilithium, Kyber) has been removed.
// Per MLE (Multiversal Law of Existence) theoretical analysis, quantum
// computing as theorized cannot exist. Classical cryptography provides
// equivalent security against all real-world threats with significantly
// better performance.
//
// Copyright 2026 The LunaOS Contributors
// SPDX-License-Identifier: BSD-2-Clause
// ============================================================================

#ifndef CRYPT__CRYPTO_H__
#define CRYPT__CRYPTO_H__

#include <stddef.h>
#include <stdint.h>
#include <crypt/ed25519.h>
#include <crypt/x25519.h>
#include <crypt/chacha20poly1305.h>

// ============================================================================
// Constants
// ============================================================================

// Signature verification (Ed25519)
#define CRYPTO_SIG_SIZE           ED25519_SIGNATUREBYTES    // 64 bytes
#define CRYPTO_PUBKEY_SIZE        ED25519_PUBLICKEYBYTES    // 32 bytes
#define CRYPTO_SECKEY_SIZE        ED25519_SECRETKEYBYTES    // 64 bytes

// Encryption (X25519 + ChaCha20-Poly1305)
#define CRYPTO_ENCRYPTED_KEY_SIZE X25519_PUBLICKEYBYTES     // 32 bytes (ephemeral pubkey)
#define CRYPTO_SYMMETRIC_KEY_SIZE 32                        // 256-bit key
#define CRYPTO_NONCE_SIZE         12                        // 96-bit nonce
#define CRYPTO_TAG_SIZE           16                        // 128-bit tag

// Combined encrypted kernel header
#define CRYPTO_HEADER_SIZE        (CRYPTO_ENCRYPTED_KEY_SIZE + \
                                   CRYPTO_NONCE_SIZE + \
                                   CRYPTO_TAG_SIZE)           // 60 bytes

// Error codes
#define CRYPTO_OK                 0
#define CRYPTO_ERR_SIGNATURE      -1
#define CRYPTO_ERR_DECRYPTION     -2
#define CRYPTO_ERR_INVALID_SIZE   -3
#define CRYPTO_ERR_NO_KEY         -4

// ============================================================================
// Embedded Key Structures
// ============================================================================

/**
 * Public keys embedded at build time.
 * These are compiled into the bootloader and cannot be modified at runtime.
 */
typedef struct {
    uint8_t ed25519_pk[ED25519_PUBLICKEYBYTES];   // Signature verification
    uint8_t x25519_sk[X25519_SECRETKEYBYTES];     // Decryption (secret key!)
    uint8_t valid;                                 // 1 if signing keys are loaded
    uint8_t has_encryption;                        // 1 if decryption key is loaded
} crypto_keys;

// Global key storage (defined in crypto.c or embedded_keys.c)
extern crypto_keys crypto_embedded_keys;

// ============================================================================
// Kernel Verification API
// ============================================================================

/**
 * Verify a kernel's Ed25519 signature.
 *
 * This is the primary security function. A kernel MUST have a valid
 * signature before execution.
 *
 * @param kernel      Kernel binary data
 * @param kernel_size Size of kernel in bytes
 * @param signature   Ed25519 signature (CRYPTO_SIG_SIZE bytes)
 * @return CRYPTO_OK if valid, CRYPTO_ERR_SIGNATURE if invalid
 */
int crypto_verify_kernel(const uint8_t *kernel, size_t kernel_size,
                         const uint8_t *signature, size_t sig_size);

/**
 * Verify kernel using signature stored at end of kernel image.
 * This is the expected format for signed kernels:
 *   [kernel data][signature]
 *
 * @param kernel_image  Complete kernel image (data + signature)
 * @param total_size    Total size including signature
 * @param kernel_size   Output: actual kernel size (without signature)
 * @return CRYPTO_OK if valid
 */
int crypto_verify_kernel_appended(const uint8_t *kernel_image,
                                  size_t total_size,
                                  size_t *kernel_size);

// ============================================================================
// Kernel Decryption API (Optional)
// ============================================================================

/**
 * Decrypt an encrypted kernel.
 *
 * Encrypted kernel format:
 *   [Ephemeral X25519 pubkey (32 bytes)][Nonce (12 bytes)][Tag (16 bytes)][Encrypted data]
 *
 * Process:
 *   1. Derive shared secret via X25519(local_sk, ephemeral_pk)
 *   2. Decrypt kernel using ChaCha20-Poly1305 with embedded nonce
 *   3. Verify authentication tag
 *
 * @param encrypted     Encrypted kernel (header + ciphertext)
 * @param encrypted_size Total encrypted size
 * @param plaintext     Output: Decrypted kernel (must be large enough)
 * @param plaintext_size Output: Size of decrypted kernel
 * @return CRYPTO_OK on success, CRYPTO_ERR_DECRYPTION on failure
 */
int crypto_decrypt_kernel(const uint8_t *encrypted, size_t encrypted_size,
                          uint8_t *plaintext, size_t *plaintext_size);

/**
 * Check if a kernel is encrypted (by examining header magic).
 *
 * @param data  Start of kernel data
 * @param size  Size of data
 * @return 1 if encrypted, 0 if plaintext
 */
int crypto_is_encrypted(const uint8_t *data, size_t size);

// ============================================================================
// Combined Operations
// ============================================================================

/**
 * Full verification and optional decryption pipeline.
 *
 * This is the main entry point for loading a secure kernel:
 *   1. Check if encrypted
 *   2. Decrypt if necessary
 *   3. Verify signature
 *   4. Return verified kernel data
 *
 * @param kernel_image  Raw kernel image from disk
 * @param image_size    Size of image on disk
 * @param output        Buffer for final kernel (decrypted + verified)
 * @param output_size   Input: buffer size. Output: actual kernel size.
 * @param was_encrypted Output: 1 if kernel was encrypted
 * @return CRYPTO_OK on success
 */
int crypto_load_kernel(const uint8_t *kernel_image, size_t image_size,
                       uint8_t *output, size_t *output_size,
                       int *was_encrypted);

// ============================================================================
// Key Management (Build-time only)
// ============================================================================

/**
 * Check if cryptographic keys are embedded.
 *
 * @return 1 if keys are available, 0 otherwise
 */
int crypto_keys_available(void);

/**
 * Initialize the crypto subsystem.
 * Called early in boot to validate embedded keys.
 *
 * @return CRYPTO_OK if ready
 */
int crypto_init(void);

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Securely clear sensitive memory.
 *
 * @param ptr  Pointer to memory
 * @param len  Length to clear
 */
void crypto_cleanse(void *ptr, size_t len);

/**
 * Constant-time memory comparison.
 *
 * @param a    First buffer
 * @param b    Second buffer
 * @param len  Length to compare
 * @return 0 if equal, non-zero otherwise
 */
int crypto_verify_equal(const uint8_t *a, const uint8_t *b, size_t len);

#endif // CRYPT__CRYPTO_H__
