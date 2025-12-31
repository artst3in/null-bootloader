// ============================================================================
// PQCrypto - Post-Quantum Cryptography Integration Layer
// ============================================================================
// Unified interface for bootloader cryptographic operations.
// Combines Dilithium-3, Kyber-1024, and ChaCha20-Poly1305.
//
// Purpose: Kernel signature verification and optional encryption.
//
// Copyright 2025 The LunaOS Contributors
// SPDX-License-Identifier: BSD-2-Clause
// ============================================================================

#ifndef CRYPT__PQCRYPTO_H__
#define CRYPT__PQCRYPTO_H__

#include <stddef.h>
#include <stdint.h>
#include <crypt/dilithium.h>
#include <crypt/kyber.h>
#include <crypt/chacha20poly1305.h>

// ============================================================================
// Constants
// ============================================================================

// Signature verification (NIST Dilithium-3 / ML-DSA)
#define PQCRYPTO_SIG_SIZE           DILITHIUM_SIGNATUREBYTES    // 3293 bytes (NIST)
#define PQCRYPTO_PUBKEY_SIZE        DILITHIUM_PUBLICKEYBYTES    // 1952 bytes
#define PQCRYPTO_SECKEY_SIZE        DILITHIUM_SECRETKEYBYTES    // 4032 bytes

// Encryption (Kyber-1024 + ChaCha20-Poly1305)
#define PQCRYPTO_ENCRYPTED_KEY_SIZE KYBER_CIPHERTEXTBYTES       // 1568 bytes
#define PQCRYPTO_SYMMETRIC_KEY_SIZE 32                          // 256-bit key
#define PQCRYPTO_NONCE_SIZE         12                          // 96-bit nonce
#define PQCRYPTO_TAG_SIZE           16                          // 128-bit tag

// Combined encrypted kernel header
#define PQCRYPTO_HEADER_SIZE        (PQCRYPTO_ENCRYPTED_KEY_SIZE + \
                                     PQCRYPTO_NONCE_SIZE + \
                                     PQCRYPTO_TAG_SIZE)           // 1596 bytes

// Error codes
#define PQCRYPTO_OK                 0
#define PQCRYPTO_ERR_SIGNATURE      -1
#define PQCRYPTO_ERR_DECRYPTION     -2
#define PQCRYPTO_ERR_INVALID_SIZE   -3
#define PQCRYPTO_ERR_NO_KEY         -4

// ============================================================================
// Embedded Key Structures
// ============================================================================

/**
 * Public keys embedded at build time.
 * These are compiled into the bootloader and cannot be modified at runtime.
 */
typedef struct {
    uint8_t dilithium_pk[DILITHIUM_PUBLICKEYBYTES];  // Signature verification
    uint8_t kyber_sk[KYBER_SECRETKEYBYTES];          // Decryption (secret key!)
    uint8_t valid;                                    // 1 if keys are loaded
} pqcrypto_keys;

// Global key storage (defined in pqcrypto.c or embedded_keys.c)
extern pqcrypto_keys pqcrypto_embedded_keys;

// ============================================================================
// Kernel Verification API
// ============================================================================

/**
 * Verify a kernel's Dilithium-3 signature.
 *
 * This is the primary security function. A kernel MUST have a valid
 * signature before execution.
 *
 * @param kernel      Kernel binary data
 * @param kernel_size Size of kernel in bytes
 * @param signature   Dilithium-3 signature (PQCRYPTO_SIG_SIZE bytes)
 * @return PQCRYPTO_OK if valid, PQCRYPTO_ERR_SIGNATURE if invalid
 */
int pqcrypto_verify_kernel(const uint8_t *kernel, size_t kernel_size,
                           const uint8_t *signature, size_t sig_size);

/**
 * Verify kernel using signature stored at end of kernel image.
 * This is the expected format for signed kernels:
 *   [kernel data][signature]
 *
 * @param kernel_image  Complete kernel image (data + signature)
 * @param total_size    Total size including signature
 * @param kernel_size   Output: actual kernel size (without signature)
 * @return PQCRYPTO_OK if valid
 */
int pqcrypto_verify_kernel_appended(const uint8_t *kernel_image,
                                    size_t total_size,
                                    size_t *kernel_size);

// ============================================================================
// Kernel Decryption API (Optional)
// ============================================================================

/**
 * Decrypt an encrypted kernel.
 *
 * Encrypted kernel format:
 *   [Kyber ciphertext (1568 bytes)][Nonce (12 bytes)][Tag (16 bytes)][Encrypted data]
 *
 * Process:
 *   1. Decapsulate Kyber ciphertext to recover symmetric key
 *   2. Decrypt kernel using ChaCha20-Poly1305 with embedded nonce
 *   3. Verify authentication tag
 *
 * @param encrypted     Encrypted kernel (header + ciphertext)
 * @param encrypted_size Total encrypted size
 * @param plaintext     Output: Decrypted kernel (must be large enough)
 * @param plaintext_size Output: Size of decrypted kernel
 * @return PQCRYPTO_OK on success, PQCRYPTO_ERR_DECRYPTION on failure
 */
int pqcrypto_decrypt_kernel(const uint8_t *encrypted, size_t encrypted_size,
                            uint8_t *plaintext, size_t *plaintext_size);

/**
 * Check if a kernel is encrypted (by examining header magic).
 *
 * @param data  Start of kernel data
 * @param size  Size of data
 * @return 1 if encrypted, 0 if plaintext
 */
int pqcrypto_is_encrypted(const uint8_t *data, size_t size);

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
 * @return PQCRYPTO_OK on success
 */
int pqcrypto_load_kernel(const uint8_t *kernel_image, size_t image_size,
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
int pqcrypto_keys_available(void);

/**
 * Initialize the crypto subsystem.
 * Called early in boot to validate embedded keys.
 *
 * @return PQCRYPTO_OK if ready
 */
int pqcrypto_init(void);

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Securely clear sensitive memory.
 *
 * @param ptr  Pointer to memory
 * @param len  Length to clear
 */
void pqcrypto_cleanse(void *ptr, size_t len);

/**
 * Constant-time memory comparison.
 *
 * @param a    First buffer
 * @param b    Second buffer
 * @param len  Length to compare
 * @return 0 if equal, non-zero otherwise
 */
int pqcrypto_verify_equal(const uint8_t *a, const uint8_t *b, size_t len);

#endif // CRYPT__PQCRYPTO_H__
