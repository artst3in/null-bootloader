// ============================================================================
// Kernel Verification - Post-Quantum Signature Checking
// ============================================================================
// Module for verifying kernel signatures before execution.
// Integrates with the Limine protocol loader.
//
// Copyright 2025 The LunaOS Contributors
// SPDX-License-Identifier: BSD-2-Clause
// ============================================================================

#ifndef CRYPT__KERNEL_VERIFY_H__
#define CRYPT__KERNEL_VERIFY_H__

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

// ============================================================================
// Configuration
// ============================================================================

// Config file options:
//   KERNEL_VERIFY=yes      - Require signature verification (default if keys present)
//   KERNEL_VERIFY=no       - Skip verification (not recommended)
//   KERNEL_ENCRYPTED=yes   - Kernel is encrypted

// ============================================================================
// Verification API
// ============================================================================

/**
 * Initialize the kernel verification subsystem.
 * Called early in boot to check for embedded keys.
 *
 * @return true if verification is available
 */
bool kernel_verify_init(void);

/**
 * Check if kernel verification is enabled.
 * This depends on:
 *   1. Keys being embedded in bootloader
 *   2. KERNEL_VERIFY config option (defaults to yes if keys present)
 *
 * @return true if verification will be performed
 */
bool kernel_verify_enabled(void);

/**
 * Check if kernel decryption is enabled.
 * Based on KERNEL_ENCRYPTED config option.
 *
 * @return true if kernel should be decrypted
 */
bool kernel_decrypt_enabled(void);

/**
 * Process a kernel image: decrypt (if needed) and verify signature.
 *
 * This is the main entry point called from the Limine loader.
 * If verification fails, this function will panic and halt boot.
 *
 * @param kernel      Pointer to kernel data (may be modified in-place for decryption)
 * @param size        Size of kernel data
 * @param out_size    Output: actual kernel size after removing signature
 * @param config      Config string for checking options
 * @return true if kernel is valid and ready to boot
 */
bool kernel_verify_and_decrypt(uint8_t **kernel, size_t *size, char *config);

/**
 * Get the embedded public key (for display purposes).
 *
 * @param key_hash   Output: first 8 bytes of key hash (for identification)
 * @return true if keys are present
 */
bool kernel_verify_get_key_id(uint8_t key_hash[8]);

// ============================================================================
// Status Reporting
// ============================================================================

/**
 * Print verification status to console.
 * Shows key fingerprint and verification mode.
 */
void kernel_verify_print_status(void);

/**
 * Get human-readable error message for last failure.
 *
 * @return Error string or NULL if no error
 */
const char *kernel_verify_error(void);

#endif // CRYPT__KERNEL_VERIFY_H__
