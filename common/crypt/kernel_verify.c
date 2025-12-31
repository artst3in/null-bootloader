// ============================================================================
// Kernel Verification - Post-Quantum Signature Checking
// ============================================================================
// Module for verifying kernel signatures before execution.
//
// Copyright 2025 The LunaOS Contributors
// SPDX-License-Identifier: BSD-2-Clause
// ============================================================================

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <crypt/kernel_verify.h>
#include <crypt/pqcrypto.h>
#include <crypt/shake.h>
#include <lib/config.h>
#include <lib/print.h>
#include <lib/libc.h>

// ============================================================================
// State
// ============================================================================

static bool verify_initialized = false;
static bool keys_present = false;
static const char *last_error = NULL;

// ============================================================================
// Initialization
// ============================================================================

bool kernel_verify_init(void) {
    if (verify_initialized) {
        return keys_present;
    }

    int result = pqcrypto_init();
    keys_present = (result == PQCRYPTO_OK);
    verify_initialized = true;

    if (keys_present) {
        print("pqcrypto: Signature verification keys loaded\n");
    } else {
        print("pqcrypto: No signing keys embedded (verification disabled)\n");
    }

    return keys_present;
}

bool kernel_verify_enabled(void) {
    return keys_present;
}

bool kernel_decrypt_enabled(void) {
    // This would be set from config
    return false;
}

// ============================================================================
// Key Identification
// ============================================================================

bool kernel_verify_get_key_id(uint8_t key_hash[8]) {
    if (!keys_present) {
        return false;
    }

    // Hash the public key to get a short identifier
    uint8_t full_hash[32];
    shake256(full_hash, 32,
             pqcrypto_embedded_keys.dilithium_pk,
             DILITHIUM_PUBLICKEYBYTES);

    memcpy(key_hash, full_hash, 8);
    return true;
}

void kernel_verify_print_status(void) {
    if (!keys_present) {
        print("pqcrypto: [ ] No verification keys\n");
        return;
    }

    uint8_t key_id[8];
    kernel_verify_get_key_id(key_id);

    print("pqcrypto: [+] Key ID: ");
    for (int i = 0; i < 8; i++) {
        print("%x", key_id[i]);
    }
    print("\n");
    print("pqcrypto: [+] Algorithm: Dilithium-3 (ML-DSA)\n");
}

const char *kernel_verify_error(void) {
    return last_error;
}

// ============================================================================
// Verification
// ============================================================================

bool kernel_verify_and_decrypt(uint8_t **kernel, size_t *size, char *config) {
    last_error = NULL;

    if (!verify_initialized) {
        kernel_verify_init();
    }

    // Check if verification is disabled in config
    char *verify_opt = config_get_value(config, 0, "KERNEL_VERIFY");
    if (verify_opt != NULL && strcmp(verify_opt, "no") == 0) {
        if (keys_present) {
            print("pqcrypto: WARNING - Signature verification disabled by config!\n");
        }
        return true;
    }

    // If no keys, skip verification
    if (!keys_present) {
        return true;
    }

    uint8_t *kdata = *kernel;
    size_t ksize = *size;

    // Check if kernel is encrypted
    char *encrypt_opt = config_get_value(config, 0, "KERNEL_ENCRYPTED");
    bool encrypted = (encrypt_opt != NULL && strcmp(encrypt_opt, "yes") == 0);

    if (encrypted || pqcrypto_is_encrypted(kdata, ksize)) {
        print("pqcrypto: Decrypting kernel...\n");

        // Allocate buffer for decryption
        // Decrypted size is slightly smaller than encrypted
        size_t decrypted_size = 0;
        int result = pqcrypto_decrypt_kernel(kdata, ksize, kdata, &decrypted_size);

        if (result != PQCRYPTO_OK) {
            last_error = "Kernel decryption failed";
            print("pqcrypto: ERROR - %s\n", last_error);
            return false;
        }

        ksize = decrypted_size;
        print("pqcrypto: Decryption successful\n");
    }

    // Verify signature
    print("pqcrypto: Verifying kernel signature...\n");

    if (ksize < PQCRYPTO_SIG_SIZE) {
        last_error = "Kernel too small to contain signature";
        print("pqcrypto: ERROR - %s\n", last_error);
        return false;
    }

    size_t kernel_size = 0;
    int result = pqcrypto_verify_kernel_appended(kdata, ksize, &kernel_size);

    if (result != PQCRYPTO_OK) {
        last_error = "Invalid kernel signature";
        print("pqcrypto: ERROR - %s\n", last_error);
        print("pqcrypto: Boot halted for security\n");
        return false;
    }

    // Update size to exclude signature
    *size = kernel_size;

    print("pqcrypto: Signature verified successfully\n");
    return true;
}
