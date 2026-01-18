// ============================================================================
// Kernel Verification - Ed25519 Signature Checking
// ============================================================================
// Module for verifying kernel signatures before execution.
// Integrates with the Limine protocol loader.
//
// Note: Post-quantum cryptography has been removed per MLE analysis.
//
// Copyright 2026 The LunaOS Contributors
// SPDX-License-Identifier: BSD-2-Clause
// ============================================================================

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <crypt/kernel_verify.h>
#include <crypt/crypto.h>
#include <crypt/sha512.h>
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

    print("\n");
    print("+-- Classical Cryptography --------------------------------------------\n");

    int result = crypto_init();
    keys_present = (result == CRYPTO_OK);
    verify_initialized = true;

    if (keys_present) {
        uint8_t key_id[8];
        uint8_t full_hash[64];
        sha512(full_hash, crypto_embedded_keys.ed25519_pk, ED25519_PUBLICKEYBYTES);
        memcpy(key_id, full_hash, 8);

        print("[  OK  ] Ed25519 verification key loaded\n");
        print("         Key ID: ");
        for (int i = 0; i < 8; i++) {
            print("%02x", key_id[i]);
        }
        print("\n");
    } else {
        print("[ WARN ] No signing keys embedded (verification disabled)\n");
    }

    // Check for X25519 decryption key
    if (crypto_embedded_keys.has_encryption) {
        print("[  OK  ] X25519 decryption key loaded\n");
    }

    return keys_present;
}

bool kernel_verify_enabled(void) {
    return keys_present;
}

bool kernel_decrypt_enabled(void) {
    return crypto_embedded_keys.has_encryption != 0;
}

// ============================================================================
// Key Identification
// ============================================================================

bool kernel_verify_get_key_id(uint8_t key_hash[8]) {
    if (!keys_present) {
        return false;
    }

    // Hash the public key to get a short identifier
    uint8_t full_hash[64];
    sha512(full_hash, crypto_embedded_keys.ed25519_pk, ED25519_PUBLICKEYBYTES);

    memcpy(key_hash, full_hash, 8);
    return true;
}

void kernel_verify_print_status(void) {
    if (!keys_present) {
        print("crypto: [ ] No verification keys\n");
        return;
    }

    uint8_t key_id[8];
    kernel_verify_get_key_id(key_id);

    print("crypto: [+] Key ID: ");
    for (int i = 0; i < 8; i++) {
        print("%x", key_id[i]);
    }
    print("\n");
    print("crypto: [+] Algorithm: Ed25519 (128-bit security)\n");
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
            print("crypto: WARNING - Signature verification disabled by config!\n");
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

    if (encrypted || crypto_is_encrypted(kdata, ksize)) {
        print("crypto: Decrypting kernel...\n");

        // Allocate buffer for decryption
        // Decrypted size is slightly smaller than encrypted
        size_t decrypted_size = 0;
        int result = crypto_decrypt_kernel(kdata, ksize, kdata, &decrypted_size);

        if (result != CRYPTO_OK) {
            last_error = "Kernel decryption failed";
            print("crypto: ERROR - %s\n", last_error);
            return false;
        }

        ksize = decrypted_size;
        print("crypto: Decryption successful\n");
    }

    // Verify signature
    print("[  ..  ] Verifying kernel signature (%u bytes)...\n", (unsigned int)ksize);

    if (ksize < CRYPTO_SIG_SIZE) {
        last_error = "Kernel too small to contain signature";
        print("[ FAIL ] %s\n", last_error);
        return false;
    }

    size_t kernel_size = 0;
    int result = crypto_verify_kernel_appended(kdata, ksize, &kernel_size);

    if (result != CRYPTO_OK) {
        last_error = "Invalid kernel signature";
        print("[ FAIL ] %s\n", last_error);
        print("[ HALT ] Boot halted - kernel may be compromised!\n");
        return false;
    }

    // Update size to exclude signature
    *size = kernel_size;

    print("[  OK  ] Signature VALID (Ed25519, 128-bit security)\n");
    print("         Kernel: %u bytes, Signature: %u bytes\n",
          (unsigned int)kernel_size, (unsigned int)CRYPTO_SIG_SIZE);
    return true;
}
