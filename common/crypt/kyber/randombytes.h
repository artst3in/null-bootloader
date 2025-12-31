// randombytes.h - Stub for bootloader (verification only, no signing)
// Bootloader doesn't need random bytes since it only verifies, not signs

#ifndef RANDOMBYTES_H
#define RANDOMBYTES_H

#include <stdint.h>
#include <stddef.h>

// Stub function - not used in verification-only mode
static inline void randombytes(uint8_t *out __attribute__((unused)),
                               size_t outlen __attribute__((unused))) {
    // Not implemented - bootloader only verifies, doesn't sign
}

#endif
