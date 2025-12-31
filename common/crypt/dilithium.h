// Dilithium-3 wrapper header for bootloader
// Uses pq-crystals reference implementation

#ifndef CRYPT__DILITHIUM_H__
#define CRYPT__DILITHIUM_H__

#include <stdint.h>
#include <stddef.h>

// Dilithium-3 constants (hardcoded to avoid header conflicts)
#define DILITHIUM_PUBLICKEYBYTES 1952
#define DILITHIUM_SECRETKEYBYTES 4032
#define DILITHIUM_SIGNATUREBYTES 3309

// Verification function prototype (implemented in dilithium/sign.c)
int pqcrystals_dilithium3_ref_verify(const uint8_t *sig, size_t siglen,
                                     const uint8_t *m, size_t mlen,
                                     const uint8_t *ctx, size_t ctxlen,
                                     const uint8_t *pk);

// Wrapper function
static inline int dilithium_verify(const uint8_t *sig, size_t siglen,
                                   const uint8_t *m, size_t mlen,
                                   const uint8_t *pk) {
    // pq-crystals uses context string parameter - pass NULL, 0 for no context
    return pqcrystals_dilithium3_ref_verify(sig, siglen, m, mlen, NULL, 0, pk);
}

#endif // CRYPT__DILITHIUM_H__
