// Kyber-1024 wrapper header for bootloader
// Uses pq-crystals reference implementation (NIST Level 5, 256-bit security)

#ifndef CRYPT__KYBER_H__
#define CRYPT__KYBER_H__

#include <stdint.h>
#include <stddef.h>

// Kyber-1024 constants (K=4, NIST Level 5)
// Calculated from params.h formulas:
//   POLYVECBYTES = K * 384 = 1536
//   PUBLICKEYBYTES = POLYVECBYTES + 32 = 1568
//   SECRETKEYBYTES = POLYVECBYTES + PUBLICKEYBYTES + 64 = 3168
//   POLYVECCOMPRESSEDBYTES = K * 352 = 1408
//   POLYCOMPRESSEDBYTES = 160
//   CIPHERTEXTBYTES = 1408 + 160 = 1568
#define KYBER_PUBLICKEYBYTES  1568
#define KYBER_SECRETKEYBYTES  3168
#define KYBER_CIPHERTEXTBYTES 1568
#define KYBER_SSBYTES         32    // Shared secret size

// Decapsulation function prototype (implemented in kyber/kem.c)
int pqcrystals_kyber1024_ref_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

// Wrapper function
static inline int kyber_decapsulate(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
    return pqcrystals_kyber1024_ref_dec(ss, ct, sk);
}

#endif // CRYPT__KYBER_H__
