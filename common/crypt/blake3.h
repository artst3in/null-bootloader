// ============================================================================
// BLAKE3 - Modern Cryptographic Hash Function
// ============================================================================
// BLAKE3 is a cryptographic hash function that is:
// - Much faster than BLAKE2, SHA-256, SHA-3, etc. (especially with SIMD)
// - Secure: 256-bit security level
// - Highly parallelizable
// - Designed in 2020 by the BLAKE2 team
//
// This is a minimal, portable C implementation for bootloader use.
// Reference: https://github.com/BLAKE3-team/BLAKE3
// ============================================================================

#ifndef CRYPT__BLAKE3_H__
#define CRYPT__BLAKE3_H__

#include <stddef.h>
#include <stdint.h>

// BLAKE3 constants
#define BLAKE3_OUT_LEN 32       // Default output length (256 bits)
#define BLAKE3_BLOCK_LEN 64     // Block size in bytes
#define BLAKE3_CHUNK_LEN 1024   // Chunk size for tree hashing
#define BLAKE3_KEY_LEN 32       // Key length for keyed hashing

// For backwards compatibility with code expecting 64-byte hashes,
// we provide an extended output option
#define BLAKE3_OUT_BYTES 64     // Extended output for compatibility

// BLAKE3 context for incremental hashing
typedef struct {
    uint32_t cv[8];             // Chaining value
    uint64_t chunk_counter;     // Chunk counter
    uint8_t buf[BLAKE3_BLOCK_LEN]; // Block buffer
    uint8_t buf_len;            // Bytes in buffer
    uint8_t blocks_compressed;  // Blocks compressed in current chunk
    uint8_t flags;              // Domain separation flags
} blake3_hasher;

// Initialize a BLAKE3 hasher
void blake3_hasher_init(blake3_hasher *self);

// Add input data to the hasher
void blake3_hasher_update(blake3_hasher *self, const void *input, size_t input_len);

// Finalize and output the hash (can output any length via XOF)
void blake3_hasher_finalize(const blake3_hasher *self, uint8_t *out, size_t out_len);

// Simple one-shot hashing function (32-byte output)
void blake3(void *out, const void *in, size_t in_len);

// Extended output version for compatibility (64-byte output like BLAKE2B)
void blake3_extended(void *out, const void *in, size_t in_len);

#endif // CRYPT__BLAKE3_H__
