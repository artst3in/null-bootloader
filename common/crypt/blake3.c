// ============================================================================
// BLAKE3 - Modern Cryptographic Hash Function
// ============================================================================
// Minimal portable C implementation for bootloader use.
// Based on the official BLAKE3 reference implementation.
// https://github.com/BLAKE3-team/BLAKE3
//
// Copyright 2025 The LunaOS Contributors (this adaptation)
// Original BLAKE3: CC0 1.0 / Apache 2.0 dual-licensed
// ============================================================================

#include <stdint.h>
#include <stddef.h>
#include <crypt/blake3.h>
#include <lib/libc.h>

// BLAKE3 IV (same as BLAKE2s, first 32 bits of fractional parts of sqrt of primes)
static const uint32_t BLAKE3_IV[8] = {
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
};

// Message schedule permutation
static const uint8_t MSG_SCHEDULE[7][16] = {
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8},
    {3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1},
    {10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6},
    {12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4},
    {9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7},
    {11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13},
};

// Flags
#define CHUNK_START         (1 << 0)
#define CHUNK_END           (1 << 1)
#define PARENT              (1 << 2)
#define ROOT                (1 << 3)

static inline uint32_t rotr32(uint32_t x, int n) {
    return (x >> n) | (x << (32 - n));
}

static inline uint32_t load32_le(const uint8_t *p) {
    return ((uint32_t)p[0]) | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static inline void store32_le(uint8_t *p, uint32_t x) {
    p[0] = (uint8_t)(x);
    p[1] = (uint8_t)(x >> 8);
    p[2] = (uint8_t)(x >> 16);
    p[3] = (uint8_t)(x >> 24);
}

// Quarter round
static inline void g(uint32_t *state, size_t a, size_t b, size_t c, size_t d,
                     uint32_t mx, uint32_t my) {
    state[a] = state[a] + state[b] + mx;
    state[d] = rotr32(state[d] ^ state[a], 16);
    state[c] = state[c] + state[d];
    state[b] = rotr32(state[b] ^ state[c], 12);
    state[a] = state[a] + state[b] + my;
    state[d] = rotr32(state[d] ^ state[a], 8);
    state[c] = state[c] + state[d];
    state[b] = rotr32(state[b] ^ state[c], 7);
}

static void round_fn(uint32_t *state, const uint32_t *msg, size_t round) {
    const uint8_t *schedule = MSG_SCHEDULE[round];

    // Column rounds
    g(state, 0, 4, 8,  12, msg[schedule[0]],  msg[schedule[1]]);
    g(state, 1, 5, 9,  13, msg[schedule[2]],  msg[schedule[3]]);
    g(state, 2, 6, 10, 14, msg[schedule[4]],  msg[schedule[5]]);
    g(state, 3, 7, 11, 15, msg[schedule[6]],  msg[schedule[7]]);

    // Diagonal rounds
    g(state, 0, 5, 10, 15, msg[schedule[8]],  msg[schedule[9]]);
    g(state, 1, 6, 11, 12, msg[schedule[10]], msg[schedule[11]]);
    g(state, 2, 7, 8,  13, msg[schedule[12]], msg[schedule[13]]);
    g(state, 3, 4, 9,  14, msg[schedule[14]], msg[schedule[15]]);
}

static void compress(const uint32_t cv[8], const uint8_t block[BLAKE3_BLOCK_LEN],
                     uint8_t block_len, uint64_t counter, uint8_t flags,
                     uint32_t out[16]) {
    uint32_t state[16] = {
        cv[0], cv[1], cv[2], cv[3],
        cv[4], cv[5], cv[6], cv[7],
        BLAKE3_IV[0], BLAKE3_IV[1], BLAKE3_IV[2], BLAKE3_IV[3],
        (uint32_t)counter, (uint32_t)(counter >> 32), (uint32_t)block_len, (uint32_t)flags
    };

    uint32_t msg[16];
    for (int i = 0; i < 16; i++) {
        msg[i] = load32_le(block + 4 * i);
    }

    // 7 rounds
    for (size_t i = 0; i < 7; i++) {
        round_fn(state, msg, i);
    }

    // XOR with CV
    for (int i = 0; i < 8; i++) {
        state[i] ^= state[i + 8];
        state[i + 8] ^= cv[i];
    }

    for (int i = 0; i < 16; i++) {
        out[i] = state[i];
    }
}

static void chunk_state_init(blake3_hasher *self, const uint32_t key[8], uint64_t chunk_counter) {
    memcpy(self->cv, key, sizeof(self->cv));
    self->chunk_counter = chunk_counter;
    memset(self->buf, 0, sizeof(self->buf));
    self->buf_len = 0;
    self->blocks_compressed = 0;
    self->flags = 0;
}

void blake3_hasher_init(blake3_hasher *self) {
    chunk_state_init(self, BLAKE3_IV, 0);
}

static uint8_t chunk_state_start_flag(const blake3_hasher *self) {
    if (self->blocks_compressed == 0) {
        return CHUNK_START;
    }
    return 0;
}

static void chunk_state_update(blake3_hasher *self, const uint8_t *input, size_t input_len) {
    while (input_len > 0) {
        // If buffer is full, compress it
        if (self->buf_len == BLAKE3_BLOCK_LEN) {
            uint32_t out[16];
            uint8_t flags = self->flags | chunk_state_start_flag(self);
            compress(self->cv, self->buf, BLAKE3_BLOCK_LEN, self->chunk_counter, flags, out);
            memcpy(self->cv, out, sizeof(self->cv));
            self->blocks_compressed++;
            self->buf_len = 0;
            memset(self->buf, 0, sizeof(self->buf));
        }

        // Fill buffer
        size_t take = BLAKE3_BLOCK_LEN - self->buf_len;
        if (take > input_len) {
            take = input_len;
        }
        memcpy(self->buf + self->buf_len, input, take);
        self->buf_len += take;
        input += take;
        input_len -= take;
    }
}

void blake3_hasher_update(blake3_hasher *self, const void *input, size_t input_len) {
    chunk_state_update(self, (const uint8_t *)input, input_len);
}

static void output_root_bytes(const blake3_hasher *self, uint8_t *out, size_t out_len) {
    uint8_t flags = self->flags | chunk_state_start_flag(self) | CHUNK_END | ROOT;

    uint64_t output_block_counter = 0;
    size_t offset_within_block = 0;

    while (out_len > 0) {
        uint32_t words[16];
        compress(self->cv, self->buf, self->buf_len, output_block_counter, flags, words);

        size_t take = 64 - offset_within_block;
        if (take > out_len) {
            take = out_len;
        }

        // Copy output bytes
        for (size_t i = 0; i < take; i++) {
            size_t word_idx = (offset_within_block + i) / 4;
            size_t byte_idx = (offset_within_block + i) % 4;
            out[i] = (uint8_t)(words[word_idx] >> (8 * byte_idx));
        }

        out += take;
        out_len -= take;
        output_block_counter++;
        offset_within_block = 0;
    }
}

void blake3_hasher_finalize(const blake3_hasher *self, uint8_t *out, size_t out_len) {
    output_root_bytes(self, out, out_len);
}

void blake3(void *out, const void *in, size_t in_len) {
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, in, in_len);
    blake3_hasher_finalize(&hasher, out, BLAKE3_OUT_LEN);
}

void blake3_extended(void *out, const void *in, size_t in_len) {
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, in, in_len);
    blake3_hasher_finalize(&hasher, out, BLAKE3_OUT_BYTES);
}
