#!/usr/bin/env bash
# ============================================================================
# Null Bootloader PQCrypto Setup
# ============================================================================
# This script sets up post-quantum cryptography tools and generates keys
# for signing and encrypting kernels.
#
# Usage:
#   ./setup.sh              # Full setup (tools + keys)
#   ./setup.sh tools        # Build tools only
#   ./setup.sh keys         # Generate keys only
#   ./setup.sh embed        # Generate embedded_keys.h only
#
# Copyright 2025 The LunaOS Contributors
# SPDX-License-Identifier: Apache-2.0
# ============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOLS_DIR="$SCRIPT_DIR"
NULL_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
KEYS_DIR="$TOOLS_DIR/keys"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color

echo -e "${CYAN}=== Null Bootloader PQCrypto Setup ===${NC}"

# ============================================================================
# Check Dependencies
# ============================================================================

check_deps() {
    local missing=()

    command -v gcc >/dev/null 2>&1 || missing+=("gcc")
    command -v make >/dev/null 2>&1 || missing+=("make")

    if [ ${#missing[@]} -gt 0 ]; then
        echo -e "${RED}[ERROR] Missing dependencies: ${missing[*]}${NC}"
        echo "Please install a C compiler (gcc/clang) and make."
        exit 1
    fi
}

# ============================================================================
# Download pq-crystals reference implementations
# ============================================================================

download_pqcrystals() {
    echo -e "${CYAN}[SETUP] Checking pq-crystals reference implementations...${NC}"

    DILITHIUM_DIR="$TOOLS_DIR/dilithium-ref"
    KYBER_DIR="$TOOLS_DIR/kyber-ref"

    if [ ! -d "$DILITHIUM_DIR/ref" ]; then
        echo -e "${YELLOW}[DOWNLOAD] Dilithium reference implementation...${NC}"
        git clone --depth 1 https://github.com/pq-crystals/dilithium.git "$DILITHIUM_DIR"
    else
        echo -e "${GREEN}[OK] Dilithium already present${NC}"
    fi

    if [ ! -d "$KYBER_DIR/ref" ]; then
        echo -e "${YELLOW}[DOWNLOAD] Kyber reference implementation...${NC}"
        git clone --depth 1 https://github.com/pq-crystals/kyber.git "$KYBER_DIR"
    else
        echo -e "${GREEN}[OK] Kyber already present${NC}"
    fi
}

# ============================================================================
# Build Tools
# ============================================================================

build_tools() {
    echo -e "${CYAN}[BUILD] Building PQCrypto tools...${NC}"

    DILITHIUM_REF="$TOOLS_DIR/dilithium-ref/ref"
    KYBER_REF="$TOOLS_DIR/kyber-ref/ref"

    # Build luna_sign (Dilithium-3)
    echo -e "${YELLOW}[BUILD] luna_sign (Dilithium-3 signing tool)...${NC}"

    # Create luna_sign.c if it doesn't exist
    if [ ! -f "$DILITHIUM_REF/luna_sign.c" ]; then
        create_luna_sign
    fi

    (cd "$DILITHIUM_REF" && \
        gcc -O3 -Wall -DDILITHIUM_MODE=3 \
            -o luna_sign \
            luna_sign.c sign.c packing.c polyvec.c poly.c ntt.c reduce.c rounding.c \
            fips202.c symmetric-shake.c randombytes.c \
            -I. 2>/dev/null || \
        gcc -O3 -Wall -DDILITHIUM_MODE=3 \
            -o luna_sign.exe \
            luna_sign.c sign.c packing.c polyvec.c poly.c ntt.c reduce.c rounding.c \
            fips202.c symmetric-shake.c randombytes.c \
            -I.)

    # Build luna_crypt (Kyber-1024)
    echo -e "${YELLOW}[BUILD] luna_crypt (Kyber-1024 encryption tool)...${NC}"

    # Create luna_crypt.c if it doesn't exist
    if [ ! -f "$KYBER_REF/luna_crypt.c" ]; then
        create_luna_crypt
    fi

    (cd "$KYBER_REF" && \
        gcc -O3 -Wall -DKYBER_K=4 \
            -o luna_crypt \
            luna_crypt.c kem.c indcpa.c polyvec.c poly.c ntt.c cbd.c reduce.c verify.c \
            fips202.c symmetric-shake.c randombytes.c \
            -I. 2>/dev/null || \
        gcc -O3 -Wall -DKYBER_K=4 \
            -o luna_crypt.exe \
            luna_crypt.c kem.c indcpa.c polyvec.c poly.c ntt.c cbd.c reduce.c verify.c \
            fips202.c symmetric-shake.c randombytes.c \
            -I.)

    echo -e "${GREEN}[OK] Tools built successfully${NC}"
}

# ============================================================================
# Generate Keys
# ============================================================================

generate_keys() {
    echo -e "${CYAN}[KEYGEN] Generating cryptographic keys...${NC}"

    mkdir -p "$KEYS_DIR"

    LUNA_SIGN="$TOOLS_DIR/dilithium-ref/ref/luna_sign"
    LUNA_CRYPT="$TOOLS_DIR/kyber-ref/ref/luna_crypt"

    # Use .exe on Windows
    [ -f "${LUNA_SIGN}.exe" ] && LUNA_SIGN="${LUNA_SIGN}.exe"
    [ -f "${LUNA_CRYPT}.exe" ] && LUNA_CRYPT="${LUNA_CRYPT}.exe"

    # Generate Dilithium-3 signing keys
    if [ ! -f "$KEYS_DIR/signing.sec" ]; then
        echo -e "${MAGENTA}[KEYGEN] Generating Dilithium-3 signing keypair...${NC}"
        "$LUNA_SIGN" keygen "$KEYS_DIR" signing
    else
        echo -e "${GREEN}[OK] Signing keys already exist${NC}"
    fi

    # Generate Kyber-1024 encryption keys
    if [ ! -f "$KEYS_DIR/encryption.sec" ]; then
        echo -e "${MAGENTA}[KEYGEN] Generating Kyber-1024 encryption keypair...${NC}"
        "$LUNA_CRYPT" keygen "$KEYS_DIR" encryption
    else
        echo -e "${GREEN}[OK] Encryption keys already exist${NC}"
    fi

    echo ""
    echo -e "${YELLOW}=== KEY SECURITY WARNING ===${NC}"
    echo -e "Secret keys are stored in: ${CYAN}$KEYS_DIR${NC}"
    echo -e "${RED}NEVER commit .sec files to version control!${NC}"
    echo -e "${RED}BACK UP your secret keys securely!${NC}"
    echo ""
}

# ============================================================================
# Generate embedded_keys.h
# ============================================================================

generate_embedded_keys() {
    echo -e "${CYAN}[EMBED] Generating embedded_keys.h...${NC}"

    DILITHIUM_PK="$KEYS_DIR/signing.pub"
    KYBER_SK="$KEYS_DIR/encryption.sec"
    OUTPUT="$NULL_ROOT/common/crypt/embedded_keys.h"

    if [ ! -f "$DILITHIUM_PK" ]; then
        echo -e "${RED}[ERROR] Signing public key not found: $DILITHIUM_PK${NC}"
        echo "Run '$0 keys' first to generate keys."
        exit 1
    fi

    # Generate C header
    echo "// Auto-generated by setup.sh - DO NOT EDIT" > "$OUTPUT"
    echo "// Generated: $(date -u +"%Y-%m-%d %H:%M:%S UTC")" >> "$OUTPUT"
    echo "" >> "$OUTPUT"
    echo "#ifndef EMBEDDED_KEYS_H" >> "$OUTPUT"
    echo "#define EMBEDDED_KEYS_H" >> "$OUTPUT"
    echo "" >> "$OUTPUT"
    echo "#include <stdint.h>" >> "$OUTPUT"
    echo "" >> "$OUTPUT"

    # Dilithium public key (for signature verification)
    echo "// Dilithium-3 public key (1952 bytes)" >> "$OUTPUT"
    echo "#define DILITHIUM_PUBLICKEYBYTES 1952" >> "$OUTPUT"
    echo "static const uint8_t DILITHIUM_PUBLIC_KEY[DILITHIUM_PUBLICKEYBYTES] = {" >> "$OUTPUT"
    xxd -i < "$DILITHIUM_PK" | grep -v "unsigned" | sed 's/^/    /' >> "$OUTPUT"
    echo "};" >> "$OUTPUT"
    echo "" >> "$OUTPUT"

    # Kyber secret key (for decryption) - optional
    if [ -f "$KYBER_SK" ]; then
        echo "// Kyber-1024 secret key for decryption (3168 bytes)" >> "$OUTPUT"
        echo "#define KYBER_SECRETKEYBYTES 3168" >> "$OUTPUT"
        echo "#define HAVE_KYBER_KEY 1" >> "$OUTPUT"
        echo "static const uint8_t KYBER_SECRET_KEY[KYBER_SECRETKEYBYTES] = {" >> "$OUTPUT"
        xxd -i < "$KYBER_SK" | grep -v "unsigned" | sed 's/^/    /' >> "$OUTPUT"
        echo "};" >> "$OUTPUT"
    else
        echo "#define HAVE_KYBER_KEY 0" >> "$OUTPUT"
    fi

    echo "" >> "$OUTPUT"
    echo "#endif // EMBEDDED_KEYS_H" >> "$OUTPUT"

    echo -e "${GREEN}[OK] Generated: $OUTPUT${NC}"

    # Print key IDs
    echo ""
    echo -e "${CYAN}Embedded keys:${NC}"
    echo -e "  Signing public key:    $DILITHIUM_PK"
    if [ -f "$KYBER_SK" ]; then
        echo -e "  Encryption secret key: $KYBER_SK"
    fi
}

# ============================================================================
# Create luna_sign.c
# ============================================================================

create_luna_sign() {
    cat > "$TOOLS_DIR/dilithium-ref/ref/luna_sign.c" << 'LUNA_SIGN_EOF'
// luna_sign - Kernel Signing Tool
// Uses pq-crystals reference Dilithium-3 implementation

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "api.h"
#include "randombytes.h"
#include "fips202.h"

#define SIGNATURE_SIZE pqcrystals_dilithium3_BYTES
#define PUBLICKEY_SIZE pqcrystals_dilithium3_PUBLICKEYBYTES
#define SECRETKEY_SIZE pqcrystals_dilithium3_SECRETKEYBYTES

static uint8_t* read_file(const char* path, size_t* size) {
    FILE* f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    *size = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t* data = malloc(*size);
    if (!data) { fclose(f); return NULL; }
    if (fread(data, 1, *size, f) != *size) { free(data); fclose(f); return NULL; }
    fclose(f);
    return data;
}

static int write_file(const char* path, const uint8_t* data, size_t size) {
    FILE* f = fopen(path, "wb");
    if (!f) return -1;
    if (fwrite(data, 1, size, f) != size) { fclose(f); return -1; }
    fclose(f);
    return 0;
}

static void print_key_id(const uint8_t* pk) {
    uint8_t hash[32];
    shake256(hash, 32, pk, PUBLICKEY_SIZE);
    for (int i = 0; i < 8; i++) printf("%02x", hash[i]);
}

static void print_usage(const char* prog) {
    printf("luna_sign - Kernel Signing Tool (Dilithium-3)\n\n");
    printf("Usage:\n");
    printf("  %s keygen <output_dir> [name]     Generate keypair\n", prog);
    printf("  %s sign <file> <key.sec> [out]    Sign file\n", prog);
    printf("  %s verify <file> <key.pub>        Verify signature\n", prog);
    printf("  %s keyid <key.pub>                Print key ID\n", prog);
}

static int cmd_keygen(int argc, char** argv) {
    const char* output_dir = argc > 2 ? argv[2] : ".";
    const char* name = argc > 3 ? argv[3] : "signing";

    char pub_path[512], sec_path[512];
    snprintf(pub_path, sizeof(pub_path), "%s/%s.pub", output_dir, name);
    snprintf(sec_path, sizeof(sec_path), "%s/%s.sec", output_dir, name);

    printf("Generating Dilithium-3 keypair...\n");

    uint8_t pk[PUBLICKEY_SIZE], sk[SECRETKEY_SIZE];
    if (pqcrystals_dilithium3_ref_keypair(pk, sk) != 0) {
        fprintf(stderr, "Error: Keypair generation failed\n");
        return 1;
    }

    if (write_file(pub_path, pk, PUBLICKEY_SIZE) != 0 ||
        write_file(sec_path, sk, SECRETKEY_SIZE) != 0) {
        fprintf(stderr, "Error: Failed to write keys\n");
        return 1;
    }

    printf("Keypair generated:\n");
    printf("  Public key:  %s (%d bytes)\n", pub_path, PUBLICKEY_SIZE);
    printf("  Secret key:  %s (%d bytes)\n", sec_path, SECRETKEY_SIZE);
    printf("  Key ID:      "); print_key_id(pk); printf("\n");
    return 0;
}

static int cmd_sign(int argc, char** argv) {
    if (argc < 4) {
        fprintf(stderr, "Usage: luna_sign sign <file> <secret_key> [output]\n");
        return 1;
    }

    const char* input_path = argv[2];
    const char* sk_path = argv[3];
    char output_path[512];
    if (argc > 4) strncpy(output_path, argv[4], sizeof(output_path) - 1);
    else snprintf(output_path, sizeof(output_path), "%s.signed", input_path);

    size_t input_size, sk_size;
    uint8_t* input = read_file(input_path, &input_size);
    uint8_t* sk = read_file(sk_path, &sk_size);

    if (!input || !sk || sk_size != SECRETKEY_SIZE) {
        fprintf(stderr, "Error: Cannot read input files\n");
        free(input); free(sk);
        return 1;
    }

    uint8_t sig[SIGNATURE_SIZE];
    size_t siglen;
    if (pqcrystals_dilithium3_ref_signature(sig, &siglen, input, input_size, NULL, 0, sk) != 0) {
        fprintf(stderr, "Error: Signing failed\n");
        free(input); free(sk);
        return 1;
    }

    // Output: data + signature
    size_t output_size = input_size + SIGNATURE_SIZE;
    uint8_t* output = malloc(output_size);
    memcpy(output, input, input_size);
    memcpy(output + input_size, sig, SIGNATURE_SIZE);

    if (write_file(output_path, output, output_size) != 0) {
        fprintf(stderr, "Error: Cannot write output\n");
        free(output); free(input); free(sk);
        return 1;
    }

    printf("Signed: %s -> %s (%zu + %d bytes)\n", input_path, output_path, input_size, SIGNATURE_SIZE);
    free(output); free(input); free(sk);
    return 0;
}

static int cmd_verify(int argc, char** argv) {
    if (argc < 4) {
        fprintf(stderr, "Usage: luna_sign verify <signed_file> <public_key>\n");
        return 1;
    }

    size_t data_size, pk_size;
    uint8_t* data = read_file(argv[2], &data_size);
    uint8_t* pk = read_file(argv[3], &pk_size);

    if (!data || !pk || pk_size != PUBLICKEY_SIZE || data_size < SIGNATURE_SIZE) {
        fprintf(stderr, "Error: Invalid input\n");
        free(data); free(pk);
        return 1;
    }

    size_t msg_size = data_size - SIGNATURE_SIZE;
    uint8_t* sig = data + msg_size;

    int result = pqcrystals_dilithium3_ref_verify(sig, SIGNATURE_SIZE, data, msg_size, NULL, 0, pk);

    if (result == 0) {
        printf("Signature VALID (key: "); print_key_id(pk); printf(")\n");
    } else {
        fprintf(stderr, "Signature INVALID!\n");
    }

    free(data); free(pk);
    return result == 0 ? 0 : 1;
}

static int cmd_keyid(int argc, char** argv) {
    if (argc < 3) {
        fprintf(stderr, "Usage: luna_sign keyid <public_key>\n");
        return 1;
    }
    size_t pk_size;
    uint8_t* pk = read_file(argv[2], &pk_size);
    if (!pk || pk_size != PUBLICKEY_SIZE) {
        fprintf(stderr, "Error: Invalid public key\n");
        free(pk);
        return 1;
    }
    print_key_id(pk);
    printf("\n");
    free(pk);
    return 0;
}

int main(int argc, char** argv) {
    if (argc < 2) { print_usage(argv[0]); return 1; }

    if (strcmp(argv[1], "keygen") == 0) return cmd_keygen(argc, argv);
    if (strcmp(argv[1], "sign") == 0) return cmd_sign(argc, argv);
    if (strcmp(argv[1], "verify") == 0) return cmd_verify(argc, argv);
    if (strcmp(argv[1], "keyid") == 0) return cmd_keyid(argc, argv);
    if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) { print_usage(argv[0]); return 0; }

    fprintf(stderr, "Unknown command: %s\n", argv[1]);
    return 1;
}
LUNA_SIGN_EOF
}

# ============================================================================
# Create luna_crypt.c
# ============================================================================

create_luna_crypt() {
    cat > "$TOOLS_DIR/kyber-ref/ref/luna_crypt.c" << 'LUNA_CRYPT_EOF'
// luna_crypt - Kernel Encryption Tool
// Uses pq-crystals reference Kyber-1024 + ChaCha20-Poly1305

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "api.h"
#include "randombytes.h"
#include "fips202.h"

#define KYBER_SECRETKEYBYTES  pqcrystals_kyber1024_SECRETKEYBYTES
#define KYBER_PUBLICKEYBYTES  pqcrystals_kyber1024_PUBLICKEYBYTES
#define KYBER_CIPHERTEXTBYTES pqcrystals_kyber1024_CIPHERTEXTBYTES
#define KYBER_SSBYTES         pqcrystals_kyber1024_BYTES

static const uint8_t ENCRYPTED_MAGIC[8] = {'L', 'U', 'N', 'A', 'E', 'N', 'C', '1'};
#define CHACHA_NONCE_SIZE 12
#define POLY1305_TAG_SIZE 16
#define HEADER_SIZE (8 + KYBER_CIPHERTEXTBYTES + CHACHA_NONCE_SIZE + POLY1305_TAG_SIZE)

// ChaCha20-Poly1305 implementation (RFC 8439)
#define ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define U8TO32_LE(p) (((uint32_t)(p)[0]) | ((uint32_t)(p)[1] << 8) | ((uint32_t)(p)[2] << 16) | ((uint32_t)(p)[3] << 24))
#define U32TO8_LE(p, v) do { (p)[0] = (uint8_t)(v); (p)[1] = (uint8_t)((v) >> 8); (p)[2] = (uint8_t)((v) >> 16); (p)[3] = (uint8_t)((v) >> 24); } while (0)
#define U64TO8_LE(p, v) do { U32TO8_LE((p), (uint32_t)(v)); U32TO8_LE((p) + 4, (uint32_t)((v) >> 32)); } while (0)
#define QUARTERROUND(a, b, c, d) do { a += b; d ^= a; d = ROTL32(d, 16); c += d; b ^= c; b = ROTL32(b, 12); a += b; d ^= a; d = ROTL32(d, 8); c += d; b ^= c; b = ROTL32(b, 7); } while (0)

static const uint32_t chacha_constants[4] = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574};

typedef struct { uint32_t state[16]; } chacha20_ctx;

static void chacha20_init(chacha20_ctx *ctx, const uint8_t key[32], const uint8_t nonce[12], uint32_t counter) {
    ctx->state[0] = chacha_constants[0]; ctx->state[1] = chacha_constants[1];
    ctx->state[2] = chacha_constants[2]; ctx->state[3] = chacha_constants[3];
    for (int i = 0; i < 8; i++) ctx->state[4 + i] = U8TO32_LE(key + 4*i);
    ctx->state[12] = counter;
    ctx->state[13] = U8TO32_LE(nonce); ctx->state[14] = U8TO32_LE(nonce + 4); ctx->state[15] = U8TO32_LE(nonce + 8);
}

static void chacha20_block(chacha20_ctx *ctx, uint8_t out[64]) {
    uint32_t x[16];
    for (int i = 0; i < 16; i++) x[i] = ctx->state[i];
    for (int i = 0; i < 10; i++) {
        QUARTERROUND(x[0], x[4], x[8], x[12]); QUARTERROUND(x[1], x[5], x[9], x[13]);
        QUARTERROUND(x[2], x[6], x[10], x[14]); QUARTERROUND(x[3], x[7], x[11], x[15]);
        QUARTERROUND(x[0], x[5], x[10], x[15]); QUARTERROUND(x[1], x[6], x[11], x[12]);
        QUARTERROUND(x[2], x[7], x[8], x[13]); QUARTERROUND(x[3], x[4], x[9], x[14]);
    }
    for (int i = 0; i < 16; i++) { x[i] += ctx->state[i]; U32TO8_LE(out + 4*i, x[i]); }
    ctx->state[12]++;
}

static void chacha20_encrypt(const uint8_t key[32], const uint8_t nonce[12], uint8_t *out, const uint8_t *in, size_t len) {
    chacha20_ctx ctx;
    chacha20_init(&ctx, key, nonce, 1);
    uint8_t block[64];
    size_t i = 0;
    while (len >= 64) { chacha20_block(&ctx, block); for (int j = 0; j < 64; j++) out[i + j] = in[i + j] ^ block[j]; i += 64; len -= 64; }
    if (len > 0) { chacha20_block(&ctx, block); for (size_t j = 0; j < len; j++) out[i + j] = in[i + j] ^ block[j]; }
}

typedef struct { uint32_t r[5], h[5], pad[4]; size_t leftover; uint8_t buffer[16]; } poly1305_ctx;

static void poly1305_init(poly1305_ctx *ctx, const uint8_t key[32]) {
    ctx->r[0] = (U8TO32_LE(key)) & 0x3ffffff; ctx->r[1] = (U8TO32_LE(key + 3) >> 2) & 0x3ffff03;
    ctx->r[2] = (U8TO32_LE(key + 6) >> 4) & 0x3ffc0ff; ctx->r[3] = (U8TO32_LE(key + 9) >> 6) & 0x3f03fff;
    ctx->r[4] = (U8TO32_LE(key + 12) >> 8) & 0x00fffff;
    for (int i = 0; i < 4; i++) ctx->pad[i] = U8TO32_LE(key + 16 + 4*i);
    for (int i = 0; i < 5; i++) ctx->h[i] = 0;
    ctx->leftover = 0;
}

static void poly1305_blocks(poly1305_ctx *ctx, const uint8_t *m, size_t bytes, uint32_t hibit) {
    uint32_t r0 = ctx->r[0], r1 = ctx->r[1], r2 = ctx->r[2], r3 = ctx->r[3], r4 = ctx->r[4];
    uint32_t s1 = r1 * 5, s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5;
    uint32_t h0 = ctx->h[0], h1 = ctx->h[1], h2 = ctx->h[2], h3 = ctx->h[3], h4 = ctx->h[4];
    while (bytes >= 16) {
        h0 += (U8TO32_LE(m)) & 0x3ffffff; h1 += (U8TO32_LE(m + 3) >> 2) & 0x3ffffff;
        h2 += (U8TO32_LE(m + 6) >> 4) & 0x3ffffff; h3 += (U8TO32_LE(m + 9) >> 6) & 0x3ffffff;
        h4 += (U8TO32_LE(m + 12) >> 8) | hibit;
        uint64_t d0 = (uint64_t)h0*r0 + (uint64_t)h1*s4 + (uint64_t)h2*s3 + (uint64_t)h3*s2 + (uint64_t)h4*s1;
        uint64_t d1 = (uint64_t)h0*r1 + (uint64_t)h1*r0 + (uint64_t)h2*s4 + (uint64_t)h3*s3 + (uint64_t)h4*s2;
        uint64_t d2 = (uint64_t)h0*r2 + (uint64_t)h1*r1 + (uint64_t)h2*r0 + (uint64_t)h3*s4 + (uint64_t)h4*s3;
        uint64_t d3 = (uint64_t)h0*r3 + (uint64_t)h1*r2 + (uint64_t)h2*r1 + (uint64_t)h3*r0 + (uint64_t)h4*s4;
        uint64_t d4 = (uint64_t)h0*r4 + (uint64_t)h1*r3 + (uint64_t)h2*r2 + (uint64_t)h3*r1 + (uint64_t)h4*r0;
        uint32_t c = (uint32_t)(d0 >> 26); h0 = (uint32_t)d0 & 0x3ffffff;
        d1 += c; c = (uint32_t)(d1 >> 26); h1 = (uint32_t)d1 & 0x3ffffff;
        d2 += c; c = (uint32_t)(d2 >> 26); h2 = (uint32_t)d2 & 0x3ffffff;
        d3 += c; c = (uint32_t)(d3 >> 26); h3 = (uint32_t)d3 & 0x3ffffff;
        d4 += c; c = (uint32_t)(d4 >> 26); h4 = (uint32_t)d4 & 0x3ffffff;
        h0 += c * 5; c = h0 >> 26; h0 &= 0x3ffffff; h1 += c;
        m += 16; bytes -= 16;
    }
    ctx->h[0] = h0; ctx->h[1] = h1; ctx->h[2] = h2; ctx->h[3] = h3; ctx->h[4] = h4;
}

static void poly1305_update(poly1305_ctx *ctx, const uint8_t *m, size_t bytes) {
    if (ctx->leftover) {
        size_t want = 16 - ctx->leftover; if (want > bytes) want = bytes;
        memcpy(ctx->buffer + ctx->leftover, m, want); bytes -= want; m += want; ctx->leftover += want;
        if (ctx->leftover < 16) return;
        poly1305_blocks(ctx, ctx->buffer, 16, 1 << 24); ctx->leftover = 0;
    }
    if (bytes >= 16) { size_t want = bytes & ~15; poly1305_blocks(ctx, m, want, 1 << 24); m += want; bytes -= want; }
    if (bytes) { memcpy(ctx->buffer, m, bytes); ctx->leftover = bytes; }
}

static void poly1305_finish(poly1305_ctx *ctx, uint8_t tag[16]) {
    if (ctx->leftover) { ctx->buffer[ctx->leftover++] = 1; while (ctx->leftover < 16) ctx->buffer[ctx->leftover++] = 0; poly1305_blocks(ctx, ctx->buffer, 16, 0); }
    uint32_t h0 = ctx->h[0], h1 = ctx->h[1], h2 = ctx->h[2], h3 = ctx->h[3], h4 = ctx->h[4];
    uint32_t c = h1 >> 26; h1 &= 0x3ffffff; h2 += c; c = h2 >> 26; h2 &= 0x3ffffff;
    h3 += c; c = h3 >> 26; h3 &= 0x3ffffff; h4 += c; c = h4 >> 26; h4 &= 0x3ffffff;
    h0 += c * 5; c = h0 >> 26; h0 &= 0x3ffffff; h1 += c;
    uint32_t g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3ffffff;
    uint32_t g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffff;
    uint32_t g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffff;
    uint32_t g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffff;
    uint32_t g4 = h4 + c - (1 << 26);
    uint32_t mask = (g4 >> 31) - 1;
    g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask; mask = ~mask;
    h0 = (h0 & mask) | g0; h1 = (h1 & mask) | g1; h2 = (h2 & mask) | g2; h3 = (h3 & mask) | g3; h4 = (h4 & mask) | g4;
    h0 = h0 | (h1 << 26); h1 = (h1 >> 6) | (h2 << 20); h2 = (h2 >> 12) | (h3 << 14); h3 = (h3 >> 18) | (h4 << 8);
    uint64_t f = (uint64_t)h0 + ctx->pad[0]; h0 = (uint32_t)f;
    f = (uint64_t)h1 + ctx->pad[1] + (f >> 32); h1 = (uint32_t)f;
    f = (uint64_t)h2 + ctx->pad[2] + (f >> 32); h2 = (uint32_t)f;
    f = (uint64_t)h3 + ctx->pad[3] + (f >> 32); h3 = (uint32_t)f;
    U32TO8_LE(tag, h0); U32TO8_LE(tag + 4, h1); U32TO8_LE(tag + 8, h2); U32TO8_LE(tag + 12, h3);
}

static void chacha20poly1305_encrypt(uint8_t *ct, uint8_t tag[16], const uint8_t *pt, size_t pt_len, const uint8_t nonce[12], const uint8_t key[32]) {
    uint8_t poly_key[64]; chacha20_ctx ctx; chacha20_init(&ctx, key, nonce, 0); chacha20_block(&ctx, poly_key);
    chacha20_encrypt(key, nonce, ct, pt, pt_len);
    poly1305_ctx pctx; poly1305_init(&pctx, poly_key); poly1305_update(&pctx, ct, pt_len);
    if (pt_len % 16) { uint8_t pad[16] = {0}; poly1305_update(&pctx, pad, 16 - (pt_len % 16)); }
    uint8_t lens[16] = {0}; U64TO8_LE(lens + 8, pt_len); poly1305_update(&pctx, lens, 16);
    poly1305_finish(&pctx, tag);
}

static int chacha20poly1305_decrypt(uint8_t *pt, const uint8_t *ct, size_t ct_len, const uint8_t tag[16], const uint8_t nonce[12], const uint8_t key[32]) {
    uint8_t poly_key[64]; chacha20_ctx ctx; chacha20_init(&ctx, key, nonce, 0); chacha20_block(&ctx, poly_key);
    poly1305_ctx pctx; poly1305_init(&pctx, poly_key); poly1305_update(&pctx, ct, ct_len);
    if (ct_len % 16) { uint8_t pad[16] = {0}; poly1305_update(&pctx, pad, 16 - (ct_len % 16)); }
    uint8_t lens[16] = {0}; U64TO8_LE(lens + 8, ct_len); poly1305_update(&pctx, lens, 16);
    uint8_t computed_tag[16]; poly1305_finish(&pctx, computed_tag);
    uint8_t diff = 0; for (int i = 0; i < 16; i++) diff |= computed_tag[i] ^ tag[i];
    if (diff != 0) return -1;
    chacha20_encrypt(key, nonce, pt, ct, ct_len);
    return 0;
}

static uint8_t* read_file(const char* path, size_t* size) {
    FILE* f = fopen(path, "rb"); if (!f) return NULL;
    fseek(f, 0, SEEK_END); *size = ftell(f); fseek(f, 0, SEEK_SET);
    uint8_t* data = malloc(*size); if (!data) { fclose(f); return NULL; }
    if (fread(data, 1, *size, f) != *size) { free(data); fclose(f); return NULL; }
    fclose(f); return data;
}

static int write_file(const char* path, const uint8_t* data, size_t size) {
    FILE* f = fopen(path, "wb"); if (!f) return -1;
    if (fwrite(data, 1, size, f) != size) { fclose(f); return -1; }
    fclose(f); return 0;
}

static void print_usage(const char* prog) {
    printf("luna_crypt - Kernel Encryption Tool (Kyber-1024 + ChaCha20-Poly1305)\n\n");
    printf("Usage:\n");
    printf("  %s keygen <output_dir> [name]           Generate Kyber keypair\n", prog);
    printf("  %s encrypt <input> <public_key> [out]   Encrypt file\n", prog);
    printf("  %s decrypt <input> <secret_key> [out]   Decrypt file\n", prog);
}

static int cmd_keygen(int argc, char** argv) {
    const char* output_dir = argc > 2 ? argv[2] : ".";
    const char* name = argc > 3 ? argv[3] : "encryption";
    char pub_path[512], sec_path[512];
    snprintf(pub_path, sizeof(pub_path), "%s/%s.pub", output_dir, name);
    snprintf(sec_path, sizeof(sec_path), "%s/%s.sec", output_dir, name);
    printf("Generating Kyber-1024 keypair...\n");
    uint8_t pk[KYBER_PUBLICKEYBYTES], sk[KYBER_SECRETKEYBYTES];
    if (pqcrystals_kyber1024_ref_keypair(pk, sk) != 0) { fprintf(stderr, "Error: Keypair generation failed\n"); return 1; }
    if (write_file(pub_path, pk, KYBER_PUBLICKEYBYTES) != 0 || write_file(sec_path, sk, KYBER_SECRETKEYBYTES) != 0) {
        fprintf(stderr, "Error: Failed to write keys\n"); return 1;
    }
    printf("Keypair generated:\n  Public key:  %s (%d bytes)\n  Secret key:  %s (%d bytes)\n", pub_path, KYBER_PUBLICKEYBYTES, sec_path, KYBER_SECRETKEYBYTES);
    uint8_t hash[32]; shake256(hash, 32, pk, KYBER_PUBLICKEYBYTES);
    printf("  Key ID:      "); for (int i = 0; i < 8; i++) printf("%02x", hash[i]); printf("\n");
    return 0;
}

static int cmd_encrypt(int argc, char** argv) {
    if (argc < 4) { fprintf(stderr, "Usage: luna_crypt encrypt <input> <public_key> [output]\n"); return 1; }
    const char* input_path = argv[2]; const char* pk_path = argv[3];
    char output_path[512];
    if (argc > 4) strncpy(output_path, argv[4], sizeof(output_path) - 1);
    else snprintf(output_path, sizeof(output_path), "%s.enc", input_path);
    size_t input_size, pk_size;
    uint8_t* input = read_file(input_path, &input_size);
    uint8_t* pk = read_file(pk_path, &pk_size);
    if (!input || !pk || pk_size != KYBER_PUBLICKEYBYTES) { fprintf(stderr, "Error: Invalid input\n"); free(input); free(pk); return 1; }
    printf("Encrypting %zu bytes...\n", input_size);
    uint8_t kyber_ct[KYBER_CIPHERTEXTBYTES], shared_secret[KYBER_SSBYTES];
    if (pqcrystals_kyber1024_ref_enc(kyber_ct, shared_secret, pk) != 0) { fprintf(stderr, "Error: Kyber encapsulation failed\n"); free(input); free(pk); return 1; }
    uint8_t nonce[CHACHA_NONCE_SIZE]; randombytes(nonce, CHACHA_NONCE_SIZE);
    size_t output_size = HEADER_SIZE + input_size;
    uint8_t* output = malloc(output_size); if (!output) { free(input); free(pk); return 1; }
    uint8_t* p = output;
    memcpy(p, ENCRYPTED_MAGIC, 8); p += 8;
    memcpy(p, kyber_ct, KYBER_CIPHERTEXTBYTES); p += KYBER_CIPHERTEXTBYTES;
    memcpy(p, nonce, CHACHA_NONCE_SIZE); p += CHACHA_NONCE_SIZE;
    uint8_t* tag_ptr = p; p += POLY1305_TAG_SIZE;
    uint8_t tag[POLY1305_TAG_SIZE];
    chacha20poly1305_encrypt(p, tag, input, input_size, nonce, shared_secret);
    memcpy(tag_ptr, tag, POLY1305_TAG_SIZE);
    if (write_file(output_path, output, output_size) != 0) { fprintf(stderr, "Error: Cannot write output\n"); free(output); free(input); free(pk); return 1; }
    printf("Encrypted: %s -> %s (%zu bytes)\n", input_path, output_path, output_size);
    memset(shared_secret, 0, sizeof(shared_secret));
    free(output); free(input); free(pk);
    return 0;
}

static int cmd_decrypt(int argc, char** argv) {
    if (argc < 4) { fprintf(stderr, "Usage: luna_crypt decrypt <input> <secret_key> [output]\n"); return 1; }
    const char* input_path = argv[2]; const char* sk_path = argv[3];
    char output_path[512];
    if (argc > 4) strncpy(output_path, argv[4], sizeof(output_path) - 1);
    else { strncpy(output_path, input_path, sizeof(output_path) - 5); strcat(output_path, ".dec"); }
    size_t input_size, sk_size;
    uint8_t* input = read_file(input_path, &input_size);
    uint8_t* sk = read_file(sk_path, &sk_size);
    if (!input || !sk || sk_size != KYBER_SECRETKEYBYTES || input_size < HEADER_SIZE) { fprintf(stderr, "Error: Invalid input\n"); free(input); free(sk); return 1; }
    if (memcmp(input, ENCRYPTED_MAGIC, 8) != 0) { fprintf(stderr, "Error: Not an encrypted file\n"); free(input); free(sk); return 1; }
    printf("Decrypting %zu bytes...\n", input_size);
    const uint8_t* p = input + 8;
    const uint8_t* kyber_ct = p; p += KYBER_CIPHERTEXTBYTES;
    const uint8_t* nonce = p; p += CHACHA_NONCE_SIZE;
    const uint8_t* tag = p; p += POLY1305_TAG_SIZE;
    const uint8_t* ciphertext = p;
    size_t ct_len = input_size - HEADER_SIZE;
    uint8_t shared_secret[KYBER_SSBYTES];
    if (pqcrystals_kyber1024_ref_dec(shared_secret, kyber_ct, sk) != 0) { fprintf(stderr, "Error: Kyber decapsulation failed\n"); free(input); free(sk); return 1; }
    uint8_t* output = malloc(ct_len); if (!output) { free(input); free(sk); return 1; }
    if (chacha20poly1305_decrypt(output, ciphertext, ct_len, tag, nonce, shared_secret) != 0) {
        fprintf(stderr, "Error: Authentication failed - file corrupted or tampered!\n");
        memset(shared_secret, 0, sizeof(shared_secret)); free(output); free(input); free(sk); return 1;
    }
    if (write_file(output_path, output, ct_len) != 0) { fprintf(stderr, "Error: Cannot write output\n"); free(output); free(input); free(sk); return 1; }
    printf("Decrypted: %s -> %s (%zu bytes)\n", input_path, output_path, ct_len);
    memset(shared_secret, 0, sizeof(shared_secret));
    free(output); free(input); free(sk);
    return 0;
}

int main(int argc, char** argv) {
    if (argc < 2) { print_usage(argv[0]); return 1; }
    if (strcmp(argv[1], "keygen") == 0) return cmd_keygen(argc, argv);
    if (strcmp(argv[1], "encrypt") == 0) return cmd_encrypt(argc, argv);
    if (strcmp(argv[1], "decrypt") == 0) return cmd_decrypt(argc, argv);
    if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) { print_usage(argv[0]); return 0; }
    fprintf(stderr, "Unknown command: %s\n", argv[1]); return 1;
}
LUNA_CRYPT_EOF
}

# ============================================================================
# Main
# ============================================================================

case "${1:-}" in
    tools)
        check_deps
        download_pqcrystals
        build_tools
        ;;
    keys)
        generate_keys
        ;;
    embed)
        generate_embedded_keys
        ;;
    ""|all)
        check_deps
        download_pqcrystals
        build_tools
        generate_keys
        generate_embedded_keys
        echo ""
        echo -e "${GREEN}=== Setup Complete ===${NC}"
        echo -e "Keys are in: ${CYAN}$KEYS_DIR${NC}"
        echo -e "Next steps:"
        echo -e "  1. Build the bootloader: ${YELLOW}cd $NULL_ROOT && make${NC}"
        echo -e "  2. Sign your kernel:     ${YELLOW}$TOOLS_DIR/dilithium-ref/ref/luna_sign sign <kernel> $KEYS_DIR/signing.sec${NC}"
        ;;
    *)
        echo "Usage: $0 [tools|keys|embed|all]"
        echo ""
        echo "  tools   - Download pq-crystals and build luna_sign/luna_crypt"
        echo "  keys    - Generate signing and encryption keys"
        echo "  embed   - Generate embedded_keys.h for bootloader"
        echo "  all     - Do everything (default)"
        exit 1
        ;;
esac
