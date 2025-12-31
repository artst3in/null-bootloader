#!/usr/bin/env bash
# ============================================================================
# Null Bootloader - One-Click PQCrypto Setup
# ============================================================================
# Run this script to set up post-quantum crypto and build the bootloader.
#
# Usage:
#   ./setup-pqcrypto.sh          # Setup crypto, generate keys, build bootloader
#   ./setup-pqcrypto.sh --help   # Show help
#
# Copyright 2025 The LunaOS Contributors
# SPDX-License-Identifier: Apache-2.0
# ============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

show_help() {
    cat << 'EOF'
Null Bootloader - PQCrypto Setup

This script sets up post-quantum cryptography for secure boot:
  - Downloads pq-crystals reference implementations (Dilithium, Kyber)
  - Builds signing and encryption tools
  - Generates cryptographic keys (if not present)
  - Embeds keys into bootloader
  - Builds the bootloader

USAGE:
    ./setup-pqcrypto.sh [OPTIONS]

OPTIONS:
    --help          Show this help message
    --tools-only    Only build crypto tools, don't generate keys or build bootloader
    --keys-only     Only generate keys (tools must exist)
    --build-only    Only build bootloader (keys must exist)
    --clean         Clean everything and start fresh
    --no-kyber      Don't embed Kyber decryption key (signing only)

EXAMPLES:
    # First time setup (does everything):
    ./setup-pqcrypto.sh

    # Regenerate keys only:
    rm -rf tools/pqcrypto/keys && ./setup-pqcrypto.sh --keys-only

    # Just rebuild bootloader after code changes:
    ./setup-pqcrypto.sh --build-only

SECURITY:
    After setup, BACK UP your secret keys:
        tools/pqcrypto/keys/signing.sec    - Used to sign kernels
        tools/pqcrypto/keys/encryption.sec - Used to encrypt kernels

    The public signing key is embedded in the bootloader.
    Anyone with the secret key can sign kernels that the bootloader will accept.

EOF
}

# Parse arguments
TOOLS_ONLY=false
KEYS_ONLY=false
BUILD_ONLY=false
CLEAN=false
NO_KYBER=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --help|-h)
            show_help
            exit 0
            ;;
        --tools-only)
            TOOLS_ONLY=true
            shift
            ;;
        --keys-only)
            KEYS_ONLY=true
            shift
            ;;
        --build-only)
            BUILD_ONLY=true
            shift
            ;;
        --clean)
            CLEAN=true
            shift
            ;;
        --no-kyber)
            NO_KYBER=true
            shift
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            show_help
            exit 1
            ;;
    esac
done

echo -e "${CYAN}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║     Null Bootloader - Post-Quantum Crypto Setup          ║${NC}"
echo -e "${CYAN}╚═══════════════════════════════════════════════════════════╝${NC}"
echo ""

# ============================================================================
# Clean
# ============================================================================

if [ "$CLEAN" = true ]; then
    echo -e "${YELLOW}[CLEAN] Removing generated files...${NC}"
    rm -rf tools/pqcrypto/dilithium-ref
    rm -rf tools/pqcrypto/kyber-ref
    rm -rf tools/pqcrypto/keys
    rm -f common/crypt/embedded_keys.h
    make clean 2>/dev/null || true
    echo -e "${GREEN}[OK] Cleaned${NC}"
fi

# ============================================================================
# Setup directories
# ============================================================================

mkdir -p tools/pqcrypto/keys

# ============================================================================
# Tools Setup
# ============================================================================

TOOLS_DIR="$SCRIPT_DIR/tools/pqcrypto"
DILITHIUM_DIR="$TOOLS_DIR/dilithium-ref"
KYBER_DIR="$TOOLS_DIR/kyber-ref"
KEYS_DIR="$TOOLS_DIR/keys"

setup_tools() {
    echo -e "${CYAN}[1/4] Setting up PQCrypto tools...${NC}"

    # Check for gcc
    if ! command -v gcc &> /dev/null; then
        echo -e "${RED}[ERROR] gcc not found. Please install a C compiler.${NC}"
        exit 1
    fi

    # Download Dilithium
    if [ ! -d "$DILITHIUM_DIR/ref" ]; then
        echo -e "${YELLOW}  Downloading Dilithium reference...${NC}"
        git clone --depth 1 https://github.com/pq-crystals/dilithium.git "$DILITHIUM_DIR"
    fi

    # Download Kyber
    if [ ! -d "$KYBER_DIR/ref" ]; then
        echo -e "${YELLOW}  Downloading Kyber reference...${NC}"
        git clone --depth 1 https://github.com/pq-crystals/kyber.git "$KYBER_DIR"
    fi

    # Create luna_sign.c
    create_luna_sign_c

    # Create luna_crypt.c
    create_luna_crypt_c

    # Build luna_sign
    echo -e "${YELLOW}  Building luna_sign (Dilithium-3)...${NC}"
    (cd "$DILITHIUM_DIR/ref" && \
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

    # Build luna_crypt
    echo -e "${YELLOW}  Building luna_crypt (Kyber-1024)...${NC}"
    (cd "$KYBER_DIR/ref" && \
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

    echo -e "${GREEN}  [OK] Tools built${NC}"
}

# ============================================================================
# Key Generation
# ============================================================================

generate_keys() {
    echo -e "${CYAN}[2/4] Generating cryptographic keys...${NC}"

    LUNA_SIGN="$DILITHIUM_DIR/ref/luna_sign"
    LUNA_CRYPT="$KYBER_DIR/ref/luna_crypt"
    [ -f "${LUNA_SIGN}.exe" ] && LUNA_SIGN="${LUNA_SIGN}.exe"
    [ -f "${LUNA_CRYPT}.exe" ] && LUNA_CRYPT="${LUNA_CRYPT}.exe"

    if [ ! -f "$KEYS_DIR/signing.sec" ]; then
        echo -e "${MAGENTA}  Generating Dilithium-3 signing keypair...${NC}"
        "$LUNA_SIGN" keygen "$KEYS_DIR" signing
    else
        echo -e "${GREEN}  [OK] Signing keys exist${NC}"
    fi

    if [ "$NO_KYBER" != true ] && [ ! -f "$KEYS_DIR/encryption.sec" ]; then
        echo -e "${MAGENTA}  Generating Kyber-1024 encryption keypair...${NC}"
        "$LUNA_CRYPT" keygen "$KEYS_DIR" encryption
    elif [ "$NO_KYBER" = true ]; then
        echo -e "${YELLOW}  [SKIP] Kyber keys (--no-kyber)${NC}"
    else
        echo -e "${GREEN}  [OK] Encryption keys exist${NC}"
    fi
}

# ============================================================================
# Embed Keys
# ============================================================================

embed_keys() {
    echo -e "${CYAN}[3/4] Embedding keys into bootloader...${NC}"

    OUTPUT="$SCRIPT_DIR/common/crypt/embedded_keys.h"
    DILITHIUM_PK="$KEYS_DIR/signing.pub"
    KYBER_SK="$KEYS_DIR/encryption.sec"

    if [ ! -f "$DILITHIUM_PK" ]; then
        echo -e "${RED}[ERROR] Signing public key not found${NC}"
        exit 1
    fi

    {
        echo "// Auto-generated by setup-pqcrypto.sh - DO NOT EDIT"
        echo "// Generated: $(date -u +"%Y-%m-%d %H:%M:%S UTC")"
        echo ""
        echo "#ifndef EMBEDDED_KEYS_H"
        echo "#define EMBEDDED_KEYS_H"
        echo ""
        echo "#include <stdint.h>"
        echo ""
        echo "// Dilithium-3 public key for signature verification (1952 bytes)"
        echo "#define DILITHIUM_PUBLICKEYBYTES 1952"
        echo "static const uint8_t DILITHIUM_PUBLIC_KEY[DILITHIUM_PUBLICKEYBYTES] = {"
        xxd -i < "$DILITHIUM_PK" | grep -v "unsigned" | sed 's/^/    /'
        echo "};"
        echo ""

        if [ "$NO_KYBER" != true ] && [ -f "$KYBER_SK" ]; then
            echo "// Kyber-1024 secret key for decryption (3168 bytes)"
            echo "#define KYBER_SECRETKEYBYTES 3168"
            echo "#define HAVE_KYBER_KEY 1"
            echo "static const uint8_t KYBER_SECRET_KEY[KYBER_SECRETKEYBYTES] = {"
            xxd -i < "$KYBER_SK" | grep -v "unsigned" | sed 's/^/    /'
            echo "};"
        else
            echo "#define HAVE_KYBER_KEY 0"
        fi

        echo ""
        echo "#endif // EMBEDDED_KEYS_H"
    } > "$OUTPUT"

    echo -e "${GREEN}  [OK] Generated: $OUTPUT${NC}"

    # Print key ID
    LUNA_SIGN="$DILITHIUM_DIR/ref/luna_sign"
    [ -f "${LUNA_SIGN}.exe" ] && LUNA_SIGN="${LUNA_SIGN}.exe"
    if [ -f "$LUNA_SIGN" ]; then
        KEY_ID=$("$LUNA_SIGN" keyid "$DILITHIUM_PK" 2>/dev/null || echo "unknown")
        echo -e "${MAGENTA}  Key ID: $KEY_ID${NC}"
    fi
}

# ============================================================================
# Build Bootloader
# ============================================================================

build_bootloader() {
    echo -e "${CYAN}[4/4] Building bootloader...${NC}"

    # Check if embedded_keys.h exists
    if [ ! -f "$SCRIPT_DIR/common/crypt/embedded_keys.h" ]; then
        echo -e "${RED}[ERROR] embedded_keys.h not found. Run setup first.${NC}"
        exit 1
    fi

    # Configure if needed
    if [ ! -f "$SCRIPT_DIR/GNUmakefile" ]; then
        echo -e "${YELLOW}  Running configure...${NC}"
        ./bootstrap
        ./configure
    fi

    # Build
    make -j$(nproc 2>/dev/null || echo 4)

    if [ -f "$SCRIPT_DIR/bin/BOOTX64.EFI" ]; then
        echo -e "${GREEN}  [OK] Bootloader built: bin/BOOTX64.EFI${NC}"
    else
        echo -e "${RED}[ERROR] Build failed${NC}"
        exit 1
    fi
}

# ============================================================================
# Create luna_sign.c
# ============================================================================

create_luna_sign_c() {
    [ -f "$DILITHIUM_DIR/ref/luna_sign.c" ] && return

    cat > "$DILITHIUM_DIR/ref/luna_sign.c" << 'LUNA_SIGN_EOF'
// luna_sign - Kernel Signing Tool (Dilithium-3)
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

static void print_key_id(const uint8_t* pk) {
    uint8_t hash[32]; shake256(hash, 32, pk, PUBLICKEY_SIZE);
    for (int i = 0; i < 8; i++) printf("%02x", hash[i]);
}

static void print_usage(const char* prog) {
    printf("luna_sign - Kernel Signing Tool (Dilithium-3)\n\n");
    printf("Usage:\n");
    printf("  %s keygen <dir> [name]        Generate keypair\n", prog);
    printf("  %s sign <file> <key.sec> [o]  Sign file (appends signature)\n", prog);
    printf("  %s verify <file> <key.pub>    Verify appended signature\n", prog);
    printf("  %s keyid <key.pub>            Print key ID\n", prog);
}

static int cmd_keygen(int argc, char** argv) {
    const char* dir = argc > 2 ? argv[2] : ".";
    const char* name = argc > 3 ? argv[3] : "signing";
    char pub[512], sec[512];
    snprintf(pub, sizeof(pub), "%s/%s.pub", dir, name);
    snprintf(sec, sizeof(sec), "%s/%s.sec", dir, name);
    printf("Generating Dilithium-3 keypair...\n");
    uint8_t pk[PUBLICKEY_SIZE], sk[SECRETKEY_SIZE];
    if (pqcrystals_dilithium3_ref_keypair(pk, sk) != 0) { fprintf(stderr, "Error: keygen failed\n"); return 1; }
    if (write_file(pub, pk, PUBLICKEY_SIZE) != 0 || write_file(sec, sk, SECRETKEY_SIZE) != 0) { fprintf(stderr, "Error: write failed\n"); return 1; }
    printf("  Public:  %s (%d bytes)\n", pub, PUBLICKEY_SIZE);
    printf("  Secret:  %s (%d bytes)\n", sec, SECRETKEY_SIZE);
    printf("  Key ID:  "); print_key_id(pk); printf("\n");
    return 0;
}

static int cmd_sign(int argc, char** argv) {
    if (argc < 4) { fprintf(stderr, "Usage: luna_sign sign <file> <key.sec> [output]\n"); return 1; }
    char out[512];
    if (argc > 4) strncpy(out, argv[4], sizeof(out)-1);
    else snprintf(out, sizeof(out), "%s.signed", argv[2]);
    size_t in_sz, sk_sz;
    uint8_t* in = read_file(argv[2], &in_sz);
    uint8_t* sk = read_file(argv[3], &sk_sz);
    if (!in || !sk || sk_sz != SECRETKEY_SIZE) { fprintf(stderr, "Error: invalid input\n"); free(in); free(sk); return 1; }
    uint8_t sig[SIGNATURE_SIZE]; size_t siglen;
    if (pqcrystals_dilithium3_ref_signature(sig, &siglen, in, in_sz, NULL, 0, sk) != 0) { fprintf(stderr, "Error: sign failed\n"); free(in); free(sk); return 1; }
    size_t out_sz = in_sz + SIGNATURE_SIZE;
    uint8_t* output = malloc(out_sz);
    memcpy(output, in, in_sz);
    memcpy(output + in_sz, sig, SIGNATURE_SIZE);
    if (write_file(out, output, out_sz) != 0) { fprintf(stderr, "Error: write failed\n"); free(output); free(in); free(sk); return 1; }
    printf("Signed: %s (%zu + %d bytes)\n", out, in_sz, SIGNATURE_SIZE);
    free(output); free(in); free(sk);
    return 0;
}

static int cmd_verify(int argc, char** argv) {
    if (argc < 4) { fprintf(stderr, "Usage: luna_sign verify <file> <key.pub>\n"); return 1; }
    size_t d_sz, pk_sz;
    uint8_t* d = read_file(argv[2], &d_sz);
    uint8_t* pk = read_file(argv[3], &pk_sz);
    if (!d || !pk || pk_sz != PUBLICKEY_SIZE || d_sz < SIGNATURE_SIZE) { fprintf(stderr, "Error: invalid input\n"); free(d); free(pk); return 1; }
    size_t msg_sz = d_sz - SIGNATURE_SIZE;
    int r = pqcrystals_dilithium3_ref_verify(d + msg_sz, SIGNATURE_SIZE, d, msg_sz, NULL, 0, pk);
    if (r == 0) { printf("VALID (key: "); print_key_id(pk); printf(")\n"); }
    else fprintf(stderr, "INVALID!\n");
    free(d); free(pk);
    return r == 0 ? 0 : 1;
}

static int cmd_keyid(int argc, char** argv) {
    if (argc < 3) { fprintf(stderr, "Usage: luna_sign keyid <key.pub>\n"); return 1; }
    size_t sz; uint8_t* pk = read_file(argv[2], &sz);
    if (!pk || sz != PUBLICKEY_SIZE) { fprintf(stderr, "Error: invalid key\n"); free(pk); return 1; }
    print_key_id(pk); printf("\n");
    free(pk); return 0;
}

int main(int argc, char** argv) {
    if (argc < 2) { print_usage(argv[0]); return 1; }
    if (strcmp(argv[1], "keygen") == 0) return cmd_keygen(argc, argv);
    if (strcmp(argv[1], "sign") == 0) return cmd_sign(argc, argv);
    if (strcmp(argv[1], "verify") == 0) return cmd_verify(argc, argv);
    if (strcmp(argv[1], "keyid") == 0) return cmd_keyid(argc, argv);
    if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) { print_usage(argv[0]); return 0; }
    fprintf(stderr, "Unknown: %s\n", argv[1]); return 1;
}
LUNA_SIGN_EOF
}

# ============================================================================
# Create luna_crypt.c
# ============================================================================

create_luna_crypt_c() {
    [ -f "$KYBER_DIR/ref/luna_crypt.c" ] && return

    cat > "$KYBER_DIR/ref/luna_crypt.c" << 'LUNA_CRYPT_EOF'
// luna_crypt - Kernel Encryption Tool (Kyber-1024 + ChaCha20-Poly1305)
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

static const uint8_t MAGIC[8] = {'L','U','N','A','E','N','C','1'};
#define NONCE_SZ 12
#define TAG_SZ 16
#define HDR_SZ (8 + KYBER_CIPHERTEXTBYTES + NONCE_SZ + TAG_SZ)

#define ROTL32(x,n) (((x)<<(n))|((x)>>(32-(n))))
#define U8TO32(p) ((uint32_t)(p)[0]|((uint32_t)(p)[1]<<8)|((uint32_t)(p)[2]<<16)|((uint32_t)(p)[3]<<24))
#define U32TO8(p,v) do{(p)[0]=(uint8_t)(v);(p)[1]=(uint8_t)((v)>>8);(p)[2]=(uint8_t)((v)>>16);(p)[3]=(uint8_t)((v)>>24);}while(0)
#define U64TO8(p,v) do{U32TO8(p,(uint32_t)(v));U32TO8((p)+4,(uint32_t)((v)>>32));}while(0)
#define QR(a,b,c,d) do{a+=b;d^=a;d=ROTL32(d,16);c+=d;b^=c;b=ROTL32(b,12);a+=b;d^=a;d=ROTL32(d,8);c+=d;b^=c;b=ROTL32(b,7);}while(0)

static const uint32_t CC[4]={0x61707865,0x3320646e,0x79622d32,0x6b206574};
typedef struct{uint32_t s[16];}cc_ctx;

static void cc_init(cc_ctx*c,const uint8_t k[32],const uint8_t n[12],uint32_t ctr){
    c->s[0]=CC[0];c->s[1]=CC[1];c->s[2]=CC[2];c->s[3]=CC[3];
    for(int i=0;i<8;i++)c->s[4+i]=U8TO32(k+4*i);
    c->s[12]=ctr;c->s[13]=U8TO32(n);c->s[14]=U8TO32(n+4);c->s[15]=U8TO32(n+8);
}

static void cc_block(cc_ctx*c,uint8_t o[64]){
    uint32_t x[16];for(int i=0;i<16;i++)x[i]=c->s[i];
    for(int i=0;i<10;i++){QR(x[0],x[4],x[8],x[12]);QR(x[1],x[5],x[9],x[13]);QR(x[2],x[6],x[10],x[14]);QR(x[3],x[7],x[11],x[15]);QR(x[0],x[5],x[10],x[15]);QR(x[1],x[6],x[11],x[12]);QR(x[2],x[7],x[8],x[13]);QR(x[3],x[4],x[9],x[14]);}
    for(int i=0;i<16;i++){x[i]+=c->s[i];U32TO8(o+4*i,x[i]);}
    c->s[12]++;
}

static void cc_crypt(const uint8_t k[32],const uint8_t n[12],uint8_t*o,const uint8_t*in,size_t len){
    cc_ctx c;cc_init(&c,k,n,1);uint8_t b[64];size_t i=0;
    while(len>=64){cc_block(&c,b);for(int j=0;j<64;j++)o[i+j]=in[i+j]^b[j];i+=64;len-=64;}
    if(len>0){cc_block(&c,b);for(size_t j=0;j<len;j++)o[i+j]=in[i+j]^b[j];}
}

typedef struct{uint32_t r[5],h[5],pad[4];size_t left;uint8_t buf[16];}p_ctx;

static void p_init(p_ctx*c,const uint8_t k[32]){
    c->r[0]=(U8TO32(k))&0x3ffffff;c->r[1]=(U8TO32(k+3)>>2)&0x3ffff03;c->r[2]=(U8TO32(k+6)>>4)&0x3ffc0ff;c->r[3]=(U8TO32(k+9)>>6)&0x3f03fff;c->r[4]=(U8TO32(k+12)>>8)&0x00fffff;
    for(int i=0;i<4;i++)c->pad[i]=U8TO32(k+16+4*i);
    for(int i=0;i<5;i++)c->h[i]=0;c->left=0;
}

static void p_blocks(p_ctx*c,const uint8_t*m,size_t b,uint32_t hi){
    uint32_t r0=c->r[0],r1=c->r[1],r2=c->r[2],r3=c->r[3],r4=c->r[4];
    uint32_t s1=r1*5,s2=r2*5,s3=r3*5,s4=r4*5;
    uint32_t h0=c->h[0],h1=c->h[1],h2=c->h[2],h3=c->h[3],h4=c->h[4];
    while(b>=16){
        h0+=(U8TO32(m))&0x3ffffff;h1+=(U8TO32(m+3)>>2)&0x3ffffff;h2+=(U8TO32(m+6)>>4)&0x3ffffff;h3+=(U8TO32(m+9)>>6)&0x3ffffff;h4+=(U8TO32(m+12)>>8)|hi;
        uint64_t d0=(uint64_t)h0*r0+(uint64_t)h1*s4+(uint64_t)h2*s3+(uint64_t)h3*s2+(uint64_t)h4*s1;
        uint64_t d1=(uint64_t)h0*r1+(uint64_t)h1*r0+(uint64_t)h2*s4+(uint64_t)h3*s3+(uint64_t)h4*s2;
        uint64_t d2=(uint64_t)h0*r2+(uint64_t)h1*r1+(uint64_t)h2*r0+(uint64_t)h3*s4+(uint64_t)h4*s3;
        uint64_t d3=(uint64_t)h0*r3+(uint64_t)h1*r2+(uint64_t)h2*r1+(uint64_t)h3*r0+(uint64_t)h4*s4;
        uint64_t d4=(uint64_t)h0*r4+(uint64_t)h1*r3+(uint64_t)h2*r2+(uint64_t)h3*r1+(uint64_t)h4*r0;
        uint32_t cc=(uint32_t)(d0>>26);h0=(uint32_t)d0&0x3ffffff;d1+=cc;cc=(uint32_t)(d1>>26);h1=(uint32_t)d1&0x3ffffff;
        d2+=cc;cc=(uint32_t)(d2>>26);h2=(uint32_t)d2&0x3ffffff;d3+=cc;cc=(uint32_t)(d3>>26);h3=(uint32_t)d3&0x3ffffff;
        d4+=cc;cc=(uint32_t)(d4>>26);h4=(uint32_t)d4&0x3ffffff;h0+=cc*5;cc=h0>>26;h0&=0x3ffffff;h1+=cc;
        m+=16;b-=16;
    }
    c->h[0]=h0;c->h[1]=h1;c->h[2]=h2;c->h[3]=h3;c->h[4]=h4;
}

static void p_update(p_ctx*c,const uint8_t*m,size_t b){
    if(c->left){size_t w=16-c->left;if(w>b)w=b;memcpy(c->buf+c->left,m,w);b-=w;m+=w;c->left+=w;if(c->left<16)return;p_blocks(c,c->buf,16,1<<24);c->left=0;}
    if(b>=16){size_t w=b&~15;p_blocks(c,m,w,1<<24);m+=w;b-=w;}
    if(b){memcpy(c->buf,m,b);c->left=b;}
}

static void p_finish(p_ctx*c,uint8_t t[16]){
    if(c->left){c->buf[c->left++]=1;while(c->left<16)c->buf[c->left++]=0;p_blocks(c,c->buf,16,0);}
    uint32_t h0=c->h[0],h1=c->h[1],h2=c->h[2],h3=c->h[3],h4=c->h[4];
    uint32_t cc=h1>>26;h1&=0x3ffffff;h2+=cc;cc=h2>>26;h2&=0x3ffffff;h3+=cc;cc=h3>>26;h3&=0x3ffffff;h4+=cc;cc=h4>>26;h4&=0x3ffffff;h0+=cc*5;cc=h0>>26;h0&=0x3ffffff;h1+=cc;
    uint32_t g0=h0+5;cc=g0>>26;g0&=0x3ffffff;uint32_t g1=h1+cc;cc=g1>>26;g1&=0x3ffffff;uint32_t g2=h2+cc;cc=g2>>26;g2&=0x3ffffff;uint32_t g3=h3+cc;cc=g3>>26;g3&=0x3ffffff;uint32_t g4=h4+cc-(1<<26);
    uint32_t mask=(g4>>31)-1;g0&=mask;g1&=mask;g2&=mask;g3&=mask;g4&=mask;mask=~mask;
    h0=(h0&mask)|g0;h1=(h1&mask)|g1;h2=(h2&mask)|g2;h3=(h3&mask)|g3;h4=(h4&mask)|g4;
    h0=h0|(h1<<26);h1=(h1>>6)|(h2<<20);h2=(h2>>12)|(h3<<14);h3=(h3>>18)|(h4<<8);
    uint64_t f=(uint64_t)h0+c->pad[0];h0=(uint32_t)f;f=(uint64_t)h1+c->pad[1]+(f>>32);h1=(uint32_t)f;f=(uint64_t)h2+c->pad[2]+(f>>32);h2=(uint32_t)f;f=(uint64_t)h3+c->pad[3]+(f>>32);h3=(uint32_t)f;
    U32TO8(t,h0);U32TO8(t+4,h1);U32TO8(t+8,h2);U32TO8(t+12,h3);
}

static void aead_enc(uint8_t*ct,uint8_t t[16],const uint8_t*pt,size_t len,const uint8_t n[12],const uint8_t k[32]){
    uint8_t pk[64];cc_ctx c;cc_init(&c,k,n,0);cc_block(&c,pk);
    cc_crypt(k,n,ct,pt,len);
    p_ctx p;p_init(&p,pk);p_update(&p,ct,len);
    if(len%16){uint8_t z[16]={0};p_update(&p,z,16-(len%16));}
    uint8_t l[16]={0};U64TO8(l+8,len);p_update(&p,l,16);
    p_finish(&p,t);
}

static int aead_dec(uint8_t*pt,const uint8_t*ct,size_t len,const uint8_t t[16],const uint8_t n[12],const uint8_t k[32]){
    uint8_t pk[64];cc_ctx c;cc_init(&c,k,n,0);cc_block(&c,pk);
    p_ctx p;p_init(&p,pk);p_update(&p,ct,len);
    if(len%16){uint8_t z[16]={0};p_update(&p,z,16-(len%16));}
    uint8_t l[16]={0};U64TO8(l+8,len);p_update(&p,l,16);
    uint8_t ct2[16];p_finish(&p,ct2);
    uint8_t d=0;for(int i=0;i<16;i++)d|=ct2[i]^t[i];
    if(d!=0)return-1;
    cc_crypt(k,n,pt,ct,len);return 0;
}

static uint8_t*rd(const char*p,size_t*sz){FILE*f=fopen(p,"rb");if(!f)return NULL;fseek(f,0,SEEK_END);*sz=ftell(f);fseek(f,0,SEEK_SET);uint8_t*d=malloc(*sz);if(!d){fclose(f);return NULL;}if(fread(d,1,*sz,f)!=*sz){free(d);fclose(f);return NULL;}fclose(f);return d;}
static int wr(const char*p,const uint8_t*d,size_t sz){FILE*f=fopen(p,"wb");if(!f)return-1;if(fwrite(d,1,sz,f)!=sz){fclose(f);return-1;}fclose(f);return 0;}

static void usage(const char*p){printf("luna_crypt - Encryption Tool (Kyber-1024 + ChaCha20-Poly1305)\n\nUsage:\n  %s keygen <dir> [name]\n  %s encrypt <in> <pk> [out]\n  %s decrypt <in> <sk> [out]\n",p,p,p);}

static int cmd_keygen(int ac,char**av){
    const char*d=ac>2?av[2]:".";const char*n=ac>3?av[3]:"encryption";
    char pub[512],sec[512];snprintf(pub,sizeof(pub),"%s/%s.pub",d,n);snprintf(sec,sizeof(sec),"%s/%s.sec",d,n);
    printf("Generating Kyber-1024 keypair...\n");
    uint8_t pk[KYBER_PUBLICKEYBYTES],sk[KYBER_SECRETKEYBYTES];
    if(pqcrystals_kyber1024_ref_keypair(pk,sk)!=0){fprintf(stderr,"Error\n");return 1;}
    if(wr(pub,pk,KYBER_PUBLICKEYBYTES)!=0||wr(sec,sk,KYBER_SECRETKEYBYTES)!=0){fprintf(stderr,"Write error\n");return 1;}
    printf("  Public:  %s (%d bytes)\n  Secret:  %s (%d bytes)\n",pub,KYBER_PUBLICKEYBYTES,sec,KYBER_SECRETKEYBYTES);
    uint8_t h[32];shake256(h,32,pk,KYBER_PUBLICKEYBYTES);printf("  Key ID:  ");for(int i=0;i<8;i++)printf("%02x",h[i]);printf("\n");
    return 0;
}

static int cmd_encrypt(int ac,char**av){
    if(ac<4){fprintf(stderr,"Usage: luna_crypt encrypt <in> <pk> [out]\n");return 1;}
    char out[512];if(ac>4)strncpy(out,av[4],sizeof(out)-1);else snprintf(out,sizeof(out),"%s.enc",av[2]);
    size_t in_sz,pk_sz;uint8_t*in=rd(av[2],&in_sz);uint8_t*pk=rd(av[3],&pk_sz);
    if(!in||!pk||pk_sz!=KYBER_PUBLICKEYBYTES){fprintf(stderr,"Invalid input\n");free(in);free(pk);return 1;}
    printf("Encrypting %zu bytes...\n",in_sz);
    uint8_t ct[KYBER_CIPHERTEXTBYTES],ss[KYBER_SSBYTES];
    if(pqcrystals_kyber1024_ref_enc(ct,ss,pk)!=0){fprintf(stderr,"Kyber error\n");free(in);free(pk);return 1;}
    uint8_t nonce[NONCE_SZ];randombytes(nonce,NONCE_SZ);
    size_t out_sz=HDR_SZ+in_sz;uint8_t*o=malloc(out_sz);if(!o){free(in);free(pk);return 1;}
    uint8_t*p=o;memcpy(p,MAGIC,8);p+=8;memcpy(p,ct,KYBER_CIPHERTEXTBYTES);p+=KYBER_CIPHERTEXTBYTES;memcpy(p,nonce,NONCE_SZ);p+=NONCE_SZ;
    uint8_t*tp=p;p+=TAG_SZ;uint8_t tag[TAG_SZ];aead_enc(p,tag,in,in_sz,nonce,ss);memcpy(tp,tag,TAG_SZ);
    if(wr(out,o,out_sz)!=0){fprintf(stderr,"Write error\n");free(o);free(in);free(pk);return 1;}
    printf("Encrypted: %s (%zu bytes)\n",out,out_sz);
    memset(ss,0,sizeof(ss));free(o);free(in);free(pk);return 0;
}

static int cmd_decrypt(int ac,char**av){
    if(ac<4){fprintf(stderr,"Usage: luna_crypt decrypt <in> <sk> [out]\n");return 1;}
    char out[512];if(ac>4)strncpy(out,av[4],sizeof(out)-1);else{strncpy(out,av[2],sizeof(out)-5);strcat(out,".dec");}
    size_t in_sz,sk_sz;uint8_t*in=rd(av[2],&in_sz);uint8_t*sk=rd(av[3],&sk_sz);
    if(!in||!sk||sk_sz!=KYBER_SECRETKEYBYTES||in_sz<HDR_SZ){fprintf(stderr,"Invalid input\n");free(in);free(sk);return 1;}
    if(memcmp(in,MAGIC,8)!=0){fprintf(stderr,"Not encrypted\n");free(in);free(sk);return 1;}
    printf("Decrypting %zu bytes...\n",in_sz);
    const uint8_t*p=in+8;const uint8_t*ct=p;p+=KYBER_CIPHERTEXTBYTES;const uint8_t*nonce=p;p+=NONCE_SZ;const uint8_t*tag=p;p+=TAG_SZ;
    size_t ct_len=in_sz-HDR_SZ;
    uint8_t ss[KYBER_SSBYTES];if(pqcrystals_kyber1024_ref_dec(ss,ct,sk)!=0){fprintf(stderr,"Kyber error\n");free(in);free(sk);return 1;}
    uint8_t*o=malloc(ct_len);if(!o){free(in);free(sk);return 1;}
    if(aead_dec(o,p,ct_len,tag,nonce,ss)!=0){fprintf(stderr,"Auth failed!\n");memset(ss,0,sizeof(ss));free(o);free(in);free(sk);return 1;}
    if(wr(out,o,ct_len)!=0){fprintf(stderr,"Write error\n");free(o);free(in);free(sk);return 1;}
    printf("Decrypted: %s (%zu bytes)\n",out,ct_len);
    memset(ss,0,sizeof(ss));free(o);free(in);free(sk);return 0;
}

int main(int ac,char**av){
    if(ac<2){usage(av[0]);return 1;}
    if(strcmp(av[1],"keygen")==0)return cmd_keygen(ac,av);
    if(strcmp(av[1],"encrypt")==0)return cmd_encrypt(ac,av);
    if(strcmp(av[1],"decrypt")==0)return cmd_decrypt(ac,av);
    if(strcmp(av[1],"-h")==0||strcmp(av[1],"--help")==0){usage(av[0]);return 0;}
    fprintf(stderr,"Unknown: %s\n",av[1]);return 1;
}
LUNA_CRYPT_EOF
}

# ============================================================================
# Execute
# ============================================================================

if [ "$TOOLS_ONLY" = true ]; then
    setup_tools
    echo -e "${GREEN}Done! Run '$0' again to generate keys and build.${NC}"
elif [ "$KEYS_ONLY" = true ]; then
    generate_keys
    embed_keys
    echo -e "${GREEN}Done! Run '$0 --build-only' to build bootloader.${NC}"
elif [ "$BUILD_ONLY" = true ]; then
    build_bootloader
else
    # Full setup
    setup_tools
    generate_keys
    embed_keys
    build_bootloader

    echo ""
    echo -e "${GREEN}╔═══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                    Setup Complete!                        ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${CYAN}Bootloader:${NC} bin/BOOTX64.EFI"
    echo -e "${CYAN}Keys:${NC}       tools/pqcrypto/keys/"
    echo ""
    echo -e "${YELLOW}To sign a kernel:${NC}"
    echo "  tools/pqcrypto/dilithium-ref/ref/luna_sign sign <kernel> tools/pqcrypto/keys/signing.sec"
    echo ""
    echo -e "${YELLOW}To encrypt a kernel:${NC}"
    echo "  tools/pqcrypto/kyber-ref/ref/luna_crypt encrypt <kernel> tools/pqcrypto/keys/encryption.pub"
    echo ""
    echo -e "${RED}IMPORTANT: Back up your secret keys!${NC}"
    echo "  tools/pqcrypto/keys/signing.sec"
    echo "  tools/pqcrypto/keys/encryption.sec"
fi
