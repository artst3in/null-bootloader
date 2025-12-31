# Null Bootloader PQCrypto Tools

Post-quantum cryptography tools for signing and encrypting kernels.

## Quick Start

```bash
# From null-bootloader root directory:
./setup-pqcrypto.sh
```

This single command will:
1. Download pq-crystals reference implementations (Dilithium, Kyber)
2. Build `luna_sign` and `luna_crypt` tools
3. Generate signing and encryption keys
4. Embed keys into bootloader
5. Build the bootloader

## Algorithms

| Algorithm | Purpose | Security Level | Key Sizes |
|-----------|---------|----------------|-----------|
| Dilithium-3 | Signing | NIST Level 3 (128-bit) | PK: 1952B, SK: 4032B, Sig: 3309B |
| Kyber-1024 | Encryption | NIST Level 5 (256-bit) | PK: 1568B, SK: 3168B, CT: 1568B |
| ChaCha20-Poly1305 | Symmetric AEAD | 256-bit | Key: 32B, Nonce: 12B, Tag: 16B |

## Tools

### luna_sign

Signs kernels with Dilithium-3 (appends signature to file).

```bash
# Generate keypair
./dilithium-ref/ref/luna_sign keygen keys/ signing

# Sign kernel
./dilithium-ref/ref/luna_sign sign kernel.elf keys/signing.sec kernel.signed

# Verify signature
./dilithium-ref/ref/luna_sign verify kernel.signed keys/signing.pub

# Get key ID
./dilithium-ref/ref/luna_sign keyid keys/signing.pub
```

### luna_crypt

Encrypts kernels with Kyber-1024 + ChaCha20-Poly1305.

```bash
# Generate keypair
./kyber-ref/ref/luna_crypt keygen keys/ encryption

# Encrypt kernel
./kyber-ref/ref/luna_crypt encrypt kernel.elf keys/encryption.pub kernel.enc

# Decrypt kernel
./kyber-ref/ref/luna_crypt decrypt kernel.enc keys/encryption.sec kernel.dec
```

## Encrypted Kernel Format

```
┌─────────────────────────────────────────────────────────────────┐
│ Magic: "LUNAENC1" (8 bytes)                                     │
├─────────────────────────────────────────────────────────────────┤
│ Kyber-1024 Ciphertext (1568 bytes)                              │
├─────────────────────────────────────────────────────────────────┤
│ ChaCha20 Nonce (12 bytes)                                       │
├─────────────────────────────────────────────────────────────────┤
│ Poly1305 Tag (16 bytes)                                         │
├─────────────────────────────────────────────────────────────────┤
│ Encrypted Data (variable)                                       │
└─────────────────────────────────────────────────────────────────┘
```

Header size: 1604 bytes

## Security Notes

1. **Back up your secret keys** - If lost, you cannot sign new kernels
2. **Never commit .sec files** - They are gitignored by default
3. **Signing is per-developer** - Each developer has their own keys
4. **Bootloader + kernel are paired** - Must ship together

## How It Works

### Signing Flow
```
Developer                           User
    │                                 │
    │  kernel.elf                     │
    │      │                          │
    │  ┌───▼───────┐                  │
    │  │ luna_sign │                  │
    │  └───┬───────┘                  │
    │      │                          │
    │  kernel.signed ─────────────►   │
    │                                 │
    │  BOOTX64.EFI ──────────────►    │
    │  (with public key)              │
    │                             ┌───▼─────────────┐
    │                             │ Bootloader      │
    │                             │ verifies sig    │
    │                             │ with embedded   │
    │                             │ public key      │
    │                             └─────────────────┘
```

### Encryption Flow (Optional)
```
Developer                           User
    │                                 │
    │  kernel.signed                  │
    │      │                          │
    │  ┌───▼────────┐                 │
    │  │ luna_crypt │                 │
    │  │ (uses PK)  │                 │
    │  └───┬────────┘                 │
    │      │                          │
    │  kernel.enc ───────────────►    │
    │                                 │
    │  BOOTX64.EFI ─────────────►     │
    │  (with secret key)              │
    │                             ┌───▼─────────────┐
    │                             │ Bootloader      │
    │                             │ decrypts with   │
    │                             │ embedded SK,    │
    │                             │ then verifies   │
    │                             │ signature       │
    │                             └─────────────────┘
```

## License

Apache-2.0
