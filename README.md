<div align="center">

# 🌙 Null
### **The Minimal Bootloader**

*A Stripped-Down Limine Fork for LunaOS*

[![Version](https://img.shields.io/badge/version-2026.01-blue.svg)]()
[![License](https://img.shields.io/badge/license-BSD%202--Clause-green.svg)](COPYING)
[![Platform](https://img.shields.io/badge/platform-x64%20%7C%20UEFI%20%7C%20BIOS-orange.svg)]()
[![Lines Removed](https://img.shields.io/badge/lines_removed-4%2C300-red.svg)]()

**🚀 Minimal** • **🛡️ Proven** • **⚡ Fast** • **🌙 LunaOS-Native**

[Features](#-features) •
[What We Changed](#-what-we-changed) •
[What We Kept](#-what-we-kept) •
[Philosophy](#-philosophy)

</div>

---

## 🎯 What is Null?

**Null** is a **minimal bootloader** for LunaOS - a stripped-down fork of [Limine](https://github.com/limine-bootloader/limine) with ~4,300 lines of dead code removed. It does exactly one thing: boot LunaOS kernels via the Limine protocol.

**The numbers:**

- 🗑️ **~4,300 lines removed** - Multiboot, Linux boot, Chainload, ISO9660
- 📦 **19 files deleted** - unused protocol handlers and filesystems
- ✅ **1 protocol supported** - Limine (the only one LunaOS uses)
- 🔒 **0 regressions** - boot process untouched

> 💡 **Philosophy:** Use proven code. Remove unused code. Touch nothing else.

---

## ✨ Features

### 🚀 What Null Does

<table>
<tr>
<td width="50%">

**🖥️ Boot LunaOS**
- 🔧 Limine protocol (full support)
- 📋 Boot menu (recovery/older kernels)
- 💾 UEFI & BIOS boot
- 🔀 SMP initialization

</td>
<td width="50%">

**🌐 Network & Storage**
- 📁 FAT32 filesystem
- 🌍 PXE/TFTP network boot
- 💿 EFI partition support
- 🔐 Classical crypto (Ed25519/X25519)

</td>
</tr>
</table>

### 🚫 What Null Doesn't Do

<table>
<tr>
<td width="33%">

**❌ Removed Protocols**
- ~~Multiboot 1/2~~
- ~~Linux boot~~
- ~~Chainload~~

</td>
<td width="33%">

**❌ Removed Filesystems**
- ~~ISO9660~~
- ~~CD/DVD boot~~

</td>
<td width="33%">

**💡 Why?**
- 🎯 LunaOS uses Limine only
- 🛡️ Dead code = attack surface
- ⚡ Smaller = faster boot

</td>
</tr>
</table>

---

## 🔧 What We Changed

| Component | Lines Removed | Status |
|-----------|---------------|--------|
| 📄 `multiboot1.c/h` | ~560 | 🗑️ Deleted |
| 📄 `multiboot2.c/h` | ~1,360 | 🗑️ Deleted |
| 📄 `linux_x86.c` | ~630 | 🗑️ Deleted |
| 📄 `linux_risc.c` | ~450 | 🗑️ Deleted |
| 📄 `chainload.c/h` | ~370 | 🗑️ Deleted |
| 📄 `iso9660.s2.c/h` | ~580 | 🗑️ Deleted |
| 🔩 Assembly files | ~220 | 🗑️ Deleted |
| 📋 `menu.c` dispatch | ~30 | ✂️ Simplified |
| **📊 Total** | **~4,300** | **✅ Gone** |

---

## 🛡️ What We Kept

| Component | Purpose | Status |
|-----------|---------|--------|
| 🔧 **Limine protocol** | Boot LunaOS kernels | ✅ Essential |
| 📋 **Boot menu** | Recovery mode, kernel selection | ✅ Essential |
| 📁 **FAT32** | Read kernel from EFI partition | ✅ Essential |
| 🌐 **PXE/TFTP** | Network boot (sister resurrection) | 💡 Useful |
| 🔐 **Crypto** | Ed25519 signatures & X25519 encryption | ✅ Essential |
| 🗺️ **Memory map** | DO NOT TOUCH | 🔒 Sacred |
| 🔀 **SMP boot** | DO NOT TOUCH | 🔒 Sacred |
| 📄 **Paging** | DO NOT TOUCH | 🔒 Sacred |

---

## 🧠 Philosophy

### 🤔 Why Fork Limine?

We tried everything else:

| Attempt | Duration | Result |
|---------|----------|--------|
| 🔨 Custom bootloader from scratch | 1 week | 😭 Crying, almost quit |
| 🔧 "Reorganizing" Limine memory | 1 day | 💀 SMP disappeared |
| 🦀 Translating to Rust | 2 days | 💥 Failed miserably |

**🎯 Conclusion:** Use proven bootloader, strip bloat, move on.

### 📜 The Rules

1. 🚫 **Never touch memory map** - It works. Don't ask how.
2. 🚫 **Never touch SMP boot** - It works. Don't ask why.
3. 🚫 **Never touch paging** - It works. Just be grateful.
4. ✂️ **Remove unused code** - Less code = fewer bugs.
5. 📋 **Keep the boot menu** - Recovery mode saves lives.

---

## 🔐 Classical Cryptography

Null includes a classical cryptographic stack for secure boot. Post-quantum cryptography
(Dilithium/Kyber) has been removed based on MLE (Multiversal Law of Existence) theoretical
analysis demonstrating that quantum computing as theorized cannot exist.

### Crypto Primitives

| Component | Algorithm | Security Level | Key Sizes |
|-----------|-----------|----------------|-----------|
| 🔏 **Signatures** | Ed25519 | 128-bit | PK: 32B, SK: 64B, Sig: 64B |
| 🔑 **Key Exchange** | X25519 | 128-bit | PK: 32B, SK: 32B |
| 🔒 **Symmetric AEAD** | ChaCha20-Poly1305 | 256-bit | Key: 32B, Nonce: 12B, Tag: 16B |

### Performance Benefits (vs removed PQC)

| Metric | PQC (Removed) | Classical | Improvement |
|--------|---------------|-----------|-------------|
| Boot overhead | ~15-25ms | ~1-2ms | **10-20x faster** |
| Signature size | 3,309 bytes | 64 bytes | **52x smaller** |
| Public key | 1,952 bytes | 32 bytes | **61x smaller** |
| Code size | ~15KB | ~3KB | **5x smaller** |

### How It Works

**Signing** protects against kernel replacement (integrity):
```
Developer                           User's Machine
    │                                    │
    │  kernel.elf + secret key           │
    │      │                             │
    │  [luna_sign] ──────────────►  kernel.signed
    │                                    │
    │  BOOTX64.EFI ─────────────►   Bootloader verifies
    │  (has public key)                  signature before
    │                                    executing kernel
```

**Encryption** protects against kernel reading (confidentiality):
```
Developer                           User's Machine
    │                                    │
    │  kernel.signed + encryption key    │
    │      │                             │
    │  [luna_crypt] ─────────────►  kernel.enc
    │                                    │
    │  BOOTX64.EFI ─────────────►   Bootloader decrypts
    │  (has decryption key)              then verifies
```

### File Formats

**Signed kernel**: `[kernel data][Ed25519 signature (64 bytes)]`

**Encrypted kernel** (LUNAENC2 format):
```
┌─────────────────────────────────────────────────────────────────┐
│ Magic: "LUNAENC2" (8 bytes)                                     │
├─────────────────────────────────────────────────────────────────┤
│ Ephemeral X25519 Public Key (32 bytes)                          │
├─────────────────────────────────────────────────────────────────┤
│ ChaCha20 Nonce (12 bytes)                                       │
├─────────────────────────────────────────────────────────────────┤
│ Poly1305 Authentication Tag (16 bytes)                          │
├─────────────────────────────────────────────────────────────────┤
│ Encrypted Data (variable length)                                │
└─────────────────────────────────────────────────────────────────┘
Header overhead: 68 bytes (vs 1604 bytes with PQC)
```

### ⚠️ Important Security Notes

1. **Keys are per-developer** - Each developer generates their own keypair
2. **Bootloader + kernel are paired** - A bootloader only verifies kernels signed with its embedded public key
3. **Back up your secret keys** - Store `keys/*.sec` files securely; if lost, you cannot sign new kernels
4. **Never commit secret keys** - `.sec` files are gitignored by default
5. **Pre-built binaries are useless** - A downloaded bootloader has someone else's keys embedded

### Setup Script Options

```bash
./setup-crypto.sh                 # Full setup (recommended)
./setup-crypto.sh --tools-only    # Only build tools
./setup-crypto.sh --keys-only     # Only generate keys
./setup-crypto.sh --build-only    # Only rebuild bootloader
./setup-crypto.sh --clean         # Clean and start fresh
./setup-crypto.sh --no-encryption # Signing only (no encryption)
./setup-crypto.sh --help          # Show all options
```

---

## 🏗️ Building

### With Cryptography (Recommended)

```bash
./setup-crypto.sh
```

### Manual Build (No Crypto)

```bash
./bootstrap
./configure --enable-uefi-x86-64
make
```

See [INSTALL.md](INSTALL.md) for full build instructions.

---

## 🏷️ Versioning

Null follows the LunaOS unified versioning scheme:

- **Version**: `2025.12.100` (YYYY.MM.BBB)
- **Increment**: Bump BBB (100 → 101 → 102) per release
- **Reset**: Back to 100 each month

See [VERSIONING.md](VERSIONING.md) for details.

---

## 📜 License

Licensed under the **BSD 2-Clause License**

Based on [Limine](https://github.com/limine-bootloader/limine) by mintsuki and contributors.

See [COPYING](COPYING) for full details.

---

## 🙏 Acknowledgments

Null is a minimal fork of the legendary **[Limine](https://github.com/limine-bootloader/limine)** bootloader. We're deeply grateful to mintsuki and the Limine community for creating such a robust foundation.

**What we took:**
- 🔧 Proven boot process (memory, SMP, paging)
- 📦 Limine protocol implementation
- 📋 Boot menu system
- 📁 FAT32 and PXE support

**What we gave back:**
- 📚 A lesson in humility (don't rewrite bootloaders)

---

## 🌙 Part of LunaOS

Null is a core component of **[LunaOS](https://github.com/artst3in/LunaOS)** - the first operating system built on the **Coherence Paradigm**.

### The Coherence Paradigm

Null embodies the **First Law of Computational Physics** (LCP):

- 🎯 **Minimum viable code** - Only what's needed to boot LunaOS
- 🛡️ **Proven foundations** - Use Limine's battle-tested boot process
- 📉 **Zero entropy increase** - Remove code, don't add it

> *"The best bootloader is the one that gets out of the way."*

---

<div align="center">

### 🚀 Ready to boot?

```bash
./configure --enable-uefi-x86-64 && make
```

**[📖 Build Instructions](INSTALL.md)** • **[⚙️ Configuration](CONFIG.md)** • **[🐛 Issues](https://github.com/artst3in/null-bootloader/issues)**

---

**Made with 💜 by the LunaOS team**

**dε/dt ≤ 0**

</div>
