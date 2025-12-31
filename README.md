<div align="center">

# 🌙 Null
### **The Minimal Bootloader**

*A Stripped-Down Limine Fork for LunaOS*

[![Version](https://img.shields.io/badge/version-2025.12-blue.svg)]()
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
- 🔐 Post-quantum crypto (Dilithium/Kyber)

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
| 🔐 **PQCrypto** | Post-quantum signatures & encryption | ✅ Essential |
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

## 🔐 Post-Quantum Cryptography

Null includes a complete post-quantum cryptographic stack for secure boot:

### Crypto Primitives

| Component | Algorithm | Purpose | Size |
|-----------|-----------|---------|------|
| 🔏 **Signatures** | Dilithium-3 (ML-DSA) | Kernel verification | ~40 KB |
| 🔑 **Key Exchange** | Kyber-1024 (ML-KEM) | Encrypted kernel support | ~25 KB |
| 🔒 **Encryption** | ChaCha20-Poly1305 | Authenticated encryption | ~8 KB |
| #️⃣ **Hashing** | SHAKE256 (SHA-3 XOF) | Dilithium internals | ~10 KB |

**Total crypto code: ~83 KB**

### Security Levels

- **Dilithium-3**: NIST Security Level 3 (~128-bit post-quantum)
- **Kyber-1024**: NIST Security Level 5 (~256-bit post-quantum)
- **ChaCha20-Poly1305**: 256-bit symmetric + 128-bit authentication

### Configuration Options

```ini
# limine.conf

/LunaOS (Signed)
    protocol: limine
    kernel_path: boot():/luna_soul
    KERNEL_VERIFY=yes        # Require signature (default if keys present)

/LunaOS (Encrypted)
    protocol: limine
    kernel_path: boot():/luna_soul.enc
    KERNEL_VERIFY=yes
    KERNEL_ENCRYPTED=yes     # Decrypt before verify
```

### Key Management

Keys are embedded at build time:
- **Public key** (Dilithium): Compiled into bootloader for verification
- **Secret key** (Kyber): Compiled into bootloader for decryption

Use the `limine` utility to embed keys:
```bash
limine keygen --output keys/       # Generate keypair
limine sign kernel keys/luna.key   # Sign kernel
limine embed-keys BOOTX64.EFI keys/luna.pub keys/kyber.key
```

### Boot Flow

```
1. Load kernel from disk
2. Check KERNEL_ENCRYPTED → Decrypt with Kyber+ChaCha20
3. Check KERNEL_VERIFY → Verify Dilithium signature
4. Execute verified kernel
```

### File Formats

**Signed kernel**: `[kernel data][Dilithium signature (3293 bytes)]`

**Encrypted kernel**:
```
[Magic "LUNAENC1" (8 bytes)]
[Kyber ciphertext (1568 bytes)]
[Nonce (12 bytes)]
[Auth tag (16 bytes)]
[Encrypted kernel+signature]
```

---

## 🏗️ Building

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
