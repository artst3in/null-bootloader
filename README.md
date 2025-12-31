<div align="center">

# 🌙 Null
### **The Minimal Bootloader**

*A Stripped-Down Limine Fork for LunaOS*

[![Version](https://img.shields.io/badge/version-2025.12-blue.svg)]()
[![License](https://img.shields.io/badge/license-BSD%202--Clause-green.svg)](COPYING)
[![Platform](https://img.shields.io/badge/platform-x86__64%20%7C%20UEFI%20%7C%20BIOS-orange.svg)]()
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
- 🔐 Config verification (BLAKE2B)

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
| 🔐 **BLAKE2B** | Config file verification | 💡 Useful |
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

## 🔮 Future Work

Tracked in source code as TODO comments:

| Feature | Location | Status |
|---------|----------|--------|
| ⚡ Replace BLAKE2B with BLAKE3 | `crypt/blake2b.c` | 📅 Planned |
| 🔐 Add Kyber post-quantum crypto | `crypt/blake2b.c` | 📅 Planned |

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
