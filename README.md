# Null Bootloader

**Minimal Limine fork for LunaOS**

## What is this?

Null is a stripped-down version of [Limine](https://github.com/limine-bootloader/limine)
optimized for LunaOS.

## What we changed:

✅ Removed terminal rendering (5000 lines)
✅ Removed unused protocols (Multiboot, Linux boot)
✅ Added Luna-specific boot fields
✅ Optimized boot time (~50% faster)

## What we DIDN'T change:

❌ Boot process (memory, SMP, paging)
❌ We learned this the hard way
❌ Never touching that again

## Why fork?

We tried:
1. Custom bootloader (week of hell, crying, almost quit)
2. "Reorganizing" Limine memory (all day, SMP disappeared)
3. Translating to Rust (Claude Code failed miserably)

**Conclusion:** Use proven bootloader, strip bloat, move on.

## Credit

Based on [Limine](https://github.com/limine-bootloader/limine)
by mintsuki and contributors. Licensed under BSD 2-Clause.
