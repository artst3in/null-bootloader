#include <stdint.h>
#include <stddef.h>
#include <stdnoreturn.h>
#include <tinf.h>

noreturn void entry(uint8_t *compressed_stage2, size_t stage2_size, uint8_t boot_drive, int pxe) {
    // The decompressor should decompress compressed_stage2 to address 0xf000.
    // The output buffer extends up to 0x70000 where the decompressor itself lives.
    uint8_t *dest = (uint8_t *)0xf000;
    unsigned int destLen = 0x70000 - 0xf000;

    if (tinf_gzip_uncompress(dest, &destLen, compressed_stage2, stage2_size) != 0) {
        const char *msg = "Limine decomp error";
        volatile uint16_t *vga = (volatile uint16_t *)0xB8000;
        for (size_t i = 0; msg[i]; i++) {
            vga[i] = 0x4F00 | (uint8_t)msg[i];
        }
        for (;;) {
            asm volatile ("cli; hlt");
        }
    }

    asm volatile (
        "movl $0xf000, %%esp\n\t"
        "xorl %%ebp, %%ebp\n\t"
        "pushl %1\n\t"
        "pushl %0\n\t"
        "pushl $0\n\t"
        "pushl $0xf000\n\t"
        "ret\n\t"
        :
        : "r" ((uint32_t)boot_drive), "r" (pxe)
        : "memory"
    );

    __builtin_unreachable();
}
