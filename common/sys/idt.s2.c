#if defined (__x86_64__) || defined (__i386__)

#include <stddef.h>
#include <stdint.h>
#include <sys/idt.h>
#include <lib/misc.h>
#include <mm/pmm.h>

struct idt_entry idt[IDT_ENTRY_COUNT];

void idt_register_isr(size_t vec, void *handler, uint8_t type) {
    uint32_t p = (uintptr_t)handler;

    idt[vec].offset_lo = (uint16_t)p;
    idt[vec].type_attr = type;
#if defined (__i386__)
    idt[vec].selector = 0x18;
    idt[vec].offset_hi = (uint16_t)((uintptr_t)p >> 16);
#elif defined (__x86_64__)
    idt[vec].selector = 0x28;
    idt[vec].offset_mid = (uint16_t)((uintptr_t)p >> 16);
    idt[vec].offset_hi = (uint32_t)((uintptr_t)p >> 32);
#endif
}

#if defined (UEFI)
void dummy_isr(void);
#elif defined (BIOS)
extern void *exceptions[];
#endif

void idt_init(void) {
#if defined (UEFI)
    for (size_t i = 0; i < IDT_ENTRY_COUNT; i++) {
        idt_register_isr(i, dummy_isr, 0x8e);
    }
#elif defined (BIOS)
    for (size_t i = 0; i < IDT_ENTRY_COUNT; i++) {
        idt_register_isr(i, exceptions[i], 0x8e);
    }

    struct idtr idtr = {
        IDT_ENTRY_COUNT * sizeof(struct idt_entry) - 1,
        (uintptr_t)idt
    };
    asm volatile ("lidt %0" :: "m"(idtr) : "memory");
#endif
}

#endif
