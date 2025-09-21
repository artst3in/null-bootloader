#ifndef SYS__IDT_H__
#define SYS__IDT_H__

#include <stdint.h>
#include <stddef.h>

#if defined (__i386__)

struct idtr {
    uint16_t limit;
    uint32_t ptr;
} __attribute__((packed));

struct idt_entry {
    uint16_t offset_lo;
    uint16_t selector;
    uint8_t  unused;
    uint8_t  type_attr;
    uint16_t offset_hi;
} __attribute__((packed));

#elif defined (__x86_64__)

struct idtr {
    uint16_t limit;
    uint64_t ptr;
} __attribute__((packed));

struct idt_entry {
    uint16_t offset_lo;
    uint16_t selector;
    uint8_t  ist;
    uint8_t  type_attr;
    uint16_t offset_mid;
    uint32_t offset_hi;
    uint32_t reserved;
} __attribute__((packed));

#endif

enum {
    IRQ_NO_FLUSH,
    IRQ_PIC_ONLY_FLUSH,
    IRQ_PIC_APIC_FLUSH
};

#if defined (UEFI)
#  define IDT_ENTRY_COUNT 256
#elif defined (BIOS)
#  define IDT_ENTRY_COUNT 32
#endif

extern struct idt_entry idt[IDT_ENTRY_COUNT];
extern int irq_flush_type;

void idt_init(void);
void idt_register_isr(size_t vec, void *handler, uint8_t type);
void flush_irqs(void);

#endif
