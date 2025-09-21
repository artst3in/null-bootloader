#if defined (__x86_64__) || defined (__i386__)

#include <stdint.h>
#include <stddef.h>
#include <sys/idt.h>
#include <sys/cpu.h>
#include <sys/pic.h>
#include <sys/lapic.h>
#include <mm/pmm.h>
#include <lib/misc.h>

int irq_flush_type = IRQ_NO_FLUSH;

void flush_irqs(void) {
    switch (irq_flush_type) {
        case IRQ_PIC_ONLY_FLUSH:
            pic_flush();
            // FALLTHRU
        case IRQ_NO_FLUSH:
            return;
        case IRQ_PIC_APIC_FLUSH:
            break;
        default:
            panic(false, "Invalid IRQ flush type");
    }

    struct idtr old_idt;
    asm volatile ("sidt %0" : "=m"(old_idt) :: "memory");

    struct idtr new_idt = {
        IDT_ENTRY_COUNT * sizeof(struct idt_entry) - 1,
        (uintptr_t)idt
    };
    asm volatile ("lidt %0" :: "m"(new_idt) : "memory");

    // Flush the legacy PIC so we know the remaining ints come from the LAPIC
    pic_flush();

    asm volatile ("sti" ::: "memory");

    // Delay a while to make sure we catch ALL pending IRQs
    delay(10000000);

    asm volatile ("cli" ::: "memory");

    asm volatile ("lidt %0" :: "m"(old_idt) : "memory");
}

#endif
