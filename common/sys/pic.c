#if defined (__x86_64__) || defined (__i386__)

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/pic.h>
#include <sys/cpu.h>
#include <lib/misc.h>

void pic_eoi(int irq) {
    if (irq >= 8) {
        outb(0xa0, 0x20);
    }

    outb(0x20, 0x20);
}

// Flush all pending IRQs by reinitialising the PICs, preserving the IMR
void pic_flush(uint8_t master_base, uint8_t slave_base) {
    uint8_t master_imr = inb(0x21);
    uint8_t slave_imr = inb(0xa1);

    outb(0xa1, 0xff);
    outb(0x21, 0xff);

    outb(0x20, 0x11);
    outb(0x21, master_base);
    outb(0x21, 0x04);
    outb(0x21, 0x01);

    outb(0xa0, 0x11);
    outb(0xa1, slave_base);
    outb(0xa1, 0x02);
    outb(0xa1, 0x01);

    outb(0xa1, slave_imr);
    outb(0x21, master_imr);
}

void pic_set_mask(int line, bool status) {
    uint16_t port;
    uint8_t value;

    if (line < 8) {
        port = 0x21;
    } else {
        port = 0xa1;
        line -= 8;
    }

    if (!status)
        value = inb(port) & ~((uint8_t)1 << line);
    else
        value = inb(port) | ((uint8_t)1 << line);

    outb(port, value);
}

void pic_mask_all(void) {
    outb(0xa1, 0xff);
    outb(0x21, 0xff);
}

#endif
