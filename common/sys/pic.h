#ifndef SYS__PIC_H__
#define SYS__PIC_H__

#include <stdint.h>
#include <stdbool.h>

void pic_eoi(int irq);
void pic_flush(uint8_t master_base, uint8_t slave_base);
void pic_set_mask(int line, bool status);
void pic_mask_all(void);

#endif
