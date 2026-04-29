#ifndef LIB__TPM_H__
#define LIB__TPM_H__

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

// PCR allocation, matching systemd-boot conventions:
//   PCR 8: kernel command line and other authoritative strings
//   PCR 9: kernel image, initrd, devicetree, and other binary blobs
#define TPM_PCR_BOOT_AUTH       8
#define TPM_PCR_LOADED_IMAGES   9

// TCG PC Client Platform Firmware Profile event types
#define TPM_EV_IPL              0x0000000d

#if defined (UEFI)

void tpm_init(void);
void tpm_measure(uint32_t pcr, uint32_t event_type,
                 const void *data, size_t data_size,
                 const char *description);

#endif

#endif
