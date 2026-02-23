#if defined (__x86_64__) || defined (__i386__)

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <sys/iommu.h>
#include <sys/cpu.h>
#include <lib/acpi.h>
#include <lib/libc.h>

// Intel VT-d registers
#define VTD_GCMD_REG  0x18
#define VTD_GSTS_REG  0x1C

// GSTS/GCMD bit positions
#define VTD_GSTS_TES  (1u << 31)  // Translation Enable Status
#define VTD_GSTS_QIES (1u << 26)  // Queued Invalidation Enable Status
#define VTD_GSTS_IRES (1u << 25)  // Interrupt Remapping Enable Status

// Mask to clear one-shot command bits when reading GSTS for use as GCMD base.
// One-shot bits auto-clear after hardware processes them and must not be
// carried over from GSTS into GCMD writes:
//   Bit 30: SRTP (Set Root Table Pointer)
//   Bit 29: SFL  (Set Fault Log)
//   Bit 27: WBF  (Write Buffer Flush)
//   Bit 24: SIRTP (Set Interrupt Remap Table Pointer)
// All other bits (TE, EAFL, QIE, IRE, CFI) are persistent toggles.
#define VTD_GCMD_ONESHOT_MASK 0x96FFFFFF

static void vtd_disable_unit(uintptr_t reg_base) {
    uint32_t sts = mmind(reg_base + VTD_GSTS_REG);

    // Disable DMA translation first (most urgent: prevents stale lookups)
    if (sts & VTD_GSTS_TES) {
        uint32_t gcmd = (sts & VTD_GCMD_ONESHOT_MASK) & ~VTD_GSTS_TES;
        mmoutd(reg_base + VTD_GCMD_REG, gcmd);

        while ((sts = mmind(reg_base + VTD_GSTS_REG)) & VTD_GSTS_TES) {
            asm volatile ("pause");
        }
    }

    // Disable interrupt remapping (depends on QIE, so disable before QIE)
    if (sts & VTD_GSTS_IRES) {
        uint32_t gcmd = (sts & VTD_GCMD_ONESHOT_MASK) & ~VTD_GSTS_IRES;
        mmoutd(reg_base + VTD_GCMD_REG, gcmd);

        while ((sts = mmind(reg_base + VTD_GSTS_REG)) & VTD_GSTS_IRES) {
            asm volatile ("pause");
        }
    }

    // Disable queued invalidation last (was prerequisite for IRE)
    if (sts & VTD_GSTS_QIES) {
        uint32_t gcmd = (sts & VTD_GCMD_ONESHOT_MASK) & ~VTD_GSTS_QIES;
        mmoutd(reg_base + VTD_GCMD_REG, gcmd);

        while ((sts = mmind(reg_base + VTD_GSTS_REG)) & VTD_GSTS_QIES) {
            asm volatile ("pause");
        }
    }
}

static void vtd_disable_all(void) {
    struct sdt *dmar = acpi_get_table("DMAR", 0);
    if (dmar == NULL) {
        return;
    }

    // DMAR header is 48 bytes: 36 (SDT) + 1 (width) + 1 (flags) + 10 (reserved)
    uint8_t *ptr = (uint8_t *)dmar + 48;
    uint8_t *end = (uint8_t *)dmar + dmar->length;

    while (ptr + 4 <= end) {
        uint16_t type   = *(uint16_t *)(ptr + 0);
        uint16_t length = *(uint16_t *)(ptr + 2);

        if (length < 4 || ptr + length > end) {
            break;
        }

        // Type 0 = DRHD (DMA Remapping Hardware Unit Definition)
        if (type == 0 && length >= 16) {
            uint64_t reg_base;
            memcpy(&reg_base, ptr + 8, sizeof(reg_base));
            vtd_disable_unit((uintptr_t)reg_base);
        }

        ptr += length;
    }
}

// AMD IOMMU control register (64-bit at offset 0x18)
#define AMDVI_CONTROL_REG 0x18

static void amdvi_disable_unit(uintptr_t mmio_base) {
    // Read low 32 bits of the 64-bit control register
    uint32_t ctrl_lo = mmind(mmio_base + AMDVI_CONTROL_REG);

    if (!(ctrl_lo & (1u << 0))) {
        return; // IOMMU not enabled
    }

    // Clear IommuEn (bit 0) — the master enable for all IOMMU functionality.
    // Takes effect immediately, no polling needed (unlike Intel VT-d).
    ctrl_lo &= ~(1u << 0);
    mmoutd(mmio_base + AMDVI_CONTROL_REG, ctrl_lo);
}

static void amdvi_disable_all(void) {
    struct sdt *ivrs = acpi_get_table("IVRS", 0);
    if (ivrs == NULL) {
        return;
    }

    // IVRS header is 48 bytes: 36 (SDT) + 4 (IVinfo) + 8 (reserved)
    uint8_t *ptr = (uint8_t *)ivrs + 48;
    uint8_t *end = (uint8_t *)ivrs + ivrs->length;

    while (ptr + 4 <= end) {
        uint8_t  type   = *(uint8_t *)(ptr + 0);
        uint16_t length = *(uint16_t *)(ptr + 2);

        if (length < 4 || ptr + length > end) {
            break;
        }

        // IVHD types: 0x10 (basic), 0x11 (extended), 0x40 (extended, newer)
        if ((type == 0x10 || type == 0x11 || type == 0x40) && length >= 16) {
            uint64_t mmio_base;
            memcpy(&mmio_base, ptr + 8, sizeof(mmio_base));
            amdvi_disable_unit((uintptr_t)mmio_base);
        }

        ptr += length;
    }
}

void iommu_disable_all(void) {
    vtd_disable_all();
    amdvi_disable_all();
}

#endif
