#include <stdint.h>
#include <stdbool.h>
#include <sys/cpu.h>
#if defined(UEFI)
#include <efi.h>
#include <lib/misc.h>
#endif

uint64_t tsc_freq = 0;

void calibrate_tsc(void) {
    tsc_freq = tsc_freq_arch();
    if (tsc_freq != 0) {
        return;
    }

#if defined(UEFI)
    uint64_t tsc_start = rdtsc();
    gBS->Stall(1000);
    uint64_t tsc_end = rdtsc();

    if (tsc_end > tsc_start) {
        tsc_freq = (tsc_end - tsc_start) * 1000ULL;
    }
#endif
}
