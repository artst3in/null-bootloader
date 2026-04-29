#if defined (UEFI)

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <efi.h>
#include <efi/protocol/efitcg2.h>
#include <lib/tpm.h>
#include <lib/misc.h>
#include <lib/print.h>
#include <lib/libc.h>
#include <mm/pmm.h>

static EFI_TCG2_PROTOCOL *tcg2 = NULL;

void tpm_init(void) {
    EFI_GUID tcg2_guid = EFI_TCG2_PROTOCOL_GUID;
    EFI_TCG2_PROTOCOL *proto = NULL;
    EFI_STATUS status = gBS->LocateProtocol(&tcg2_guid, NULL, (void **)&proto);
    if (status != EFI_SUCCESS || proto == NULL) {
        return;
    }

    EFI_TCG2_BOOT_SERVICE_CAPABILITY cap;
    memset(&cap, 0, sizeof(cap));
    cap.Size = sizeof(cap);
    status = proto->GetCapability(proto, &cap);
    if (status != EFI_SUCCESS || !cap.TPMPresentFlag) {
        return;
    }

    tcg2 = proto;
    printv("tpm: TCG2 protocol located, TPM present (active PCR banks: %x)\n",
           (uint32_t)cap.ActivePcrBanks);
}

void tpm_measure(uint32_t pcr, uint32_t event_type,
                 const void *data, size_t data_size,
                 const char *description) {
    if (tcg2 == NULL || data == NULL) {
        return;
    }

    size_t desc_len = description != NULL ? strlen(description) : 0;
    size_t event_size = offsetof(EFI_TCG2_EVENT, Event) + desc_len;

    EFI_TCG2_EVENT *event = ext_mem_alloc(event_size);
    event->Size = (UINT32)event_size;
    event->Header.HeaderSize = sizeof(EFI_TCG2_EVENT_HEADER);
    event->Header.HeaderVersion = 1;
    event->Header.PCRIndex = pcr;
    event->Header.EventType = event_type;
    if (desc_len > 0) {
        memcpy(event->Event, description, desc_len);
    }

    EFI_STATUS status = tcg2->HashLogExtendEvent(
        tcg2, 0,
        (EFI_PHYSICAL_ADDRESS)(uintptr_t)data, (UINT64)data_size,
        event);
    if (status != EFI_SUCCESS) {
        printv("tpm: HashLogExtendEvent for PCR %u failed: %X\n",
               pcr, (uint64_t)status);
    }

    pmm_free(event, event_size);
}

#endif
