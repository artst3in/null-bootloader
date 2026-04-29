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

// TCG event log entry layouts (TCG PC Client Platform Firmware Profile).
struct tpm_pcr_event_v1_2 {
    uint32_t pcr_idx;
    uint32_t event_type;
    uint8_t  digest[20];
    uint32_t event_size;
    uint8_t  event[];
} __attribute__((packed));

struct tpm_specid_event_alg {
    uint16_t alg_id;
    uint16_t digest_size;
} __attribute__((packed));

struct tpm_specid_event_head {
    uint8_t  signature[16];
    uint32_t platform_class;
    uint8_t  spec_version_minor;
    uint8_t  spec_version_major;
    uint8_t  spec_errata;
    uint8_t  uintn_size;
    uint32_t num_algs;
    struct tpm_specid_event_alg digest_sizes[];
} __attribute__((packed));

// Followed by `count` digests (uint16_t alg_id + variable-length digest),
// then a uint32_t event_size and event_size bytes of event data.
struct tpm_pcr_event2_head {
    uint32_t pcr_idx;
    uint32_t event_type;
    uint32_t count;
} __attribute__((packed));

#define TCG_EV_NO_ACTION 3
#define TCG_SPECID_SIG   "Spec ID Event03"

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

uint32_t tpm_calc_event_size(const void *event_p, const void *header_p) {
    const struct tpm_pcr_event2_head *event = event_p;
    const struct tpm_pcr_event_v1_2 *event_header = header_p;

    static const uint8_t zero_digest[20] = {0};

    if (event_header->pcr_idx != 0
     || event_header->event_type != TCG_EV_NO_ACTION
     || memcmp(event_header->digest, zero_digest, sizeof(zero_digest)) != 0) {
        return 0;
    }

    const struct tpm_specid_event_head *efispecid =
        (const struct tpm_specid_event_head *)event_header->event;

    if (memcmp(efispecid->signature, TCG_SPECID_SIG, sizeof(TCG_SPECID_SIG)) != 0
     || efispecid->num_algs == 0
     || event->count != efispecid->num_algs) {
        return 0;
    }

    const uint8_t *marker_start = (const uint8_t *)event_p;
    const uint8_t *marker = marker_start
                          + sizeof(event->pcr_idx)
                          + sizeof(event->event_type)
                          + sizeof(event->count);

    for (uint32_t i = 0; i < event->count; i++) {
        uint16_t halg;
        memcpy(&halg, marker, sizeof(halg));
        marker += sizeof(halg);

        uint32_t j;
        for (j = 0; j < efispecid->num_algs; j++) {
            if (halg == efispecid->digest_sizes[j].alg_id) {
                marker += efispecid->digest_sizes[j].digest_size;
                break;
            }
        }
        if (j == efispecid->num_algs) {
            return 0;
        }
    }

    uint32_t trailing_event_size;
    memcpy(&trailing_event_size, marker, sizeof(trailing_event_size));
    marker += sizeof(trailing_event_size) + trailing_event_size;

    if (event->event_type == 0 && trailing_event_size == 0) {
        return 0;
    }

    return (uint32_t)(marker - marker_start);
}

static void *captured_log = NULL;
static size_t captured_log_size = 0;
static uint32_t captured_log_format = 0;
static bool capture_attempted = false;

// Pull the firmware event log via GetEventLog and copy the raw event bytes
// into a bootloader-reclaimable buffer. Idempotent. Returns true if the
// captured state is valid.
static bool tpm_capture_event_log(void) {
    if (capture_attempted) {
        return captured_log != NULL;
    }
    capture_attempted = true;

    if (tcg2 == NULL) {
        return false;
    }

    EFI_PHYSICAL_ADDRESS log_location = 0, log_last_entry = 0;
    BOOLEAN truncated = FALSE;

    uint32_t log_format = EFI_TCG2_EVENT_LOG_FORMAT_TCG_2;
    EFI_STATUS status = tcg2->GetEventLog(tcg2, log_format,
        &log_location, &log_last_entry, &truncated);
    if (status != EFI_SUCCESS || log_location == 0) {
        log_format = EFI_TCG2_EVENT_LOG_FORMAT_TCG_1_2;
        status = tcg2->GetEventLog(tcg2, log_format,
            &log_location, &log_last_entry, &truncated);
        if (status != EFI_SUCCESS || log_location == 0) {
            return false;
        }
    }

    uint32_t log_size = 0;
    if (log_last_entry != 0) {
        uint32_t last_entry_size = 0;
        if (log_format > EFI_TCG2_EVENT_LOG_FORMAT_TCG_1_2) {
            last_entry_size = tpm_calc_event_size(
                (void *)(uintptr_t)log_last_entry,
                (void *)(uintptr_t)log_location);
        } else {
            const struct tpm_pcr_event_v1_2 *e =
                (const struct tpm_pcr_event_v1_2 *)(uintptr_t)log_last_entry;
            last_entry_size = sizeof(struct tpm_pcr_event_v1_2) + e->event_size;
        }
        log_size = (uint32_t)(log_last_entry - log_location) + last_entry_size;
    }

    void *log_bytes = NULL;
    if (log_size > 0) {
        log_bytes = ext_mem_alloc(log_size);
        memcpy(log_bytes, (void *)(uintptr_t)log_location, log_size);
    }

    captured_log = log_bytes;
    captured_log_size = log_size;
    captured_log_format = log_format;
    return true;
}

bool tpm_get_event_log(uint32_t *format, void **address, size_t *size) {
    if (!tpm_capture_event_log()) {
        return false;
    }

    *format = captured_log_format;
    *address = captured_log;
    *size = captured_log_size;
    return true;
}

void tpm_release_event_log(void) {
    if (captured_log != NULL) {
        pmm_free(captured_log, captured_log_size);
        captured_log = NULL;
    }
}

#endif
