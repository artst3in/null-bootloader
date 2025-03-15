#if defined (UEFI)

#include <config.h>
#include <efi.h>
#include <lib/bli.h>
#include <lib/guid.h>
#include <lib/misc.h>

#define LIMINE_BRAND L"Limine " LIMINE_VERSION

static EFI_GUID bli_vendor_guid = { 0x4a67b082, 0x0a4c, 0x41cf, { 0xb6, 0xc7, 0x44, 0x0b, 0x29, 0xbb, 0x8c, 0x4f } };

void init_bli(void) {
    gRT->SetVariable(L"LoaderInfo",
            &bli_vendor_guid,
            EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS,
            sizeof(LIMINE_BRAND),
            LIMINE_BRAND);

    char part_uuid_str[37];
    guid_to_string(&boot_volume->part_guid, part_uuid_str);

    // Convert part_uuid_str to a wide-char string
    wchar_t part_uuid[37];
    for (size_t i = 0; i < 37; i++) {
        part_uuid[i] = (wchar_t) part_uuid_str[i];
    }

    gRT->SetVariable(L"LoaderDevicePartUUID",
            &bli_vendor_guid,
            EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS,
            sizeof(part_uuid),
            part_uuid);
}

#endif
