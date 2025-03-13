# 3rd Party Software Acknowledgments

The Limine project depends on several other projects which are pulled in by the
./bootstrap script, or, in the case of release tarballs, are shipped alongside
the core Limine code in the tarballs themselves, similar to ./bootstrap having
been already run.

These additional projects are NOT covered by the License as present inside the
COPYING file, but are instead licensed as described by each individual
project's documentation present in the project's dedicated subdirectory or
license header(s).

A non-binding, informal summary of all projects Limine depends on, and the
licenses used by said projects, in SPDX format, is as follows:

- [cc-runtime](https://github.com/osdev0/cc-runtime)
(Apache-2.0 WITH LLVM-exception) is used to provide runtime libgcc-like
routines.

- [0BSD Freestanding C Headers](https://github.com/osdev0/freestnd-c-hdrs-0bsd)
(0BSD) provide GCC and Clang compatible freestanding C headers.

- [Nyu-EFI](https://github.com/osdev0/nyu-efi) (multiple licenses, see list
below) provides headers and build-time support for UEFI.
    - BSD-2-Clause
    - BSD-2-Clause-Patent
    - BSD-3-Clause
    - LicenseRef-scancode-bsd-no-disclaimer-unmodified
    - MIT

    For more information about the
    LicenseRef-scancode-bsd-no-disclaimer-unmodified license used by parts of
    Nyu-EFI, see
    https://scancode-licensedb.aboutcode.org/bsd-no-disclaimer-unmodified.html
    and the LicenseRef file
    [here](LICENSES/LicenseRef-scancode-bsd-no-disclaimer-unmodified.txt).

- [tinf](https://github.com/jibsen/tinf) (Zlib) is used in early x86 BIOS
stages for GZIP decompression of stage2.

- [Flanterm](https://github.com/mintsuki/flanterm) (BSD-2-Clause) is used for
text related screen drawing.

- [stb_image](https://github.com/nothings/stb/blob/master/stb_image.h) (MIT) is
used for wallpaper image loading.

- [libfdt](https://git.kernel.org/pub/scm/utils/dtc/dtc.git) (BSD-2-Clause) is
used for manipulating Flat Device Trees.

Note that some of these projects, or parts of them, are provided under
dual-licensing, in which case, in the above list, the only license mentioned is
the one chosen by the Limine developers. Refer to each individual project's
documentation for details.
