#ifndef CRYPT__BLAKE2B_H__
#define CRYPT__BLAKE2B_H__

#include <stddef.h>

#define BLAKE2B_OUT_BYTES 64

void blake2b(void *out, const void *in, size_t in_len);

struct file_handle;
bool blake2b_verify_file(struct file_handle *fd, const uint8_t expected[BLAKE2B_OUT_BYTES]);

#endif
