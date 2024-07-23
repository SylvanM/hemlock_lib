#ifndef C_API
#define C_API

#include <stdint.h>

int hash_bytes(const uint8_t *pt, int pt_len, uint8_t *digest);
int hash_str(const char *pt, uint8_t *digest);

#endif