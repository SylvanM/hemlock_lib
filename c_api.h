#ifndef C_API
#define C_API

#include <stdint.h>

int capi_hash_bytes(const uint8_t *pt, int pt_len, uint8_t *digest);
int capi_hash_str(const char *pt, uint8_t *digest);

uint8_t *capi_enc(const uint8_t *pt, int pt_len, const uint8_t *key, int *ct_len);
uint8_t *capi_dec(const uint8_t *ct, int ct_len, const uint8_t *key, int *pt_len);

#endif