#ifndef C_API
#define C_API

#include <stdint.h>

// MARK: Cryptographic Constants

const int ENCRYPTED_SECRET_KEY_LEN;
const int PUBLIC_KEY_LEN;
const int SECRET_KEY_LEN;
const int SPECK_KEY_LEN;
const int SHA512_DIGEST_LEN;

// MARK: Error Codes

const int SUCCESS;
const int EMAIL_TAKEN;
const int CONNECTION_ERROR;
const int DATA_ERROR;
const int USER_DOES_NOT_EXIST;
const int EMAIL_DOES_NOT_EXIST;

int capi_hash_bytes(const uint8_t *pt, int pt_len, uint8_t *digest);
int capi_hash_str(const char *pt, uint8_t *digest);
uint8_t *capi_enc(const uint8_t *pt, int pt_len, const uint8_t *key, int *ct_len);
uint8_t *capi_dec(const uint8_t *ct, int ct_len, const uint8_t *key, int *pt_len);

// MARK: Asynchronicity 

void *capi_create_runtime();
int capi_test_async(void *rt, void (*callback)(int));
void capi_destroy_runtime(void *rt);

// MARK: Users

void capi_create_user(const void *rt, const char* email_ptr, void (*callback)(int, u_int64_t, uint8_t *));
void capi_download_user(
	const void *rt, 
	uint64_t user_id, 
	void (*callback)(
		int,
		uint64_t,
		const char *,
		const uint8_t *,
		const uint8_t *,
		const uint8_t *
	)
);
void capi_download_user_email(
	const void *rt, 
	const char* email, 
	void (*callback)(
		int,
		uint64_t,
		const char *,
		const uint8_t *,
		const uint8_t *,
		const uint8_t *
	)
);

#endif