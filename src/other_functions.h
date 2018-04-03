#ifndef EDHOC_OTHER_FUNCTIONS_H_
#define EDHOC_OTHER_FUNCTIONS_H_


#include <b64/cdecode.h>
#include <b64/cencode.h>
#include "cbor.h"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <string.h>


bool CBOR_ITEM_T_init(cbor_item_t *item);
char *decode(const char *input, int input_sz, int *output_sz);
char* encode(const char* input, int buf_sz);
//void find_string(void *_ctx, cbor_data buffer, size_t len);
unsigned char *key_add_headers(unsigned char *key, size_t key_sz, const char *filepath);
unsigned char *strip_pkey(EVP_PKEY *pkey, int *pure_key_sz);


#endif // EDHOC_OTHER_FUNCTIONS_H_
