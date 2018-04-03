#ifndef EDHOC_CRYPTO_FUNCTIONS_H_
#define EDHOC_CRYPTO_FUNCTIONS_H_


#include "cbor.h"
#include "define.h"
#include "edhoc_messages.h"
#include "enum.h"
#include "io_functions.h"
#include <stdio.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/ocsp.h>
#include <openssl/pem.h>


cbor_item_t *cose_enc_i(cbor_item_t *aad_i, cbor_item_t *app_i, EVP_PKEY *pkey, int msg_type, unsigned char *party);
cbor_item_t *COSE_KDF_Context(unsigned char *mode, unsigned char *aad_i);
ASN1_INTEGER *create_nonce(int bits);
int decrypt_ccm(unsigned char *ciphertext, int ciphertext_len, unsigned char *aad,int aad_len, unsigned char *tag, unsigned char *key, unsigned char *iv, unsigned char *plaintext);
int encrypt_ccm(unsigned char *plaintext, int plaintext_len, unsigned char *aad, int aad_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext, unsigned char *tag);
unsigned char *gen_K_i(unsigned char *ext_aad, EVP_PKEY *session_pkey, int msg_type,unsigned char *mode, unsigned char *party);
unsigned char *gen_random_S_ID(size_t length);
unsigned char *gen_shared_secret(EVP_PKEY *pkey, size_t *skeylength, const char *filepath);
EVP_PKEY *gen_x25519();
const char *get_salt();
void *get_x(EVP_PKEY *pkey);
EVP_PKEY *get_x25519();
void handleErrors(void);
unsigned char *hash_aad(cbor_item_t *aad, int msg_type);
unsigned char *request_nonce(int nonce_sz);
size_t shared_secret_sz;


#endif // EDHOC_CRYPTO_FUNCTIONS_H_
