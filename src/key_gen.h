#ifndef EDHOC_KEY_GEN_FUNCTIONS_H_
#define EDHOC_KEY_GEN_FUNCTIONS_H_


#include <openssl/bio.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <string.h>


EVP_PKEY *gen_ECDSA_p256_key_pair(char *path);


#endif // EDHOC_KEY_GEN_FUNCTIONS_H_
