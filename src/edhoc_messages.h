#ifndef EDHOC_EDHOC_MESSAGES_H_
#define EDHOC_EDHOC_MESSAGES_H_


#include "cbor.h"
#include "crypto_functions.h"
#include "define.h"
#include "enum.h"
#include "io_functions.h"
#include <openssl/evp.h>
#include "other_functions.h"
#include "x509.h"


unsigned char *gen_msg_1_sym(unsigned char *app_1, size_t app_1_sz, EVP_PKEY *pkey, const char *filepath);
unsigned char *gen_msg_2_sym(unsigned char *app_2, size_t app_2_sz, EVP_PKEY *pkey, const char *filepath, unsigned char *msg_1, size_t msg_1_len);
unsigned char *gen_msg_3_sym(unsigned char *app_3, size_t app_3_sz, EVP_PKEY *pkey, const char *filepath, unsigned char *msg_1, unsigned char *msg_2, size_t msg_1_len, size_t msg_2_len);
unsigned char *gen_msg_4_sym(PKCS7 *cert, size_t cert_sz, EVP_PKEY *pkey, const char *filepath, unsigned char *msg_1, unsigned char *msg_2, unsigned char *msg_3, size_t msg_1_len, size_t msg_2_len, size_t msg_3_len);
unsigned char *cbor_array(int msg_type, unsigned char app_i[], size_t app_i_sz, EVP_PKEY *pkey);
int get_msg_num(int msg_type);
unsigned char *message_1;
unsigned char *message_2;
unsigned char *message_3;
unsigned char *message_4;
size_t message_1_len;
size_t message_2_len;
size_t message_3_len;
size_t message_4_len;
void *parse_edhoc_sym_msg_1(cbor_item_t *MSG);
void *parse_edhoc_sym_msg_2(cbor_item_t *MSG);
PKCS7 *parse_edhoc_sym_msg_3(cbor_item_t *MSG);
void *parse_edhoc_sym_msg_4(cbor_item_t *MSG);


#endif // EDHOC_EDHOC_MESSAGES_H_
