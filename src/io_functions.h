#ifndef EDHOC_IO_FUNCTIONS_H_
#define EDHOC_IO_FUNCTIONS_H_


#include "cbor.h"
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <stdio.h>
#include <stdlib.h>


unsigned char *import_msg(const char *filepath, size_t *len);
cbor_item_t *print_and_get_cbor_array(const char *filepath);
void *print_bytes(unsigned char *buffer, size_t length);
void *print_cbor_array_to_stdout(unsigned char *buffer, size_t length);
void *print_cbor_bytestring_to_stdout(unsigned char *buffer, size_t length);
void *print_cbor_bytestring_to_stdout_hex(unsigned char *buffer, size_t length);
int print_pkey_hr(EVP_PKEY *pkey);
void *print_title();
void *write_cbor_array_to_file_RAW(unsigned char *buffer, size_t length, int msg_type, const char *filepath);
void *write_cbor_array_to_file_HEX(unsigned char *buffer, size_t length, int msg_type, const char *filepath);
void *write_X509_to_file(X509_REQ *x509);

#endif // EDHOC_IO_FUNCTIONS_H_
