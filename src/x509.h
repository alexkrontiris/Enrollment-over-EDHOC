#ifndef EDHOC_X509_FUNCTIONS_H_
#define EDHOC_X509_FUNCTIONS_H_


#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/pkcs7.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>


X509_REQ *d2i(unsigned char *in, int len);
X509_REQ *gen_csr();
PKCS7 *sign_CSR(X509_REQ *x509_req);


#endif // EDHOC_X509_FUNCTIONS_H_
