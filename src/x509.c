#include "key_gen.h"
#include "io_functions.h"
#include "x509.h"


X509_REQ *d2i(unsigned char *in, int len)
{
	X509_REQ *x509;
	unsigned char *buf;
	//unsigned char *p;
	in = buf;
	
	x509 = d2i_X509_REQ(NULL, in, len);

	return x509;
}


X509_REQ *gen_csr()
{

	//EC KEY TEST
	//EVP_PKEY *test;
	//test = EVP_PKEY_new();
	//test = gen_ECDSA_p256_key_pair();

	EVP_PKEY *pkey;
	pkey = EVP_PKEY_new();

	RSA *rsa = NULL;
	BIGNUM *bne = NULL;
	BIO *pub = NULL;
	BIO *pri = NULL;
	unsigned long e = RSA_F4;

	bne = BN_new();
	BN_set_word(bne, e);
	rsa = RSA_new();
	//rsa = RSA_generate_key(2048, RSA_F4, NULL, NULL);
	RSA_generate_key_ex(rsa, 2048, bne, NULL);

	//EVP_PKEY_assign_RSA(pkey, rsa);
	pkey = gen_ECDSA_p256_key_pair("./ecdsa-client-keys/");

	//pub = BIO_new_file("./rsa-client-keys/rsa_pubkey.pem","w+");
	//PEM_write_bio_RSAPublicKey(pub, rsa);
	//PEM_write_bio_EC_PUBKEY(pub, pkey);

	//pri = BIO_new_file("./rsa-client-keys/rsa_privkey.pem","w+");
	//PEM_write_bio_RSAPrivateKey(pri, rsa, NULL, NULL, 0, NULL, NULL);

	//BIO *prfile = BIO_new_file("./rsa-client-keys/rsa_privkey.pem","w");
	//BIO *pufile = BIO_new_file("./rsa-client-keys/rsa_pubkey.pem","w");
	//fopen("./rsa-client-keys/rsa_pubkey.pem","w");

	//PEM_write_bio_RSAPrivateKey(prfile, pkey, NULL, NULL, 0,NULL,NULL);
	//FILE *pufile = NULL;
	//FILE *prfile = NULL;
	//pufile = fopen("./rsa-client-keys/rsa_pubkey.pem", "wt");
	//prfile = fopen("./rsa-client-keys/rsa_prikey.pem", "wt");
	//PEM_write_PUBKEY(pufile, pkey);
	//PEM_write_PrivateKey(prfile, pkey);
	//fflush(pufile);
	//fflush(prfile);
	//fclose(pufile);
	//fclose(prfile);


	X509_REQ *x509_req;
	x509_req = X509_REQ_new();

	if(X509_REQ_set_version(x509_req, 3) != 1)
	{
		printf("1");
	}
	//ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
	

	//x509_name = X509_REQ_get_subject_name(x509_req);
	//X509_NAME_add_entry_by_txt(x509_name,"C", MBSTRING_ASC, (const unsigned char*)szCountry, -1, -1, 0);



	

	//X509_gmtime_adj(X509_get_notBefore(x509), 0);
	//X509_gmtime_adj(X509_get_notAfter(x509), 31536000L);

	if(X509_REQ_set_pubkey(x509_req, pkey) != 1)
	{
		printf("2");
	}


	X509_NAME *name = NULL;
	name = X509_REQ_get_subject_name(x509_req);


	X509_NAME_add_entry_by_txt(name, "C",  MBSTRING_ASC,
                           (unsigned char *)"SE", -1, -1, 0);
	X509_NAME_add_entry_by_txt(name,"L", MBSTRING_ASC, 
						   (unsigned char*)"Stockholm", -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "O",  MBSTRING_ASC,
                           (unsigned char *)"Alex, Inc.", -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                           (unsigned char *)"*.alex.se", -1, -1, 0);

	//X509_set_issuer_name(x509_req, name);

	X509_REQ_sign(x509_req, pkey, EVP_sha1());

	write_X509_to_file(x509_req);

	return x509_req;
}


PKCS7 *sign_CSR(X509_REQ *x509_req)
{
	X509 *x509 = NULL;

	EVP_PKEY *pkey;
	pkey = EVP_PKEY_new();

	RSA *rsa = NULL;
	BIGNUM *bne = NULL;
	BIO *pub = NULL;
	BIO *pri = NULL;
	unsigned long e = RSA_F4;

	bne = BN_new();
	BN_set_word(bne, e);
	rsa = RSA_new();
	//rsa = RSA_generate_key(2048, RSA_F4, NULL, NULL);
	RSA_generate_key_ex(rsa, 2048, bne, NULL);

	pkey = gen_ECDSA_p256_key_pair("./ecdsa-server-keys/");
	//EVP_PKEY_assign_RSA(pkey, rsa);

	//pub = BIO_new_file("./rsa-server-keys/rsa_pubkey.pem","w+");
	//PEM_write_bio_RSAPublicKey(pub, rsa);
	//pri = BIO_new_file("./rsa-server-keys/rsa_privkey.pem","w+");
	//PEM_write_bio_RSAPrivateKey(pri, rsa, NULL, NULL, 0, NULL, NULL);

	//X509 * x509;
	x509 = X509_new();
	ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
	X509_gmtime_adj(X509_get_notBefore(x509), 0);
	X509_gmtime_adj(X509_get_notAfter(x509), 31536000L);
	X509_set_pubkey(x509, pkey);
	X509_NAME *name;
	name = X509_get_subject_name(x509);

	X509_NAME_add_entry_by_txt(name, "C",  MBSTRING_ASC,
                           (unsigned char *)"SE", -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "O",  MBSTRING_ASC,
                           (unsigned char *)"Certificate Authority, Inc.", -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                           (unsigned char *)"*.CA.se", -1, -1, 0);
	X509_set_issuer_name(x509, name);
	
	X509_sign(x509, pkey, EVP_sha1());
	
	FILE *f;
	f = fopen("./cert-server/CA-cert.pem", "wb+");
	PEM_write_X509(f, x509);

	X509 *client_x509 = X509_new();
	X509_set_version(client_x509, 2);
	//ASN1_INTEGER *aserial = NULL;
	//aserial = M_ASN1_INTEGER_new();
	//ASN1_INTEGER_set(aserial, 0);
	X509_set_serialNumber(client_x509, 0);

	long valid_secs = 31536000;

	name = X509_REQ_get_subject_name(x509_req);
	X509_set_subject_name(client_x509, name);
	name = X509_get_subject_name(x509);
	X509_set_issuer_name(client_x509, name);
	EVP_PKEY *req_pubkey;
	req_pubkey=X509_REQ_get_pubkey(x509_req);



	if (X509_REQ_verify(x509_req, req_pubkey) != 1) {
		printf("Error verifying signature on request\n");
		//exit -1;
	}

	if (X509_set_pubkey(client_x509, req_pubkey) != 1) {
		printf("Error setting public key of certificate\n");
		//exit -1;
	}

	if (! (X509_gmtime_adj(X509_get_notBefore(client_x509),0))) {
		printf("Error setting start time\n");
		//exit -1;
	}
   
	if(! (X509_gmtime_adj(X509_get_notAfter(client_x509), valid_secs))) {
		printf("Error setting expiration time\n");
		//exit -1;
	}
	

	X509V3_CTX ctx;
	X509V3_set_ctx(&ctx, x509, client_x509, NULL, NULL, 0);
	X509_EXTENSION *ext;
	EVP_MD *digest = NULL;
	digest = EVP_sha256();
	
	if (! X509_sign(client_x509, pkey, digest)) {
		printf("Error signing the new certificate\n");
		//exit -1;
	}
	
	FILE *client_cert_f;
	client_cert_f = fopen("./cert-client/client-cert.pem", "wb+");
	PEM_write_X509(client_cert_f, client_x509);

	fclose(client_cert_f);

	//FILE *cert_pkcs7;
	char *command = "openssl crl2pkcs7 -nocrl -certfile ./cert-client/client-cert.pem -out ./cert-client/client-cert.p7b -certfile ./cert-server/CA-cert.pem";

	system(command);
	//cert_pkcs7 = popen(command, "w");
	//fclose(cert_pkcs7);
	//BIO *pkcs7_bp = NULL;
	FILE *pkcs7_f;
	pkcs7_f = fopen("./cert-client/client-cert.p7b", "r");
	//pkcs7_bp = BIO_new(BIO_s_file());
	//BIO_read_filename(pkcs7_bp, "./cert-client/client-cert.p7b");
	PKCS7 *pkcs7 = NULL;
	PEM_read_PKCS7(pkcs7_f, &pkcs7, 0, NULL);

	//BIO *bio_out;
    //bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);
    //PKCS7_print_ctx(bio_out, pkcs7, 0, NULL);

	//EVP_PKEY_free(req_pubkey);
	//EVP_PKEY_free(ca_privkey);
	//X509_REQ_free(certreq);
	//X509_free(newcert);
	//BIO_free_all(reqbio);
	//BIO_free_all(outbio);

	return pkcs7;
}
