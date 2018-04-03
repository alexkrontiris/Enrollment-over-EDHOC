#include "key_gen.h"


#define EC_TYPE "NID_X9_62_prime256v1"


EVP_PKEY *gen_ECDSA_p256_key_pair(char *path)
{
	// Context initialization
	BIO *outbio = NULL;
	BIO *outbio_pub = NULL;
	BIO *outbio_pri = NULL;
	EC_KEY *eckey = NULL;
	EVP_PKEY *pkey = NULL;
	int ec_name;
	
	// Openssl Initialization
	OpenSSL_add_all_algorithms();
	ERR_load_BIO_strings();
	ERR_load_crypto_strings();

	// IO BIO
	outbio  = BIO_new(BIO_s_file());
	outbio = BIO_new_fp(stdout, BIO_NOCLOSE);
	char *filename_pub = malloc(41);
	char *filename_pri = malloc(41);
	strcat(filename_pub, path);
	strcat(filename_pub, "ec_pubkey.pem");
	strcat(filename_pri, path);
	strcat(filename_pri, "ec_privkey.pem");
	outbio_pub = BIO_new_file(filename_pub, "w+");
	outbio_pri = BIO_new_file(filename_pri, "w+");

	// EC key struct
	ec_name = OBJ_txt2nid("prime256v1");
	eckey = EC_KEY_new_by_curve_name(ec_name);
	EC_KEY_set_asn1_flag(eckey, OPENSSL_EC_NAMED_CURVE);

	if (! (EC_KEY_generate_key(eckey)))
	{
		BIO_printf(outbio, "Error generating the ECC key.");
	}

	pkey=EVP_PKEY_new();
	if (!EVP_PKEY_assign_EC_KEY(pkey, eckey))
	{
		BIO_printf(outbio, "Error assigning ECC key to EVP_PKEY structure.");
	}

	eckey = EVP_PKEY_get1_EC_KEY(pkey);
	const EC_GROUP *ec_group = EC_KEY_get0_group(eckey);

	// Print key length and type
	BIO_printf(outbio, "ECC Key size: %d bit\n", EVP_PKEY_bits(pkey));
	BIO_printf(outbio, "ECC Key type: %s\n", OBJ_nid2sn(EC_GROUP_get_curve_name(ec_group)));

	// Write key pair to file
	PEM_write_bio_EC_PUBKEY(outbio_pub, eckey);
	PEM_write_bio_ECPrivateKey(outbio_pri, eckey, NULL, NULL, 0, NULL, NULL);

	// Free structs
	EC_KEY_free(eckey);
	BIO_free_all(outbio);
	BIO_free_all(outbio_pri);
	BIO_free_all(outbio_pub);
	free(filename_pub);
	free(filename_pri);

	return pkey;
}
