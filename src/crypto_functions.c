#include "crypto_functions.h"


cbor_item_t *cose_enc_i(cbor_item_t *aad_i, cbor_item_t *app_i, EVP_PKEY *pkey, int msg_type, unsigned char *party)
{
	/*
	 * Build COSE Enc_structure which is the AAD for the encryption
	 */
    cbor_item_t *ENC_STRUCT = cbor_new_definite_array(COSE_ENC_STRUCTURE_SZ);

    cbor_item_t *ctx_string = cbor_new_definite_string();
    ctx_string = cbor_build_string(ENC_STRUCT_CTX);
    if (!cbor_array_push(ENC_STRUCT, ctx_string))
    {
        printf("\ncbor_array_push ctx_string FAILED.\n");
    }

    cbor_item_t *protected_attr = cbor_new_definite_bytestring();
    unsigned char protected_attr_data[] = ENC_STRUCT_PROTECTED_ATTR;
    protected_attr = cbor_build_bytestring(protected_attr_data, ENC_STRUCT_PROTECTED_ATTR_SZ);
    if (!cbor_array_push(ENC_STRUCT, protected_attr))
    {
        printf("\ncbor_array_push protected_attr FAILED.\n");
    }

    cbor_item_t *ext_aad = cbor_new_definite_bytestring();
    unsigned char *aad_hash = hash_aad(aad_i, msg_type);
	//printf("AAD in COSE ENCRYPT I:\n");
	//print_bytes(aad_hash, AAD_HASH_SZ);
	//fflush(stdout);
    ext_aad = cbor_build_bytestring(aad_hash, AAD_HASH_SZ);
    if (!cbor_array_push(ENC_STRUCT, ext_aad))
    {
        printf("\ncbor_array_push ext_aad FAILED.\n");
    }
    
	unsigned char *enc_struct_buffer;
    size_t enc_struct_buffer_sz, length = cbor_serialize_alloc(ENC_STRUCT, &enc_struct_buffer, &enc_struct_buffer_sz);
	
	printf("\n Print bytes enc struct buffer:\n");
	print_bytes(enc_struct_buffer, enc_struct_buffer_sz);

	/*
	 * Generate K_i with HKDF
	 */
    unsigned char *k_i = gen_K_i(aad_hash, pkey, msg_type, (unsigned char*)"", party);

	/*
	 * Generate IV with HKDF
	 */
    unsigned char *iv = gen_K_i(aad_hash, pkey, msg_type, (unsigned char*)"IV-GENERATION", party);


    //unsigned char *ciphertext = malloc(500);
    unsigned char *app_i_buffer;
    size_t app_i_buffer_sz, app_i_length = cbor_serialize_alloc(app_i, &app_i_buffer, &app_i_buffer_sz);
	//size_t cbor_obj_sz = cbor_bytestring_length(app_i);
	//printf("CBOR OBJ SZ::::::::::::: %d", cbor_obj_sz);
	//printf("APP_I_BUFFER:::::::::::::: %d", app_i_buffer_sz);
	//printf("APP_I_LENGTH:::::::::::::: %d", app_i_length);
    unsigned char *ciphertext = malloc(app_i_length + AES_CCM_64_64_128_block_sz - (app_i_length%AES_CCM_64_64_128_block_sz));// = malloc(app_i_length+200);
    unsigned char *tag = malloc(AES_CCM_64_64_128_tag_sz);
    int ciphertext_len = encrypt_ccm(app_i_buffer, app_i_length, enc_struct_buffer, enc_struct_buffer_sz, k_i, iv, ciphertext, tag);
	//printf("CIPHERTEXT LEN:::::::::::::: %d", ciphertext_len);
    
	//unsigned char *plaintext = malloc(app_i_length+200);
	unsigned char *plaintext = malloc(ciphertext_len);
    int dec_ciphertext_len = decrypt_ccm(ciphertext, ciphertext_len, enc_struct_buffer, enc_struct_buffer_sz, tag, k_i, iv, plaintext);
    //printf("\nDECRYPTED output:\n%s", plaintext);
	printf("\nCIPHERTEXT len: %d\n", dec_ciphertext_len);
    printf("\nDECRYPTED output:\n");
	print_bytes(plaintext, dec_ciphertext_len);
	
	/*
	 * Concatenate tag to ciphertext
	 */
	//memcpy(ciphertext + strlen((const char*)ciphertext), tag, AES_CCM_64_64_128_tag_sz);
	
	memcpy(ciphertext + ciphertext_len, tag, AES_CCM_64_64_128_tag_sz);
    
	//unsigned char *plaintext = malloc(ciphertext_len);
	//printf("\nENC STRUCT BUFFER AND >> SZ: %s %zu \n", enc_struct_buffer, enc_struct_buffer_sz);
    dec_ciphertext_len = decrypt_ccm(ciphertext, ciphertext_len, enc_struct_buffer, enc_struct_buffer_sz, tag, k_i, iv, plaintext);
	printf("\nCIPHERTEXT len: %d\n", dec_ciphertext_len);
    printf("\nDECRYPTED output:\n");
	print_bytes(plaintext, dec_ciphertext_len);
	/*
	 * Build COSE_ENC_i structure
	 */
    cbor_item_t *COSE_ENC_i = cbor_new_indefinite_array();

	cbor_item_t *protected = cbor_new_definite_bytestring();
    unsigned char protected_data[] = ENC_STRUCT_PROTECTED_ATTR;
    protected = cbor_build_bytestring(protected_data, ENC_STRUCT_PROTECTED_ATTR_SZ);
    if (!cbor_array_push(COSE_ENC_i, protected))
    {
        printf("\ncbor_array_push protected to COSE_ENC_i FAILED!");
    }

    cbor_item_t *unprotected = cbor_new_definite_map(ENC_STRUCT_UNPROTECTED_ATTR_SZ);
    if (!cbor_array_push(COSE_ENC_i, unprotected))
    {
        printf("\ncbor_array_push unprotected to COSE_ENC_i FAILED!");
    }

    cbor_item_t *Encrypt0_ciphertext;
    Encrypt0_ciphertext = cbor_build_bytestring(ciphertext, ciphertext_len + AES_CCM_64_64_128_tag_sz);
    if (!cbor_array_push(COSE_ENC_i, Encrypt0_ciphertext))
    {
        printf("\ncbor_array_push Encrypt0_ciphertext to COSE_ENC_i FAILED!");
    }

    //unsigned char *plaintext = malloc(500);
    //int dec_ciphertext_len = decrypt_ccm(ciphertext, ciphertext_len, enc_struct_buffer, enc_struct_buffer_sz, tag, k_i, iv, plaintext);
    //printf("\nDECRYPTED output:\n%s", plaintext);
	//printf("\nCIPHERTEXT len: %d\n", dec_ciphertext_len);
	
	//memcpy(ciphertext + strlen((const char*)ciphertext), tag, AES_CCM_64_64_128_tag_sz);
	
	return COSE_ENC_i;
}


cbor_item_t *COSE_KDF_Context(unsigned char *mode, unsigned char *aad_i)
{
    const char *selected_mode = (const char*)mode;
    cbor_item_t *cose_kdf_ctx = cbor_new_definite_array(COSE_KDF_CTX_SZ);

    const char *tstr = "IV-GENERATION";
    cbor_item_t *algorithm_ID_int = cbor_new_int8();
    cbor_item_t *algorithm_ID_tstr = cbor_new_definite_string();
    if (strcmp(selected_mode, tstr))
    {
        algorithm_ID_tstr = cbor_build_string(tstr);
        if (!cbor_array_push(cose_kdf_ctx, algorithm_ID_tstr))
        {
            printf("\ncbor_array_push algorithm_ID_tstr FAILED");
        }
    }
    else
    {
        algorithm_ID_int = cbor_build_uint8(AES_CCM_64_64_128);
        if (!cbor_array_push(cose_kdf_ctx, algorithm_ID_int))
        {
            printf("\ncbor_array_push algorithm_ID_int FAILED");
        }
    }

    cbor_item_t *partyUinfo = cbor_new_definite_array(3);

    cbor_item_t *identity = cbor_new_definite_bytestring();
    cbor_item_t *nonce = cbor_new_definite_bytestring();
    cbor_item_t *other = cbor_new_definite_bytestring();
    identity = cbor_build_bytestring(NULL, 0);
    nonce = cbor_build_bytestring(NULL, 0);
    other = cbor_build_bytestring(NULL, 0);
    if (!cbor_array_push(partyUinfo, identity))
    {
        printf("\ncbor_array_push identity FAILED");
    }
    if (!cbor_array_push(partyUinfo, nonce))
    {
        printf("\ncbor_array_push nonce_ID_int FAILED");
    }
    if (!cbor_array_push(partyUinfo, other))
    {
        printf("\ncbor_array_push other FAILED");
    }

    if (!cbor_array_push(cose_kdf_ctx, partyUinfo))
    {
        printf("\ncbor_array_push partyUinfo FAILED");
    }

    cbor_item_t *keyDataLength = cbor_new_int8();
    if (strcmp(selected_mode, tstr))
    {
        keyDataLength = cbor_build_uint8(COSE_KDF_CTX_keyDataLength_IV);
    }
    else
    {
        keyDataLength = cbor_build_uint8(COSE_KDF_CTX_keyDataLength);
    }
    if (!cbor_array_push(cose_kdf_ctx, keyDataLength))
    {
        printf("\ncbor_array_push keyDataLength FAILED");
    }

    cbor_item_t *protected = cbor_new_definite_bytestring();
    unsigned char protected_data[] = COSE_KDF_CTX_protected;
    protected = cbor_build_bytestring(protected_data, COSE_KDF_CTX_protected_sz);
    if (!cbor_array_push(cose_kdf_ctx, protected))
    {
        printf("\ncbor_array_push protected FAILED");
    }

    other = cbor_new_definite_bytestring();
    unsigned char *other_data = aad_i;
    other = cbor_build_bytestring(other_data, sizeof(other_data));
    if (!cbor_array_push(cose_kdf_ctx, other))
    {
        printf("\ncbor_array_push other FAILED");
    }

    return cose_kdf_ctx;
}


ASN1_INTEGER *create_nonce(int bits)
{
	int RAND_bytes(unsigned char buffer[], int length);
    unsigned char buf[20];
    ASN1_INTEGER *nonce = NULL;
    int len = (bits - 1) / 8 + 1;
    int i;

    if (len > (int)sizeof(buf))
    { 
        goto err;
    } 
    if (RAND_bytes(buf, len) <= 0)
    { 
        goto err;
    } 
    
    /* Find the first non-zero byte and creating ASN1_INTEGER object. */
    for (i = 0; i < len && !buf[i]; ++i)
    { 
        continue;
    } 
    if ((nonce = ASN1_INTEGER_new()) == NULL)
    { 
        goto err;
    } 
    OPENSSL_free(nonce -> data);
    nonce -> length = len - i;
    nonce -> data = malloc(nonce -> length + 1);
    memcpy(nonce -> data, buf + i, nonce -> length);
  
    return nonce;

    err:
        printf("\nCould not create nonce.\n");
        ASN1_INTEGER_free(nonce);

        return NULL;
}


int decrypt_ccm(unsigned char *ciphertext, int ciphertext_len, unsigned char *aad,
    int aad_len, unsigned char *tag, unsigned char *key, unsigned char *iv,
    unsigned char *plaintext)
{
	printf("\n---- DECRYPTION INPUT ----\n");
	printf("CIPHERTEXT:\n");
	print_bytes(ciphertext, ciphertext_len);
	printf("\nCIPHERTEXT LEN: %d", ciphertext_len);
	printf("\nAAD:\n");
	print_bytes(aad, aad_len);
	printf("\nAAD LEN: %d", aad_len);
	printf("\nTAG:\n");
	print_bytes(tag, AES_CCM_64_64_128_tag_sz);
	printf("\nKEY:\n");
	print_bytes(key, HKDF_OUT_SZ);
	printf("\nIV:\n");
	print_bytes(iv, HKDF_OUT_SZ);
	//printf("\nSIZE OF PLAINTEXT: %lu", sizeof(plaintext));
	printf("\n--------------------------\n");
    EVP_CIPHER_CTX *ctx;
    int len; 
    int plaintext_len;
    int ret;
    
    if(!(ctx = EVP_CIPHER_CTX_new()))
    {
        handleErrors();
		printf("\nEVP_CIPHER_CTX_new FAILED!");
    }
	else
	{
		printf("1!");
	}
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_ccm(), NULL, NULL, NULL))
    {   
        handleErrors();
		printf("\nEVP_DecryptInit_ex FAILED!");
    }
	else
	{
		printf("2!");
	}
    /* Setting IV len to 7. Not strictly necessary as this is the default
     * but shown here for the purposes of this example */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, 7, NULL))
    {
        handleErrors();
		printf("\nEVP_CIPHER_CTX_ctrl FAILED!");
    }
	else
	{
		printf("3!");
	}
    /* Set expected tag value. */
	//tag = "123jk";
	//int res = 0;
	//res = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, AES_CCM_64_64_128_tag_sz, tag);
	//printf("\n RES = %d\n",res); 
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, AES_CCM_64_64_128_tag_sz, tag))
    {
        handleErrors();
		printf("\nEVP_CIPHER_CTX_ctrl FAILED!");
    }
	else
	{
		printf("4!");
	}
    /* Initialise key and IV */
    if(1 != EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
    {
        handleErrors();
		printf("\nEVP_DecryptInit_ex FAILED!");
    }
	else
	{
		printf("5!");
	}
    /* Provide the total ciphertext length
     */ 
    if(1 != EVP_DecryptUpdate(ctx, NULL, &len, NULL, ciphertext_len))
    {
        handleErrors();
		printf("\nEVP_DecryptUpdate FAILED!");
    }
	else
	{
		printf("6!");
	}
    /* Provide any AAD data. This can be called zero or more times as
     * required
     */
    if(1 != EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
    {
        handleErrors();
		printf("\nEVP_DecryptUpdate FAILED!");
    }
	else
	{
		printf("7!");
	}
    /* Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    ret = EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);

    plaintext_len = len;
	printf("\nPLAINTEXT LEN: %d", plaintext_len);
    
	printf("\nPLAINTEXT:\n");
	print_bytes(plaintext, plaintext_len);
    
	EVP_CIPHER_CTX_free(ctx);
    
    if(ret > 0)
    {
        /* Success */
        return plaintext_len;
    }
    else
    {   
        /* Verify failed */
        return -1;
    }
}


int encrypt_ccm(unsigned char *plaintext, int plaintext_len, unsigned char *aad, int aad_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext, unsigned char *tag)
{
	printf("\n---- ENCRYPTION INPUT START ----\n");
	//printf("CIPHERTEXT:\n %s", ciphertext);
	//printf("\nCIPHERTEXT LEN: %d", ciphertext_len);
	//printf("\nAAD:\n %s", aad);
	printf("\nPLAINTEXT:\n");
	print_bytes(plaintext, plaintext_len);
	printf("\nAAD:\n");
	print_bytes(aad, aad_len);
	printf("\nAAD LEN: %d", aad_len);
	printf("\nTAG:\n");
	print_bytes(tag, AES_CCM_64_64_128_tag_sz);
	printf("\nKEY:\n");
	print_bytes(key, HKDF_OUT_SZ);
	printf("\nIV:\n");
	print_bytes(iv, HKDF_OUT_SZ);
	//printf("\nSIZE OF PLAINTEXT: %d", plaintext_len);
	printf("\n--------------------------\n");

    EVP_CIPHER_CTX *ctx;

    int len;
    int ciphertext_len;

    if (!(ctx = EVP_CIPHER_CTX_new()))
    {
        handleErrors();
        printf("\nEVP_CIPHER_CTX_new FAILED!");
    }
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ccm(), NULL, NULL, NULL))
    {
        handleErrors();
        printf("\nEVP_EncryptInit_ex FAILED!");
    }
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, 7, NULL))
    {
        handleErrors();
        printf("\nEVP_CIPHER_CTX_ctrl FAILED!");
    }
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, AES_CCM_64_64_128_tag_sz, NULL);
    if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))
    {
        handleErrors();
        printf("EVP_EncryptInit_ex of key and IV FAILED!");
    }
    if (1 != EVP_EncryptUpdate(ctx, NULL, &len, NULL, plaintext_len))
    {
        handleErrors();
        printf("\nEVP_EncrypUpdate FAILED!");
    }
    if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len))
    {
        handleErrors();
        printf("\nEVP_EncryptUpdate FAILED!");
    }
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    {
        handleErrors();
        printf("\nEVP_EncryptUpdate FAILED!");
    }
    ciphertext_len = len;
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
    {
        handleErrors();
        printf("\nEVP_EncryptFinal_ex FAILED!");
    }
    ciphertext_len += len;
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_GET_TAG, AES_CCM_64_64_128_tag_sz, tag))
    {
        handleErrors();
        printf("\nEVP_CIPHER_CTX_ctrl FAILED!");
    }
	//printf("\nTAG used for encryption: %s \n", tag);
	printf("\nTAG used for encryption:\n");
	print_bytes(tag, AES_CCM_64_64_128_tag_sz);
    EVP_CIPHER_CTX_free(ctx);

	printf("\n---- ENCRYPTION INPUT END ----\n");
	printf("CIPHERTEXT:\n ");
	print_bytes(ciphertext, ciphertext_len);
	printf("\nCIPHERTEXT LEN: %d", ciphertext_len);
	//printf("\nAAD:\n %s", aad);
	//printf("\nAAD LEN: %d", aad_len);
	//printf("\nTAG:\n %s", tag);
	//printf("\nKEY:\n %s", key);
	//printf("\nIV:\n %s", iv);
	//printf("\nPLAINTEXT:\n %s", plaintext);
	//printf("\nSIZE OF PLAINTEXT: %d", plaintext_len);
	printf("\n--------------------------\n");

    return ciphertext_len;
}


unsigned char *gen_K_i(unsigned char *ext_aad, EVP_PKEY *session_pkey, int msg_type, unsigned char *mode, unsigned char *party)
{
    EVP_PKEY_CTX *pctx;
    unsigned char k_i[HKDF_OUT_SZ];
    size_t outlen = sizeof(k_i);
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);

    const char *salt = get_salt();
    size_t salt_sz = strlen(salt);
    cbor_item_t *cose_kdf_ctx = COSE_KDF_Context(mode, ext_aad);
    unsigned char *buffer_kdf_context;
    size_t buffer_sz, kdf_context_sz = cbor_serialize_alloc(cose_kdf_ctx, &buffer_kdf_context, &buffer_sz);

    size_t *skeylength = malloc(sizeof(int));
	int msg_num = get_msg_num(msg_type);
	const char *filepath;
	if (strcmp((const char *)party, "SERVER") == 0)
	{
		filepath = "./edhoc_server_INBOX/client_PUBKEY.txt";
	}
	else if (strcmp((const char *)party, "CLIENT") == 0)
	{
		filepath = "./edhoc_client_INBOX/server_PUBKEY.txt";
	}
    unsigned char *shared_secret = gen_shared_secret(session_pkey, skeylength, filepath);
    printf("\nShared secret size: %zu\n", shared_secret_sz);

    if (EVP_PKEY_derive_init(pctx) <= 0)
    {
        /* Error */
        printf("\nEVP_PKEY_derive_init FAILED.\n");
    }
    if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0)
    {
        /* Error */
        printf("\nEVP_PKEY_CTX_set_hkdf_md FAILED.\n");
    }
    if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, salt_sz) <= 0)
    {
        /* Error */
        printf("\nEVP_PKEY_CTX_set1_salt FAILED\n");
    }
    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, shared_secret, shared_secret_sz) <= 0)
    {
        /* Error */
        printf("\nEVP_PKEY_CTX_set1_key FAILED.\n");
    }
    if (EVP_PKEY_CTX_add1_hkdf_info(pctx, buffer_kdf_context, kdf_context_sz) <= 0)
    {
        /* Error */
        printf("\nEVP_PKEY_CTX_add1_hkdf_info FAILED.\n");
    }
    if (EVP_PKEY_derive(pctx, k_i, &outlen) <= 0)
    {
        /* Error */
        printf("\nEVP_PKEY_derive FAILED.\n");
    }

    unsigned char *k_i_ptr = malloc(HKDF_OUT_SZ);
    if (strcmp((const char*)mode, "IV-GENERATION") != 0)
    {
        printf("\nHKDF extract-and-expand output k_%d:\n", get_msg_num(msg_type));
    }
    else if (strcmp((const char*)mode, "IV-GENERATION") == 0)
    {
        printf("\nHKDF extract-and-expand output for IV-GENERATION k_%d:\n", get_msg_num(msg_type));
    }
    for (int i = 0; i < HKDF_OUT_SZ; i++)
    {
        k_i_ptr[i] = k_i[i];
        printf("%02x", k_i_ptr[i]);
    }
    printf("\n");

    return k_i_ptr;
}


unsigned char *gen_random_S_ID(size_t length) 
{
    printf("\nS_ID length = %zu\n", length);
    unsigned char *s_id = malloc(length);
    static const char alphanum[] = "0123456789" "ABCDEFGHIJKLMNOPQRSTUVWXYZ" "abcdefghijklmnopqrstuvwxyz";

    for (int i = 0; i < length; ++i) {
        s_id[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
    }

    s_id[length] = 0;

    return s_id;
}


unsigned char *gen_shared_secret(EVP_PKEY *pkey, size_t *skeylength, const char *filepath)
{
    FILE *keyfile = fopen(filepath, "r");
    EVP_PKEY *peerkey = PEM_read_PUBKEY(keyfile, NULL, NULL, NULL);
    printf("\nOTHER Party's PUBKEY:\n");
    PEM_write_PUBKEY(stdout, peerkey);

    EVP_PKEY_CTX *ctx;
    unsigned char *skey;
    size_t skeylen;
    ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) {
        /* Error */
        printf("\nCTX is empty\n");
    }
    if (EVP_PKEY_derive_init(ctx) <= 0) {
        /* Error */
        printf("\nEVP derive initialization failed\n");
    }
    if (EVP_PKEY_derive_set_peer(ctx, peerkey) <= 0) {
        /* Error */
        printf("\nEVP derive set peer failed\n");
    }
    /* Determine buffer length */
    if (EVP_PKEY_derive(ctx, NULL, &skeylen) <= 0) {
        /* Error */
        printf("\nEVP derive failed\n");
    }
    skey = OPENSSL_malloc(skeylen);
    if (!skey) {
        /* Malloc failure */
        printf("\nOpenSSL Malloc failed\n");
    }
    if (EVP_PKEY_derive(ctx, skey, &skeylen) <= 0) {
        /* Error */
        printf("\nShared key derivation failed\n");
    }

    printf("\nShared secret:\n");
    for (size_t i = 0; i < skeylen; i++) {
        printf("%02x", skey[i]);
    }
    printf("\n");
    skeylength = malloc(sizeof(int));
    *skeylength = skeylen;

    shared_secret_sz = skeylen;

    return skey;
}


EVP_PKEY *gen_x25519()
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(NID_X25519, NULL);
    EVP_PKEY_keygen_init(pctx);
    EVP_PKEY_keygen(pctx, &pkey);
    EVP_PKEY_CTX_free(pctx);
    printf("\n\nX25519 PUBKEY:\n");
    PEM_write_PUBKEY(stdout, pkey);

    if (!print_pkey_hr(pkey))
    {
        printf("\nPrint key in human readable form FAILED.\n");
    }

    return pkey;
}


const char *get_salt()
{
    if (strcmp(EDHOC_MODE, "asymmetric") == 0)
    {
        return "";
    }
    else if (strcmp(EDHOC_MODE, "symmetric") == 0)
    {
        return PSK;
    }
    else
    {
        printf("\nERROR, uknown option for SALT!");
        return "";
    }
}


void *get_x(EVP_PKEY *pkey)
{
    EC_GROUP *ec_group;
    ec_group = EC_GROUP_new_by_curve_name(NID_X25519);
    if (ec_group == NULL)
    {
        printf("\nEC_GROUP is INVALID.\n");
    }
    else
    {
        printf("\nEC_GROUP is ok.\n");
    }

    return 0;
}


EVP_PKEY *get_x25519()
{
    FILE *keyfile = fopen("static_PUBKEY.txt", "r");
    EVP_PKEY *pkey = NULL;
    //EVP_PKEY_CTX *pctx =
    pkey = PEM_read_PUBKEY(keyfile, NULL, NULL, NULL);
    printf("\nAlices's PUBKEY:\n");
    PEM_write_PUBKEY(stdout, pkey);

    if (!print_pkey_hr(pkey))
    {
        printf("\nPrint key in human readable form FAILED.\n");
    }

    return pkey;
}


void handleErrors(void)
{
  ERR_print_errors_fp(stderr);
  abort();
}


unsigned char *hash_aad(cbor_item_t *aad, int msg_type)
{
    unsigned char *aad_hash;
    unsigned int *aad_hash_len = malloc(sizeof(int));
    unsigned char *buffer;
    size_t buffer_sz, length = cbor_serialize_alloc(aad, &buffer, &buffer_sz);

    EVP_MD_CTX *mdctx;

    if((mdctx = EVP_MD_CTX_create()) == NULL)
    {
        handleErrors();
        printf("\nEVP_MD_CTX_create FAILED!");
    }
    if(1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL))
    {
        handleErrors();
        printf("\nEVP_DigestInit_ex FAILED!");
    }
    if(1 != EVP_DigestUpdate(mdctx, buffer, length))
    {
        handleErrors();
        printf("\nEVP_DigestUpdate FAILED!");
    }
    if((aad_hash = (unsigned char *)OPENSSL_malloc(EVP_MD_size(EVP_sha256()))) == NULL)
    {
        handleErrors();
        printf("\nOPENSSL_malloc FAILED!");
    }
    if(1 != EVP_DigestFinal_ex(mdctx, aad_hash, aad_hash_len))
    {
        handleErrors();
        printf("\nEVP_DigestFinal_ex FAILED!");
    }
    EVP_MD_CTX_destroy(mdctx);

    printf("\nHash of aad_%d:\n", get_msg_num(msg_type));
    for (int i = 0; i < AAD_HASH_SZ; i++)
    {
        printf("%02x", aad_hash[i]);
    }
    printf("\n");

    return aad_hash;
}


unsigned char *request_nonce(int nonce_sz)
{
    OCSP_REQUEST *req;
    req = OCSP_REQUEST_new();
    unsigned char *nonce;
    nonce = malloc(nonce_sz);
    int ocsp_request = OCSP_request_add1_nonce(req, NULL, nonce_sz);
    if (!ocsp_request)
    {
        printf("\nERROR: Failed to generate nonce.\n");
    }
    else if (ocsp_request)
    {
        printf("\nNonce generation succeeded.\n");
        OCSP_BASICRESP *resp;
        resp = OCSP_BASICRESP_new();
        int ocsp_req_copy = OCSP_copy_nonce(resp, req);
        if (!ocsp_req_copy)
        {
            printf("\nNonce copy FAILED.\n");
        }
        i2d_OCSP_BASICRESP(resp, &nonce);
        for (int i = 0; i < nonce_sz; i++)
        {
            printf("%02x", nonce[i]);
        }
    }
    else
    {
        printf("\nERROR: %d in nonce generation.\n", ocsp_request);
    }

    return nonce;
}
