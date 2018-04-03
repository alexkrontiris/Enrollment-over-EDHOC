#include "edhoc_messages.h"


struct msg_1_data MSG_1;
struct msg_2_data MSG_2;
struct msg_3_data MSG_3;
struct msg_4_data MSG_4;


unsigned char *error_msg(int msg_type, const char *msg_payload)
{
    cbor_item_t *MSG = cbor_new_indefinite_array();
    
    cbor_item_t *MSG_TYPE = cbor_new_int8();
    MSG_TYPE = cbor_build_uint8(msg_type);
    if (!cbor_array_push(MSG, MSG_TYPE))
    {   
        printf("\nerror_msg cbor_array_push MSG_TYPE FAILED.\n");
    }   

    cbor_item_t *ERR_MSG = cbor_new_definite_string();
    ERR_MSG = cbor_build_string(msg_payload);
    if (!cbor_array_push(MSG, ERR_MSG))
    {   
        printf("\nerror_msg cbor_array_push ERR_MSG FAILED.\n");
    }   

    unsigned char *buffer;
    size_t buffer_sz, length = cbor_serialize_alloc(MSG, &buffer, &buffer_sz);

    //write_cbor_array_to_file_RAW(buffer, length);

    //write_cbor_array_to_file_BINARY(buffer, length);

    print_cbor_array_to_stdout(buffer, length);
    
    return buffer;
}


unsigned char *gen_msg_1_sym(unsigned char *app_1, size_t app_1_sz, EVP_PKEY *pkey, const char *filepath)
{
	int msg_type = EDHOC_SYM_MSG_1;

	printf("\n#### GENERATING EDHOC SYMMETRIC MSG_%d ####\n", get_msg_num(msg_type));

    cbor_item_t *MSG = cbor_new_indefinite_array();
    if (!CBOR_ITEM_T_init(MSG))
    {
        printf("\ncbor_item_t initialization FAILED.\n");
    }

    cbor_item_t *MSG_TYPE = cbor_new_int8();
    MSG_TYPE = cbor_build_uint8(msg_type);
    if (!cbor_array_push(MSG, MSG_TYPE))
    {
        printf("\ncbor_array_push MSG_TYPE FAILED.\n");
    }

    cbor_item_t *S_U = cbor_new_definite_bytestring();
    //size_t variable_length = rand() % (S_ID_MAX_SIZE + 1 - S_ID_MIN_SIZE) + S_ID_MIN_SIZE;
    //unsigned char *bstr_s_u = gen_random_S_ID(variable_length);
    //S_U = cbor_build_bytestring(bstr_s_u, variable_length);
	unsigned char s_id_party_U[] = S_ID_PARTY_U;
	unsigned char *bstr_s_u = (unsigned char *)S_ID_PARTY_U;
	S_U = cbor_build_bytestring(bstr_s_u, sizeof(S_ID_PARTY_U));
    if (!cbor_array_push(MSG, S_U))
    {
        printf("\ncbor_array_push S_U FAILED.\n");
    }

    cbor_item_t *N_U = cbor_new_definite_bytestring();
    ASN1_INTEGER *nonce_asn1 = create_nonce(NONCE_size_bits);
	BIGNUM *bn = ASN1_INTEGER_to_BN(nonce_asn1, NULL);
 	unsigned char *bstr_n_u = (unsigned char*)BN_bn2hex(bn);
 	N_U = cbor_build_bytestring(bstr_n_u, NONCE_size_bytes);
	if (!cbor_array_push(MSG, N_U))
	{
		printf("\ncbor_array_push N_U FAILED.\n");
	}

	/* cbor map format */
 	cbor_item_t *E_U = cbor_new_definite_map(E_U_map_size);
	int *bstr_e_u_sz = malloc(sizeof(int));
	unsigned char *bstr_e_u = strip_pkey(pkey, bstr_e_u_sz);
	/* key_1 and key_2 refer to cbor map keys */
	cbor_item_t *key_1;
	key_1 = cbor_new_int8();
	cbor_mark_negint(key_1);
	int abs_key_1 = abs(E_U_map_param_1 - 1);
	cbor_set_uint8(key_1, abs_key_1);
	cbor_map_add(E_U, (struct cbor_pair)
	{
		.key = cbor_move(key_1),
		.value = cbor_move(cbor_build_uint8(X25519_OKP_value))
	});
	cbor_item_t *key_2;
	key_2 = cbor_new_int8();
	cbor_mark_negint(key_2);
	int abs_key_2 = abs(E_U_map_param_2 - 1);
	cbor_set_uint8(key_2, abs_key_2);
	cbor_map_add(E_U, (struct cbor_pair)
	{
		.key = cbor_move(key_2),
		.value = cbor_move(cbor_build_bytestring(bstr_e_u, *bstr_e_u_sz))
	});
	cbor_map_add(E_U, (struct cbor_pair)
	{
 		.key = cbor_move(cbor_build_uint8(E_U_map_param_3)),
		.value = cbor_move(cbor_build_uint8(COSE_key_object_type))
	});
	if (!cbor_array_push(MSG, E_U))
	{
		printf("\ncbor_array_push E_U FAILED.\n");
	}

	cbor_item_t *ECDH_Curves_U = cbor_new_definite_array(ECDH_Curves_ARRAY);
	for (int i = X25519; i <= X25519; i++)
	{
 		cbor_item_t *alg = cbor_new_int8();
		alg = cbor_build_uint8(i);
		if (!cbor_array_push(ECDH_Curves_U, alg))
		{
			printf("\ncbor_array_push alg in ECDH_Curves array FAILED.\n");
		}
	}
	if (!cbor_array_push(MSG, ECDH_Curves_U))
	{
		printf("\ncbor_array_push ECDH_Curves_U FAILED.\n");
	}

	/* 
	 * Push only ONE supported HKDF algorithm for now... 
	 * */
	cbor_item_t *HKDFs_U = cbor_new_definite_array(HKDFs_ARRAY);
	/* 
	 * Push ALL supported HKDF algorithms (work in progress)
	 */
	/*
	for (HKDF_algorithms i = ECDH_ES_HKDF_256; i >= ECDH_SS_HKDF_512; i--)
	{
		cbor_item_t *alg = cbor_new_int8();
		int abs_i = abs(i);
		alg = cbor_build_uint8(abs_i - 1);
		cbor_mark_negint(alg);
		if (!cbor_array_push(HKDFs, alg))
		{
			printf("\ncbor_array_push alg in HKDFs array FAILED.\n");
		}
	}
	*/
	cbor_item_t *hkdf_alg = cbor_new_int8();
	cbor_mark_negint(hkdf_alg);
	int abs_i = abs(ECDH_SS_HKDF_256) - 1;
	cbor_set_uint8(hkdf_alg, abs_i);
	if (!cbor_array_push(HKDFs_U, hkdf_alg))
	{
		printf("\ncbor_array_push alg in HKDFs array FAILED.\n");
	}
	if (!cbor_array_push(MSG, HKDFs_U))
	{
		printf("\ncbor_array_push HKDFs_U FAILED.\n");
	}

	/* 
	 * Push only ONE supported AEAD algorithm for now... 
	 * */
	cbor_item_t *AEADs_U = cbor_new_definite_array(AEADs_ARRAY);
	/* 
	 * Push ALL supported AEAD algorithms (work in progress)
	 * BUG AFTER i = AES_CCM_64_64_128
	 */
	/*
	for (AEAD_algorithms i = AES_CCM_16_64_128; i <= AES_CCM_64_128_256; i++)
	{
 		cbor_item_t *alg = cbor_new_int8(i);
		alg = cbor_build_uint8(i);
		if (!cbor_array_push(AEADs, alg))
		{
			printf("\ncbor_array_push alg in AEADs array FAILED.\n");
		}
		//if (i == 14)
		//{
		//  i = 30;
		//}
	}
	*/
  	cbor_item_t *aead_alg = cbor_new_int8();
	aead_alg = cbor_build_uint8(AES_CCM_64_64_128);
	if (!cbor_array_push(AEADs_U, aead_alg))
	{
		printf("\ncbor_array_push alg in AEADs array FAILED.\n");
	}
	if (!cbor_array_push(MSG, AEADs_U))
	{
		printf("\ncbor_array_push AEADs_U FAILED.\n");
	}

	cbor_item_t *KID = cbor_new_definite_bytestring();
	unsigned char kid[] = PRE_SHARED_KEY_ID;
	KID = cbor_build_bytestring(kid, sizeof(kid));
	if (!cbor_array_push(MSG, KID))
	{
		printf("\ncbor_array_push KID FAILED.\n");
	}

	if (app_1 != NULL)
	{
		cbor_item_t *APP_1 = cbor_new_definite_bytestring();
		APP_1 = cbor_build_bytestring(app_1, app_1_sz);
		if (!cbor_array_push(MSG, APP_1))
		{
			printf("\ncbor_array_push APP_1 FAILED.\n");
		}
	}

    unsigned char *buffer;
    size_t buffer_sz, length = cbor_serialize_alloc(MSG, &buffer, &buffer_sz);

	message_1 = buffer;
	message_1_len = length;

    write_cbor_array_to_file_HEX(buffer, length, msg_type, filepath);

    write_cbor_array_to_file_RAW(buffer, length, msg_type, filepath);

    printf("\nmessage_%d msg_type: %d", get_msg_num(msg_type), msg_type);
    print_cbor_array_to_stdout(buffer, length);

    return buffer;
}


unsigned char *gen_msg_2_sym(unsigned char *app_2, size_t app_2_sz, EVP_PKEY *pkey, const char *filepath, unsigned char *msg_1, size_t msg_1_len)
{
    int msg_type = EDHOC_SYM_MSG_2;

	unsigned char *message_1 = msg_1;
	size_t message_1_len = msg_1_len;

	printf("\n#### GENERATING EDHOC SYMMETRIC MSG_%d ####\n", get_msg_num(msg_type));
   
    cbor_item_t *MSG = cbor_new_indefinite_array();
    if (!CBOR_ITEM_T_init(MSG))
    {
        printf("\ncbor_item_t initialization FAILED.\n");
    }

	cbor_item_t *MSG_TYPE = cbor_new_int8();
	MSG_TYPE = cbor_build_uint8(msg_type);
	if (!cbor_array_push(MSG, MSG_TYPE))
	{
		printf("\ncbor_array_push MSG_TYPE FAILED.\n");
	}

	cbor_item_t *S_U = cbor_new_definite_bytestring();
	//unsigned char s_id_party_U[] = S_ID_PARTY_U;
	unsigned char *bstr_s_u = (unsigned char *)S_ID_PARTY_U;
	S_U = cbor_build_bytestring(bstr_s_u, sizeof(S_ID_PARTY_U));
	if (!cbor_array_push(MSG, S_U))
	{
		printf("\ncbor_array_push S_U FAILED.\n");
	}

	cbor_item_t *S_V = cbor_new_definite_bytestring();
	//size_t variable_length = rand() % (S_ID_MAX_SIZE + 1 - S_ID_MIN_SIZE) + S_ID_MIN_SIZE;
	//unsigned char *bstr_s_v = gen_random_S_ID(variable_length);
	//S_V = cbor_build_bytestring(bstr_s_v, variable_length);
	unsigned char s_id_party_V[] = S_ID_PARTY_V;
	unsigned char *bstr_s_v = s_id_party_V;
	S_V = cbor_build_bytestring(bstr_s_v, sizeof(S_ID_PARTY_V));
	if (!cbor_array_push(MSG, S_V))
	{
		printf("\ncbor_array_push S_V FAILED.\n");
	}

	cbor_item_t *N_V = cbor_new_definite_bytestring();
	ASN1_INTEGER *nonce_asn1 = create_nonce(NONCE_size_bits);
	BIGNUM *bn = ASN1_INTEGER_to_BN(nonce_asn1, NULL);
	unsigned char *bstr_n_v = (unsigned char*)BN_bn2hex(bn);
	N_V = cbor_build_bytestring(bstr_n_v, NONCE_size_bytes);
	if (!cbor_array_push(MSG, N_V))
	{
		printf("\ncbor_array_push N_V FAILED.\n");
	}

	/* cbor map format */
	cbor_item_t *E_V = cbor_new_definite_map(E_V_map_size);
	int *bstr_e_v_sz = malloc(sizeof(int));
	unsigned char *bstr_e_v = strip_pkey(pkey, bstr_e_v_sz);
	/* key_1 and key_2 refer to cbor map keys */
	cbor_item_t *key_1;
	key_1 = cbor_new_int8();
	cbor_mark_negint(key_1);
	int abs_key_1 = abs(E_V_map_param_1 - 1);
	cbor_set_uint8(key_1, abs_key_1);
	cbor_map_add(E_V, (struct cbor_pair)
	{
		.key = cbor_move(key_1),
		.value = cbor_move(cbor_build_uint8(X25519_OKP_value))
	});
	cbor_item_t *key_2;
	key_2 = cbor_new_int8();
	cbor_mark_negint(key_2);
	int abs_key_2 = abs(E_V_map_param_2 - 1);
	cbor_set_uint8(key_2, abs_key_2);
	cbor_map_add(E_V, (struct cbor_pair)
	{
		.key = cbor_move(key_2),
		.value = cbor_move(cbor_build_bytestring(bstr_e_v, *bstr_e_v_sz))
	});
	cbor_map_add(E_V, (struct cbor_pair)
	{
		.key = cbor_move(cbor_build_uint8(E_V_map_param_3)),
		.value = cbor_move(cbor_build_uint8(COSE_key_object_type))
	});
	if (!cbor_array_push(MSG, E_V))
	{
		printf("\ncbor_array_push E_V FAILED.\n");
	}

    /* 
	 * Push only ONE supported HKDF algorithm for now... 
	 * */
 	cbor_item_t *HKDFs_V = cbor_new_definite_array(HKDFs_ARRAY);
	/* 
	 * Push ALL supported HKDF algorithms (work in progress)
	 */
	/*
	for (HKDF_algorithms i = ECDH_ES_HKDF_256; i >= ECDH_SS_HKDF_512; i--)
	{
		cbor_item_t *alg = cbor_new_int8();
		int abs_i = abs(i);
		alg = cbor_build_uint8(abs_i - 1);
		cbor_mark_negint(alg);
		if (!cbor_array_push(HKDFs, alg))
		{
			printf("\ncbor_array_push alg in HKDFs array FAILED.\n");
		}
	}
	*/
	cbor_item_t *hkdf_alg = cbor_new_int8();
	cbor_mark_negint(hkdf_alg);
	int abs_i = abs(ECDH_SS_HKDF_256) - 1;
	cbor_set_uint8(hkdf_alg, abs_i);
	if (!cbor_array_push(HKDFs_V, hkdf_alg))
	{
		printf("\ncbor_array_push alg in HKDFs array FAILED.\n");
	}
	if (!cbor_array_push(MSG, HKDFs_V))
	{
 		printf("\ncbor_array_push HKDFs_V FAILED.\n");
	}

 	/* 
	 * Push only ONE supported AEAD algorithm for now... 
	 * */
	cbor_item_t *AEADs_V = cbor_new_definite_array(AEADs_ARRAY);
	/* 
	 * Push ALL supported AEAD algorithms (work in prgress)
	 * BUG AFTER i = AES_CCM_64_64_128
	 */
	/*
	for (AEAD_algorithms i = AES_CCM_16_64_128; i <= AES_CCM_64_128_256; i++)
	{
 		cbor_item_t *alg = cbor_new_int8(i);
		alg = cbor_build_uint8(i);
		if (!cbor_array_push(AEADs, alg))
		{
			printf("\ncbor_array_push alg in AEADs array FAILED.\n");
		}
		//if (i == 14)
		//{
		//  i = 30;
		//}
	}
	*/
	cbor_item_t *aead_alg = cbor_new_int8();
	aead_alg = cbor_build_uint8(AES_CCM_64_64_128);
	if (!cbor_array_push(AEADs_V, aead_alg))
	{
		printf("\ncbor_array_push alg in AEADs array FAILED.\n");
	}
	if (!cbor_array_push(MSG, AEADs_V))
	{
		printf("\ncbor_array_push AEADs_V FAILED.\n");
	}

	/* 
	 * Serialize cbor array to create data_2
	 */
	unsigned char *buffer_data_2;
	size_t buffer_data_2_sz, length_data_2 = cbor_serialize_alloc(MSG, &buffer_data_2, &buffer_data_2_sz);

	unsigned char *data_2 = buffer_data_2;
	size_t data_2_len = length_data_2;
	
	printf("\ndata_2 (size = %zu):", data_2_len);
	print_cbor_array_to_stdout(data_2, data_2_len);

	printf("\nmessage_1 (size = %zu):", message_1_len);
	print_cbor_array_to_stdout(message_1, message_1_len);

	size_t aad_2_sz = message_1_len + data_2_len;
	printf("\nSize of (message_1 | data_2) = %zu\n", aad_2_sz);

	unsigned char *aad_2 = malloc(message_1_len + data_2_len + 1);
	memcpy(aad_2, message_1, message_1_len);
	memcpy(aad_2 + message_1_len, data_2, data_2_len + 1);
	
	printf("\naad_2 (size = %zu):", aad_2_sz);
	print_cbor_array_to_stdout(aad_2, aad_2_sz);
        
	cbor_item_t *AAD_2 = cbor_new_definite_bytestring();
	AAD_2 = cbor_build_bytestring(aad_2, aad_2_sz);

	cbor_item_t *APP_2;
	if (app_2 != NULL)
	{
		APP_2 = cbor_new_definite_bytestring();
		APP_2 = cbor_build_bytestring(app_2, app_2_sz);
	}
	else
	{
		APP_2 = NULL;
	}

	cbor_item_t *COSE_ENC_2 = cose_enc_i(AAD_2, APP_2, pkey, msg_type, (unsigned char *)"SERVER");
	if (!cbor_array_push(MSG, COSE_ENC_2))
	{
		printf("\ncbor_array_push COSE_ENC_2 FAILED.\n");
	}

    unsigned char *buffer;
    size_t buffer_sz, length = cbor_serialize_alloc(MSG, &buffer, &buffer_sz);

	message_2 = buffer;
	message_2_len = length;

    write_cbor_array_to_file_HEX(buffer, length, msg_type, filepath);

    write_cbor_array_to_file_RAW(buffer, length, msg_type, filepath);

    printf("\nmessage_%d msg_type: %d", get_msg_num(msg_type), msg_type);
    print_cbor_array_to_stdout(buffer, length);

    return buffer;
}


unsigned char *gen_msg_3_sym(unsigned char *app_3, size_t app_3_sz, EVP_PKEY *pkey, const char *filepath, unsigned char *msg_1, unsigned char *msg_2, size_t msg_1_len, size_t msg_2_len)
{
    int msg_type = EDHOC_SYM_MSG_3;

	unsigned char *message_1 = msg_1;
	unsigned char *message_2 = msg_2;
	size_t message_1_len = msg_1_len;
	size_t message_2_len = msg_2_len;

	printf("\n#### GENERATING EDHOC SYMMETRIC MSG_%d ####\n", get_msg_num(msg_type));
   
    cbor_item_t *MSG = cbor_new_indefinite_array();
    if (!CBOR_ITEM_T_init(MSG))
    {
        printf("\ncbor_item_t initialization FAILED.\n");
    }

	cbor_item_t *MSG_TYPE = cbor_new_int8();
	MSG_TYPE = cbor_build_uint8(msg_type);
	if (!cbor_array_push(MSG, MSG_TYPE))
	{
		printf("\ncbor_array_push MSG_TYPE FAILED.\n");
	}

	cbor_item_t *S_V = cbor_new_definite_bytestring();
	unsigned char s_id_party_V[] = S_ID_PARTY_V;
	unsigned char *bstr_s_v = s_id_party_V;
	S_V = cbor_build_bytestring(bstr_s_v, sizeof(S_ID_PARTY_V));
	if (!cbor_array_push(MSG, S_V))
	{
		printf("\ncbor_array_push S_V FAILED.\n");
	}

	/* 
	 * Serialize cbor array to create data_3
	 */
	unsigned char *buffer_data_3;
	size_t buffer_data_3_sz, length_data_3 = cbor_serialize_alloc(MSG, &buffer_data_3, &buffer_data_3_sz);

	unsigned char *data_3 = buffer_data_3;
	size_t data_3_len = length_data_3;
	
	printf("\ndata_3 (size = %zu):", data_3_len);
	print_cbor_array_to_stdout(data_3, data_3_len);

	printf("\nmessage_1 (size = %zu):", message_1_len);
	print_cbor_array_to_stdout(message_1, message_1_len);
	
	printf("\nmessage_2 (size = %zu):", message_2_len);
	print_cbor_array_to_stdout(message_2, message_2_len);

	unsigned char *msg_1_msg_2 = malloc(message_1_len + message_2_len);
	memcpy(msg_1_msg_2, message_1, message_1_len);
	memcpy(msg_1_msg_2 + message_1_len, message_2, message_2_len);
	cbor_item_t *MSG_1_MSG_2 = cbor_new_definite_bytestring();
	MSG_1_MSG_2 = cbor_build_bytestring(msg_1_msg_2, message_1_len + message_2_len);
	unsigned char *msg_1_msg_2_hash = hash_aad(MSG_1_MSG_2, message_1_len + message_2_len);
	size_t msg_1_msg_2_hash_len = strlen((const char *)msg_1_msg_2_hash);

	size_t aad_3_sz = msg_1_msg_2_hash_len + data_3_len;
	printf("\nSize of H(H(message_1 | message_2) | data_3) = %zu\n", aad_3_sz);
	
	unsigned char *aad_3 = malloc(msg_1_msg_2_hash_len + data_3_len + 1);
	memcpy(aad_3, msg_1_msg_2_hash, msg_1_msg_2_hash_len);
	memcpy(aad_3 + msg_1_msg_2_hash_len, data_3, data_3_len + 1);

	cbor_item_t *aad_3_hash = cbor_new_definite_bytestring();
	aad_3_hash = cbor_build_bytestring(aad_3, aad_3_sz);

	// LEFT IT HERE!!!!!!!!!!!!!
	
	printf("\naad_3 (size = %zu):", aad_3_sz);
	print_cbor_array_to_stdout(aad_3, aad_3_sz);
        
	cbor_item_t *AAD_3 = cbor_new_definite_bytestring();
	AAD_3 = cbor_build_bytestring(aad_3, aad_3_sz);

	cbor_item_t *APP_3;
	if (app_3 != NULL)
	{
		APP_3 = cbor_new_definite_bytestring();
		APP_3 = cbor_build_bytestring(app_3, app_3_sz);
	}
	else
	{
		APP_3 = NULL;
	}
	
	cbor_item_t *COSE_ENC_3 = cose_enc_i(AAD_3, APP_3, pkey, msg_type, (unsigned char *)"CLIENT");
	if (!cbor_array_push(MSG, COSE_ENC_3))
	{
		printf("\ncbor_array_push COSE_ENC_3 FAILED.\n");
	}

    unsigned char *buffer;
    size_t buffer_sz, length = cbor_serialize_alloc(MSG, &buffer, &buffer_sz);

	message_3 = buffer;
	message_3_len = length;

    write_cbor_array_to_file_HEX(buffer, length, msg_type, filepath);

    write_cbor_array_to_file_RAW(buffer, length, msg_type, filepath);

    printf("\nmessage_%d msg_type: %d", get_msg_num(msg_type), msg_type);
    print_cbor_array_to_stdout(buffer, length);

    return buffer;
}


unsigned char *gen_msg_4_sym(PKCS7 *cert, size_t cert_sz, EVP_PKEY *pkey, const char *filepath, unsigned char *msg_1, unsigned char *msg_2, unsigned char *msg_3, size_t msg_1_len, size_t msg_2_len, size_t msg_3_len)
{
	BIO *bio_out;
	bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);
	PKCS7_print_ctx(bio_out, cert, 0, NULL);

	unsigned char *app_4;
	app_4 = NULL;
	//unsigned char *app_4 = "thisistheplaintext";
	//int app_4_sz = strlen(app_4);
	int app_4_sz = i2d_PKCS7(cert, &app_4);
	//printf("app_4_sz: %d", app_4_sz);

	//print_bytes(app_4, app_4_sz);


	unsigned char *message_1 = msg_1;
    unsigned char *message_2 = msg_2;
    unsigned char *message_3 = msg_3;
    size_t message_1_len = msg_1_len;
    size_t message_2_len = msg_2_len;
    size_t message_3_len = msg_3_len;

	printf("\n#### GENERATING MSG_4 ####\n");
	//unsigned char *buffer_data_4;
	cbor_item_t *MSG_4 = cbor_new_indefinite_array();
	if (!CBOR_ITEM_T_init(MSG_4))
    {
		printf("\ncbor_item_t initialization FAILED.\n");
	}
	
	cbor_item_t *S_U = cbor_new_definite_bytestring();
	unsigned char s_id_party_U[] = S_ID_PARTY_U;
	unsigned char *bstr_s_u = s_id_party_U;
	S_U = cbor_build_bytestring(bstr_s_u, sizeof(S_ID_PARTY_U));
	if (!cbor_array_push(MSG_4, S_U))
	{
		printf("\ncbor_array_push S_U FAILED.\n");
	}

	//MSG_3.S_V
	//size_t buffer_data_4_sz, length_data_4 = cbor_serialize_alloc(MSG, &buffer_data_4, &buffer_data_4_sz);
	
	//message_3 = import_msg("./edhoc_server_INBOX/edhoc_sym_msg3_RAW.txt", &message_3_len);

/*
	unsigned char *msg_1_msg_2 = malloc(message_1_len + message_2_len);
	memcpy(msg_1_msg_2, message_1, message_1_len);
	memcpy(msg_1_msg_2 + message_1_len, message_2, message_2_len);
	size_t msg_1_msg_2_len = message_1_len + message_2_len;

	cbor_item_t *MSG_1_MSG_2 = cbor_new_definite_bytestring();
	MSG_1_MSG_2 = cbor_build_bytestring(msg_1_msg_2, msg_1_msg_2_len);
	unsigned char *msg_1_msg_2_hash = hash_aad(MSG_1_MSG_2, EDHOC_SYM_MSG_3);
*/


	unsigned char *msg_1_msg_2 = malloc(message_1_len + message_2_len);
    memcpy(msg_1_msg_2, message_1, message_1_len);
    memcpy(msg_1_msg_2 + message_1_len, message_2, message_2_len);
    cbor_item_t *MSG_1_MSG_2 = cbor_new_definite_bytestring();
    MSG_1_MSG_2 = cbor_build_bytestring(msg_1_msg_2, message_1_len + message_2_len);
    unsigned char *msg_1_msg_2_hash = hash_aad(MSG_1_MSG_2, message_1_len + message_2_len);
    //size_t msg_1_msg_2_hash_len = strlen((const char *)msg_1_msg_2_hash);

	size_t aad_4_sz = AAD_HASH_SZ + message_3_len;
    printf("\nSize of H(H(message_1 | message_2) | message_3) = %zu\n", aad_4_sz);
 
	unsigned char *aad_4 = malloc(AAD_HASH_SZ + message_3_len);
    memcpy(aad_4, msg_1_msg_2_hash, AAD_HASH_SZ);
    memcpy(aad_4 + AAD_HASH_SZ, message_3, message_3_len);
  
    cbor_item_t *aad_4_hash = cbor_new_definite_bytestring();
    aad_4_hash = cbor_build_bytestring(aad_4, aad_4_sz);





/*
	unsigned char *msg_1_msg_2_hash_msg_3 = malloc(AAD_HASH_SZ + message_3_len);
	memcpy(msg_1_msg_2_hash_msg_3, msg_1_msg_2_hash, AAD_HASH_SZ);
	memcpy(msg_1_msg_2_hash_msg_3, message_3, message_3_len);

	cbor_item_t *MSG_1_MSG_2_MSG_3 = cbor_new_definite_bytestring();
	MSG_1_MSG_2_MSG_3 = cbor_build_bytestring(msg_1_msg_2_hash_msg_3, AAD_HASH_SZ + message_3_len);
	unsigned char *msg_1_msg_2_msg_3_hash = hash_aad(MSG_1_MSG_2_MSG_3, 7);
	

	unsigned char *aad_4 = msg_1_msg_2_msg_3_hash;
	cbor_item_t *AAD_4 = cbor_new_definite_bytestring();
	AAD_4 = cbor_build_bytestring(aad_4, AAD_HASH_SZ);
*/
	printf("\naad_4 (size = %zu):", aad_4_sz);
    print_cbor_array_to_stdout(aad_4, aad_4_sz);
  
	cbor_item_t *AAD_4 = cbor_new_definite_bytestring();
	AAD_4 = cbor_build_bytestring(aad_4, aad_4_sz);
  
    cbor_item_t *APP_4;
    if (app_4 != NULL)
    {
        APP_4 = cbor_new_definite_bytestring();
		APP_4 = cbor_build_bytestring(app_4, app_4_sz);
    }
    else
    {
		APP_4 = NULL;
    }
  
    cbor_item_t *COSE_ENC_4 = cose_enc_i(AAD_4, APP_4, pkey, 7, (unsigned char *)"SERVER");
    if (!cbor_array_push(MSG_4, COSE_ENC_4))
    {
		printf("\ncbor_array_push COSE_ENC_3 FAILED.\n");
    }
  
	unsigned char *buffer;
    size_t buffer_sz, length = cbor_serialize_alloc(MSG_4, &buffer, &buffer_sz);
  
    message_4 = buffer;
    message_4_len = length;
  
    write_cbor_array_to_file_HEX(buffer, length, 7, filepath);
  
    write_cbor_array_to_file_RAW(buffer, length, 7, filepath);
  
    printf("\nmessage_%d msg_type: %d", 4, 7);
    print_cbor_array_to_stdout(buffer, length);




	//unsigned char *aad_4_hash = hash_aad(AAD_3, MSG_TYPE);

/*
	EVP_PKEY *session_pkey = NULL;
	FILE *keyfile_pu = fopen("./input_parameters/server_PUBKEY.txt", "r");
	PEM_read_PUBKEY(keyfile_pu, &session_pkey, NULL, NULL);
	FILE *keyfile_pr = fopen("./input_parameters/server_PrivateKey.txt", "r");
	PEM_read_PrivateKey(keyfile_pr, &session_pkey, NULL, NULL);
	fclose(keyfile_pu);
	fclose(keyfile_pr);


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
    unsigned char *aad_hash = aad_4;
    ext_aad = cbor_build_bytestring(aad_hash, AAD_HASH_SZ);
    if (!cbor_array_push(ENC_STRUCT, ext_aad))
    {
		printf("\ncbor_array_push ext_aad FAILED.\n");
    }
	unsigned char *enc_struct_buffer;
	size_t enc_struct_buffer_sz, length = cbor_serialize_alloc(ENC_STRUCT, &enc_struct_buffer, &enc_struct_buffer_sz);
*/
	/*
    * Generate K_i and IV for decryption
    */
/*
    unsigned char *k_i = gen_K_i(aad_3_hash, session_pkey, MSG_TYPE, (unsigned char *)"", (unsigned char *   )"SERVER");
      unsigned char *iv = gen_K_i(aad_3_hash, session_pkey, MSG_TYPE, (unsigned char *)"IV-GENERATION",        (unsigned char *)"SERVER");
*/
    /*
    * Decryption
    */
/*
    unsigned char *plaintext = malloc(ciphertext_with_tag_len - AES_CCM_64_64_128_tag_sz);
    //printf("T A G: %s", tag);
    //printf("CIPHERTEXT WITHOUT TAG LEN: %d", ciphertext_without_tag_len);
    printf("\nTAG used for decryption: %s \n", tag);
	printf("CIPHERTEXT: %d \n %s", ciphertext_without_tag_len, ciphertext);
    int dec_ciphertext_len = decrypt_ccm(ciphertext, ciphertext_without_tag_len, enc_struct_buffer, enc_struct_buffer_sz, tag, k_i, iv, plaintext);
*/

	return 0;
}


/* 
 * Unified msg generation (old version)
 */
//unsigned char *cbor_array(int msg_type, unsigned char app_i[], size_t app_i_sz, EVP_PKEY *pkey)
//{
//    printf("\n#### GENERATING MSG_%d ####\n", get_msg_num(msg_type));
//
//    cbor_item_t *MSG = cbor_new_indefinite_array();
//    if (!CBOR_ITEM_T_init(MSG))
//    {
//        printf("\ncbor_item_t initialization FAILED.\n");
//    }
//
//    if (msg_type == EDHOC_SYM_MSG_1)
//    {
//        cbor_item_t *MSG_TYPE = cbor_new_int8();
//        MSG_TYPE = cbor_build_uint8(msg_type);
//        if (!cbor_array_push(MSG, MSG_TYPE))
//        {
//            printf("\ncbor_array_push MSG_TYPE FAILED.\n");
//        }
//
//        cbor_item_t *S_U = cbor_new_definite_bytestring();
//        size_t variable_length = rand() % (S_ID_MAX_SIZE + 1 - S_ID_MIN_SIZE) + S_ID_MIN_SIZE;
//        unsigned char *bstr_s_u = gen_random_S_ID(variable_length);
//        S_U = cbor_build_bytestring(bstr_s_u, variable_length);
//        if (!cbor_array_push(MSG, S_U))
//        {
//            printf("\ncbor_array_push S_U FAILED.\n");
//        }
//
//        cbor_item_t *N_U = cbor_new_definite_bytestring();
//        ASN1_INTEGER *nonce_asn1 = create_nonce(NONCE_size_bits);
//        BIGNUM *bn = ASN1_INTEGER_to_BN(nonce_asn1, NULL);
//        unsigned char *bstr_n_u = (unsigned char*)BN_bn2hex(bn);
//        N_U = cbor_build_bytestring(bstr_n_u, NONCE_size_bytes);
//        if (!cbor_array_push(MSG, N_U))
//        {
//            printf("\ncbor_array_push N_U FAILED.\n");
//        }
//
//        //cbor_item_t *E_U = cbor_new_definite_bytestring();
////      EVP_PKEY *pkey = get_x25519();
//        /* cbor map format */
//        cbor_item_t *E_U = cbor_new_definite_map(E_U_map_size);
//        int *bstr_e_u_sz = malloc(sizeof(int));
//        unsigned char *bstr_e_u = strip_pkey(pkey, bstr_e_u_sz);
//        cbor_item_t *key_1;
//        key_1 = cbor_new_int8();
//        cbor_mark_negint(key_1);
//        int abs_key_1 = abs(E_U_map_param_1 - 1);
//        cbor_set_uint8(key_1, abs_key_1);
//        cbor_map_add(E_U, (struct cbor_pair)
//        {
//            .key = cbor_move(key_1),
//            .value = cbor_move(cbor_build_uint8(X25519_OKP_value))
//        });
//        cbor_item_t *key_2;
//        key_2 = cbor_new_int8();
//        cbor_mark_negint(key_2);
//        int abs_key_2 = abs(E_U_map_param_2 - 1);
//        cbor_set_uint8(key_2, abs_key_2);
//        cbor_map_add(E_U, (struct cbor_pair)
//        {
//            .key = cbor_move(key_2),
//            .value = cbor_move(cbor_build_bytestring(bstr_e_u, *bstr_e_u_sz))
//        });
//        cbor_map_add(E_U, (struct cbor_pair)
//        {
//            .key = cbor_move(cbor_build_uint8(E_U_map_param_3)),
//            .value = cbor_move(cbor_build_uint8(COSE_key_object_type))
//        });
//        /* Bytestring version */
//        /*
//        int *bstr_e_u_sz = malloc(sizeof(int));
//        unsigned char *bstr_e_u = strip_pkey(pkey, bstr_e_u_sz);
//        E_U = cbor_build_bytestring(bstr_e_u, *bstr_e_u_sz);
//        */
//        if (!cbor_array_push(MSG, E_U))
//        {
//            printf("\ncbor_array_push E_U FAILED.\n");
//        }
//
//        cbor_item_t *ECDH_Curves_U = cbor_new_definite_array(ECDH_Curves_ARRAY);
//        for (int i = X25519; i <= X25519; i++)
//        {
//            cbor_item_t *alg = cbor_new_int8();
//            alg = cbor_build_uint8(i);
//            if (!cbor_array_push(ECDH_Curves_U, alg))
//            {
//                printf("\ncbor_array_push alg in ECDH_Curves array FAILED.\n");
//            }
//        }
//        if (!cbor_array_push(MSG, ECDH_Curves_U))
//        {
//            printf("\ncbor_array_push ECDH_Curves_U FAILED.\n");
//        }
//
//        /* Push only ONE supporting HKDF algorithm for now... */
//        cbor_item_t *HKDFs_U = cbor_new_definite_array(HKDFs_ARRAY);
//        /*
//        for (HKDF_algorithms i = ECDH_ES_HKDF_256; i >= ECDH_SS_HKDF_512; i--)
//        {
//            cbor_item_t *alg = cbor_new_int8();
//            int abs_i = abs(i);
//            alg = cbor_build_uint8(abs_i - 1);
//            cbor_mark_negint(alg);
//            if (!cbor_array_push(HKDFs, alg))
//            {
//                printf("\ncbor_array_push alg in HKDFs array FAILED.\n");
//            }
//        }
//        */
//        cbor_item_t *hkdf_alg = cbor_new_int8();
//        cbor_mark_negint(hkdf_alg);
//        int abs_i = abs(ECDH_SS_HKDF_256) - 1;
//        cbor_set_uint8(hkdf_alg, abs_i);
//        if (!cbor_array_push(HKDFs_U, hkdf_alg))
//        {
//            printf("\ncbor_array_push alg in HKDFs array FAILED.\n");
//        }
//        if (!cbor_array_push(MSG, HKDFs_U))
//        {
//            printf("\ncbor_array_push HKDFs_U FAILED.\n");
//        }
//
//        /* Push only ONE AEAD algorithm for now... */
//        cbor_item_t *AEADs_U = cbor_new_definite_array(AEADs_ARRAY);
//        /* BUG AFTER i = AES_CCM_64_64_128
//        for (AEAD_algorithms i = AES_CCM_16_64_128; i <= AES_CCM_64_128_256; i++)
//        {
//            cbor_item_t *alg = cbor_new_int8(i);
//            alg = cbor_build_uint8(i);
//            if (!cbor_array_push(AEADs, alg))
//            {
//                printf("\ncbor_array_push alg in AEADs array FAILED.\n");
//            }
//            //if (i == 14)
//            //{
//            //  i = 30;
//            //}
//        }
//        */
//        cbor_item_t *aead_alg = cbor_new_int8();
//        aead_alg = cbor_build_uint8(AES_CCM_64_64_128);
//        if (!cbor_array_push(AEADs_U, aead_alg))
//        {
//            printf("\ncbor_array_push alg in AEADs array FAILED.\n");
//        }
//        if (!cbor_array_push(MSG, AEADs_U))
//        {
//            printf("\ncbor_array_push AEADs_U FAILED.\n");
//        }
//
//        cbor_item_t *KID = cbor_new_definite_bytestring();
//        unsigned char kid[] = PRE_SHARED_KEY_ID;
//        KID = cbor_build_bytestring(kid, sizeof(kid));
//        if (!cbor_array_push(MSG, KID))
//        {
//            printf("\ncbor_array_push KID FAILED.\n");
//        }
//
//        if (app_i != NULL)
//        {
//            cbor_item_t *APP_1 = cbor_new_definite_bytestring();
//            APP_1 = cbor_build_bytestring(app_i, app_i_sz);
//            if (!cbor_array_push(MSG, APP_1))
//            {
//                printf("\ncbor_array_push APP_1 FAILED.\n");
//            }
//        }
//    }
//    else if (msg_type == EDHOC_SYM_MSG_2)
//    {
//        cbor_item_t *MSG_TYPE = cbor_new_int8();
//        MSG_TYPE = cbor_build_uint8(msg_type);
//        if (!cbor_array_push(MSG, MSG_TYPE))
//        {
//            printf("\ncbor_array_push MSG_TYPE FAILED.\n");
//        }
//
//        cbor_item_t *S_U = cbor_new_definite_bytestring();
//        //size_t variable_length = rand() % (S_ID_MAX_SIZE + 1 - S_ID_MIN_SIZE) + S_ID_MIN_SIZE;
//        //unsigned char *bstr_s_u = gen_random_S_ID(variable_length);
//        //S_U = cbor_build_bytestring(bstr_s_u, variable_length);
//        unsigned char s_id_party_U[] = S_ID_PARTY_U;
//        unsigned char *bstr_s_u = s_id_party_U;
//        S_U = cbor_build_bytestring(bstr_s_u, sizeof(S_ID_PARTY_U));
//        if (!cbor_array_push(MSG, S_U))
//        {
//            printf("\ncbor_array_push S_U FAILED.\n");
//        }
//
//        cbor_item_t *S_V = cbor_new_definite_bytestring();
//        size_t variable_length = rand() % (S_ID_MAX_SIZE + 1 - S_ID_MIN_SIZE) + S_ID_MIN_SIZE;
//        unsigned char *bstr_s_v = gen_random_S_ID(variable_length);
//        S_V = cbor_build_bytestring(bstr_s_v, variable_length);
//        if (!cbor_array_push(MSG, S_V))
//        {
//            printf("\ncbor_array_push S_V FAILED.\n");
//        }
//
//        cbor_item_t *N_V = cbor_new_definite_bytestring();
//        ASN1_INTEGER *nonce_asn1 = create_nonce(NONCE_size_bits);
//        BIGNUM *bn = ASN1_INTEGER_to_BN(nonce_asn1, NULL);
//        unsigned char *bstr_n_v = (unsigned char*)BN_bn2hex(bn);
//        N_V = cbor_build_bytestring(bstr_n_v, NONCE_size_bytes);
//        if (!cbor_array_push(MSG, N_V))
//        {
//            printf("\ncbor_array_push N_V FAILED.\n");
//        }
//
//        //cbor_item_t *E_U = cbor_new_definite_bytestring();
////      EVP_PKEY *pkey = get_x25519();
//        /* cbor map format */
//        cbor_item_t *E_V = cbor_new_definite_map(E_V_map_size);
//        int *bstr_e_v_sz = malloc(sizeof(int));
//        unsigned char *bstr_e_v = strip_pkey(pkey, bstr_e_v_sz);
//        cbor_item_t *key_1;
//        key_1 = cbor_new_int8();
//        cbor_mark_negint(key_1);
//        int abs_key_1 = abs(E_V_map_param_1 - 1);
//        cbor_set_uint8(key_1, abs_key_1);
//        cbor_map_add(E_V, (struct cbor_pair)
//        {
//            .key = cbor_move(key_1),
//            .value = cbor_move(cbor_build_uint8(X25519_OKP_value))
//        });
//        cbor_item_t *key_2;
//        key_2 = cbor_new_int8();
//        cbor_mark_negint(key_2);
//        int abs_key_2 = abs(E_V_map_param_2 - 1);
//        cbor_set_uint8(key_2, abs_key_2);
//        cbor_map_add(E_V, (struct cbor_pair)
//        {
//            .key = cbor_move(key_2),
//            .value = cbor_move(cbor_build_bytestring(bstr_e_v, *bstr_e_v_sz))
//        });
//        cbor_map_add(E_V, (struct cbor_pair)
//        {
//            .key = cbor_move(cbor_build_uint8(E_V_map_param_3)),
//            .value = cbor_move(cbor_build_uint8(COSE_key_object_type))
//        });
//        /* Bytestring version */
//        /*
//        int *bstr_e_u_sz = malloc(sizeof(int));
//        unsigned char *bstr_e_u = strip_pkey(pkey, bstr_e_u_sz);
//        E_U = cbor_build_bytestring(bstr_e_u, *bstr_e_u_sz);
//        */
//        if (!cbor_array_push(MSG, E_V))
//        {
//            printf("\ncbor_array_push E_V FAILED.\n");
//        }
//
//        /* ONLY for MSG_TYPE_1 */
//        /*
//        cbor_item_t *ECDH_Curves_U = cbor_new_definite_array(ECDH_Curves_ARRAY);
//        for (int i = X25519; i <= X25519; i++)
//        {
//            cbor_item_t *alg = cbor_new_int8();
//            alg = cbor_build_uint8(i);
//            if (!cbor_array_push(ECDH_Curves_U, alg))
//            {
//                printf("\ncbor_array_push alg in ECDH_Curves array FAILED.\n");
//            }
//        }
//        if (!cbor_array_push(MSG, ECDH_Curves_U))
//        {
//            printf("\ncbor_array_push ECDH_Curves_U FAILED.\n");
//        }
//        */
//
//        /* Push only ONE supporting HKDF algorithm for now... */
//        cbor_item_t *HKDFs_V = cbor_new_definite_array(HKDFs_ARRAY);
//        /*
//        for (HKDF_algorithms i = ECDH_ES_HKDF_256; i >= ECDH_SS_HKDF_512; i--)
//        {
//            cbor_item_t *alg = cbor_new_int8();
//            int abs_i = abs(i);
//            alg = cbor_build_uint8(abs_i - 1);
//            cbor_mark_negint(alg);
//            if (!cbor_array_push(HKDFs, alg))
//            {
//                printf("\ncbor_array_push alg in HKDFs array FAILED.\n");
//            }
//        }
//        */
//        cbor_item_t *hkdf_alg = cbor_new_int8();
//        cbor_mark_negint(hkdf_alg);
//        int abs_i = abs(ECDH_SS_HKDF_256) - 1;
//        cbor_set_uint8(hkdf_alg, abs_i);
//        if (!cbor_array_push(HKDFs_V, hkdf_alg))
//        {
//            printf("\ncbor_array_push alg in HKDFs array FAILED.\n");
//        }
//        if (!cbor_array_push(MSG, HKDFs_V))
//        {
//            printf("\ncbor_array_push HKDFs_V FAILED.\n");
//        }
//
//        /* Push only ONE AEAD algorithm for now... */
//        cbor_item_t *AEADs_V = cbor_new_definite_array(AEADs_ARRAY);
//        /* BUG AFTER i = AES_CCM_64_64_128
//        for (AEAD_algorithms i = AES_CCM_16_64_128; i <= AES_CCM_64_128_256; i++)
//        {
//            cbor_item_t *alg = cbor_new_int8(i);
//            alg = cbor_build_uint8(i);
//            if (!cbor_array_push(AEADs, alg))
//            {
//                printf("\ncbor_array_push alg in AEADs array FAILED.\n");
//            }
//            //if (i == 14)
//            //{
//            //  i = 30;
//            //}
//        }
//        */
//        cbor_item_t *aead_alg = cbor_new_int8();
//        aead_alg = cbor_build_uint8(AES_CCM_64_64_128);
//        if (!cbor_array_push(AEADs_V, aead_alg))
//        {
//            printf("\ncbor_array_push alg in AEADs array FAILED.\n");
//        }
//        if (!cbor_array_push(MSG, AEADs_V))
//        {
//            printf("\ncbor_array_push AEADs_V FAILED.\n");
//        }
//
//        unsigned char *buffer;
//        size_t buffer_sz, length = cbor_serialize_alloc(MSG, &buffer, &buffer_sz);
//
//        unsigned char *data_2 = buffer;
//        size_t data_2_len = length;
//        printf("\ndata_2 (size = %zu):", data_2_len);
//        print_cbor_array_to_stdout(data_2, data_2_len);
//
//        printf("\nmessage_1 (size = %zu):", message_1_len);
//        print_cbor_array_to_stdout(message_1, message_1_len);
//
//        size_t aad_2_sz = message_1_len + data_2_len;
//        printf("\nSize of (message_1 | data_2) = %zu\n", aad_2_sz);
//
//        unsigned char *aad_2 = malloc(message_1_len + data_2_len + 1);
//        memcpy(aad_2, message_1, message_1_len);
//        memcpy(aad_2 + message_1_len, data_2, data_2_len + 1);
//        printf("\naad_2 (size = %zu):", aad_2_sz);
//        print_cbor_array_to_stdout(aad_2, aad_2_sz);
//        
//		cbor_item_t *AAD_2 = cbor_new_definite_bytestring();
//        AAD_2 = cbor_build_bytestring(aad_2, aad_2_sz);
//
//        cbor_item_t *APP_2;
//        if (app_i != NULL)
//        {
//            APP_2 = cbor_new_definite_bytestring();
//            APP_2 = cbor_build_bytestring(app_i, app_i_sz);
//            //if (!cbor_array_push(MSG, APP_2))
//            //{
//            //  printf("\ncbor_array_push APP_2 FAILED.\n");
//            //}
//        }
//        else
//        {
//            APP_2 = NULL;
//        }
//
//        //cbor_item_t *COSE_ENC_2 = cbor_new_definite_array(COSE_ENC_2_SIZE);
//        //COSE_ENC_2 = cose_enc_i(AAD_2, APP_2, pkey, msg_type);
//        cbor_item_t *COSE_ENC_2 = cose_enc_i(AAD_2, APP_2, pkey, msg_type);
//        //COSE_ENC_2 = cbor_build_bytestring(cose_enc_2, sizeof(cose_enc_2));
//        if (!cbor_array_push(MSG, COSE_ENC_2))
//        {
//            printf("\ncbor_array_push COSE_ENC_2 FAILED.\n");
//        }
//	}
//    else if (msg_type == EDHOC_SYM_MSG_3)
//    {
//
//    }
//    else
//    {
//        printf("\nSet EDHOC mode. [1][2][3][4][5][6]\n");
//    }
//
//    unsigned char *buffer;
//    size_t buffer_sz, length = cbor_serialize_alloc(MSG, &buffer, &buffer_sz);
//
//    if (msg_type == EDHOC_SYM_MSG_1)
//    {
//        message_1 = buffer;
//        message_1_len = length;
//    }
//    if (msg_type == EDHOC_SYM_MSG_2)
//    {
//        message_2 = buffer;
//        message_2_len = length;
//    }
//    if (msg_type == EDHOC_SYM_MSG_3)
//    {
//        message_3 = buffer;
//        message_3_len = length;
//    }
//
//    write_cbor_array_to_file_HEX(buffer, length);
//
//    write_cbor_array_to_file_BINARY(buffer, length);
//
//    printf("\nmessage_%d msg_type: %d", get_msg_num(msg_type), msg_type);
//    print_cbor_array_to_stdout(buffer, length);
//
//    return buffer;
//}


int get_msg_num(int msg_type)
{
    if (msg_type < 4)
    {
        return msg_type;
    }
    else
    {
        return msg_type - 3;
    }
}


struct msg_1_data
{
    uint8_t MSG_TYPE;
    unsigned char *S_U;
    unsigned char * N_U;
    uint8_t E_U_param_1;
    unsigned char *E_U_param_2;
    uint8_t E_U_param_3;
    uint8_t ECDH_Curves_U;
    int8_t HKDFs_U;
    uint8_t AEADs_U;
    unsigned char *KID;
    unsigned char *APP_1;
};


struct msg_2_data
{
	uint8_t MSG_TYPE;
    unsigned char *S_U;
    unsigned char *S_V;
    unsigned char * N_V;
    unsigned char *E_V;
    uint8_t E_V_param_1;
    unsigned char *E_V_param_2;
    uint8_t E_V_param_3;
    int8_t HKDFs_V;
    uint8_t AEADs_V;
    cbor_item_t *COSE_ENC_2;
    unsigned char *APP_2;
};


struct msg_3_data
{
	uint8_t MSG_TYPE;
    unsigned char *S_V;
    cbor_item_t *COSE_ENC_3;
	unsigned char *APP_3;
};


struct msg_4_data
{
	//uint8_t MSG_TYPE;
    //unsigned char *S_V;
    cbor_item_t *COSE_ENC_4;
	cbor_item_t *S_U;
	unsigned char *APP_3;
};


void *parse_edhoc_sym_msg_1(cbor_item_t *MSG)
{
	printf("\n#### PARSING EDHOC MESSAGE 1 ####\n");

    cbor_item_t *msg_type;
    msg_type = cbor_array_get(MSG, 0);
    uint8_t MSG_TYPE = cbor_get_uint8(msg_type);
    MSG_1.MSG_TYPE = MSG_TYPE;

    cbor_item_t *s_u;
    s_u = cbor_array_get(MSG, 1);
    size_t S_U_length = cbor_bytestring_length(s_u);
    unsigned char *S_U = cbor_bytestring_handle(s_u);
    MSG_1.S_U = S_U;

    cbor_item_t *n_u;
    n_u = cbor_array_get(MSG, 2);
    size_t N_U_length = cbor_bytestring_length(n_u);
    unsigned char *N_U = cbor_bytestring_handle(n_u);
    MSG_1.N_U = N_U;

    cbor_item_t *e_u;
    e_u = cbor_array_get(MSG, 3);
	struct cbor_pair *e_u_map_pairs = cbor_map_handle(e_u);
	cbor_item_t *crv = cbor_move(e_u_map_pairs[0].value);
	cbor_item_t *ephemeral_key = cbor_move(e_u_map_pairs[1].value);
	size_t ephemeral_key_sz = cbor_map_allocated(e_u_map_pairs[1].value);
	cbor_item_t *kty = cbor_move(e_u_map_pairs[2].value);
	MSG_1.E_U_param_1 = cbor_get_uint8(crv);
	MSG_1.E_U_param_2 = cbor_bytestring_handle(ephemeral_key);
	MSG_1.E_U_param_3 = cbor_get_uint8(kty);

	/*
	 * Retrieve the other Party's PUBKEY
	 */
	const char *filepath = "./edhoc_server_INBOX/client_PUBKEY.txt";
	unsigned char *key_pem_format = key_add_headers(MSG_1.E_U_param_2, ephemeral_key_sz, filepath);

    cbor_item_t *ecdh_curves_u;
    ecdh_curves_u = cbor_array_get(MSG, 4);
    uint8_t ECDH_Curves_U = cbor_get_uint8(cbor_array_get(ecdh_curves_u, 0));
    MSG_1.ECDH_Curves_U = ECDH_Curves_U;

    cbor_item_t *hkdfs_u;
    hkdfs_u = cbor_array_get(MSG, 5);
    int8_t HKDFs_U = cbor_get_uint8(cbor_array_get(hkdfs_u, 0));
    HKDFs_U = -HKDFs_U - 1;
    MSG_1.HKDFs_U = HKDFs_U;

    cbor_item_t *aeads_u;
    aeads_u = cbor_array_get(MSG, 6);
    uint8_t AEADs_U = cbor_get_uint8(cbor_array_get(aeads_u, 0));
    MSG_1.AEADs_U = AEADs_U;

    cbor_item_t *kid;
    kid = cbor_array_get(MSG, 7);
    size_t KID_length = cbor_bytestring_length(kid);
    unsigned char *KID = cbor_bytestring_handle(kid);
    MSG_1.KID = KID;

    cbor_item_t *app_1;
	unsigned char *APP_1 = NULL;
	size_t APP_1_length;
	if (cbor_array_size(MSG) == 9)
	{
		app_1 = cbor_array_get(MSG, 8);
		APP_1_length = cbor_bytestring_length(app_1);
		APP_1 = cbor_bytestring_handle(app_1);
		MSG_1.APP_1 = APP_1;
	}

    printf("\n-----BEGIN EDHOC MESSAGE DESCRIPTION-----\n");
    printf("   MSG_TYPE : %d",MSG_TYPE);
    printf("\n   S_U : ");
    print_cbor_bytestring_to_stdout(S_U, S_U_length);
    printf("\n   N_U : ");
    print_cbor_bytestring_to_stdout(N_U, N_U_length);
    printf("\n   E_U : ");
	printf("Param_1= %d ", MSG_1.E_U_param_1);
	printf("Param_2= ");
	print_cbor_bytestring_to_stdout_hex(MSG_1.E_U_param_2, ephemeral_key_sz);
	printf(" Param_3= %d", MSG_1.E_U_param_3);
    printf("\n   ECDH-Curves_U : %d", ECDH_Curves_U);
    printf("\n   HKDFs_U : %d",HKDFs_U);
    printf("\n   AEADs_U : %d", AEADs_U);
    printf("\n   KID : ");
    print_cbor_bytestring_to_stdout(KID, KID_length);
    if (APP_1 != NULL)
    {
		printf("\n   APP_1 : ");
        print_cbor_bytestring_to_stdout(APP_1, APP_1_length);
    }
    else
    {
        printf("\n   APP_1 : NULL (No data transmited)");
    }
    printf("\n-----END EDHOC MESSAGE DESCRIPTION-----\n");

	printf("\n#### END OF PARSING EDHOC MESSAGE 1 ####\n");
    
	return 0;
}


void *parse_edhoc_sym_msg_2(cbor_item_t *MSG)
{
	printf("\n#### PARSING EDHOC MESSAGE 2 ####\n");
    
	cbor_item_t *msg_type;
    msg_type = cbor_array_get(MSG, 0);
    uint8_t MSG_TYPE = cbor_get_uint8(msg_type);
    MSG_2.MSG_TYPE = MSG_TYPE;

    cbor_item_t *s_u;
    s_u = cbor_array_get(MSG, 1);
    size_t S_U_length = cbor_bytestring_length(s_u);
    unsigned char *S_U = cbor_bytestring_handle(s_u);
    MSG_2.S_U = S_U;
    
	cbor_item_t *s_v;
    s_v = cbor_array_get(MSG, 2);
    size_t S_V_length = cbor_bytestring_length(s_v);
    unsigned char *S_V = cbor_bytestring_handle(s_v);
    MSG_2.S_V = S_V;

    cbor_item_t *n_v;
    n_v = cbor_array_get(MSG, 3);
    size_t N_V_length = cbor_bytestring_length(n_v);
    unsigned char *N_V = cbor_bytestring_handle(n_v);
    MSG_2.N_V = N_V;

    cbor_item_t *e_v;
    e_v = cbor_array_get(MSG, 4);
	struct cbor_pair *e_v_map_pairs = cbor_map_handle(e_v);
	cbor_item_t *crv = cbor_move(e_v_map_pairs[0].value);
	cbor_item_t *ephemeral_key = cbor_move(e_v_map_pairs[1].value);
	size_t ephemeral_key_sz = cbor_map_allocated(e_v_map_pairs[1].value);
	cbor_item_t *kty = cbor_move(e_v_map_pairs[2].value);
	MSG_2.E_V_param_1 = cbor_get_uint8(crv);
	MSG_2.E_V_param_2 = cbor_bytestring_handle(ephemeral_key);
	MSG_2.E_V_param_3 = cbor_get_uint8(kty);

	/*
	 * Retrieve the other Party's PUBKEY
	 */
	const char *filepath = "./edhoc_client_INBOX/server_PUBKEY.txt";
	unsigned char *key_pem_format = key_add_headers(MSG_2.E_V_param_2, ephemeral_key_sz, filepath);

    cbor_item_t *hkdfs_v;
    hkdfs_v = cbor_array_get(MSG, 5);
    int8_t HKDFs_V = cbor_get_uint8(cbor_array_get(hkdfs_v, 0));
    HKDFs_V = -HKDFs_V - 1;
    MSG_2.HKDFs_V = HKDFs_V;

    cbor_item_t *aeads_v;
    aeads_v = cbor_array_get(MSG, 6);
    uint8_t AEADs_V = cbor_get_uint8(cbor_array_get(aeads_v, 0));
    MSG_2.AEADs_V = AEADs_V;

	cbor_item_t *cose_enc_2;
	cose_enc_2 = cbor_array_get(MSG, 7);
	MSG_2.COSE_ENC_2 = cose_enc_2;
	
	/*
	 * Separate tag from ciphertext
	 */
	unsigned char *ciphertext_with_tag = cbor_bytestring_handle(cbor_array_get(MSG_2.COSE_ENC_2, 2));
	size_t ciphertext_with_tag_len = cbor_bytestring_length(cbor_array_get(MSG_2.COSE_ENC_2, 2));
	unsigned char *ciphertext = malloc(ciphertext_with_tag_len - AES_CCM_64_64_128_tag_sz); 
	memcpy(ciphertext, ciphertext_with_tag, ciphertext_with_tag_len - AES_CCM_64_64_128_tag_sz);
	unsigned char *tag = malloc(AES_CCM_64_64_128_tag_sz);
	memcpy(tag, ciphertext_with_tag + ciphertext_with_tag_len - AES_CCM_64_64_128_tag_sz, AES_CCM_64_64_128_tag_sz);
	
	/*
	 * Create data_2 for AAD_2
	 */
	cbor_item_t *message_2_data = cbor_new_indefinite_array();
	cbor_array_push(message_2_data, msg_type);
	cbor_array_push(message_2_data, s_u);
	cbor_array_push(message_2_data, s_v);
	cbor_array_push(message_2_data, n_v);
	cbor_array_push(message_2_data, e_v);
	cbor_array_push(message_2_data, hkdfs_v);
	cbor_array_push(message_2_data, aeads_v);
	unsigned char *buffer_data_2;
	size_t buffer_data_2_sz, length_data_2 = cbor_serialize_alloc(message_2_data, &buffer_data_2, &buffer_data_2_sz);
	unsigned char *aad_2 = malloc(message_1_len + length_data_2 + 1);
	memcpy(aad_2, message_1, message_1_len);
	memcpy(aad_2 + message_1_len, buffer_data_2, length_data_2 + 1);
	size_t aad_2_sz = message_1_len + length_data_2;
	cbor_item_t *AAD_2 = cbor_build_bytestring(aad_2, aad_2_sz);
	/*
	 * Hash AAD_2
	 */
	unsigned char *aad_2_hash = hash_aad(AAD_2, MSG_TYPE);
	
	/*
	 * Import our session pkey
	 */
	EVP_PKEY *session_pkey = NULL;
	FILE *keyfile_pu = fopen("./input_parameters/client_PUBKEY.txt", "r");
	PEM_read_PUBKEY(keyfile_pu, &session_pkey, NULL, NULL);
	FILE *keyfile_pr = fopen("./input_parameters/client_PrivateKey.txt", "r");
	PEM_read_PrivateKey(keyfile_pr, &session_pkey, NULL, NULL);
	fclose(keyfile_pu);
	fclose(keyfile_pr);

	/*
	 * Create COSE Enc_structure to produce the AAD used for decryption
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
    unsigned char *aad_hash = aad_2_hash;
    ext_aad = cbor_build_bytestring(aad_hash, AAD_HASH_SZ);
    if (!cbor_array_push(ENC_STRUCT, ext_aad))
    {   
        printf("\ncbor_array_push ext_aad FAILED.\n");
    } 
    unsigned char *enc_struct_buffer;
    size_t enc_struct_buffer_sz, length = cbor_serialize_alloc(ENC_STRUCT, &enc_struct_buffer, &enc_struct_buffer_sz);

	/*
	 * Generate K_i and IV for decryption
	 */
	unsigned char *k_i = gen_K_i(aad_2_hash, session_pkey, MSG_TYPE, (unsigned char *)"", (unsigned char *)"CLIENT");
	unsigned char *iv = gen_K_i(aad_2_hash, session_pkey, MSG_TYPE, (unsigned char *)"IV-GENERATION", (unsigned char *)"CLIENT");

	/*
	 * Decryption
	 */
	//printf("DEBUG !!!!!!!!!");
	//printf("%d - %d - %d", enc_struct_buffer_sz, length, ciphertext_with_tag_len);
	//fflush(stdout);
	unsigned char *plaintext = malloc(ciphertext_with_tag_len); //= malloc(ciphertext_with_tag_len + 1);
	int dec_ciphertext_len = decrypt_ccm(ciphertext, ciphertext_with_tag_len - AES_CCM_64_64_128_tag_sz, enc_struct_buffer, enc_struct_buffer_sz, tag, k_i, iv, plaintext);

    printf("\n-----BEGIN EDHOC MESSAGE DESCRIPTION-----\n");
    printf("   MSG_TYPE : %d",MSG_TYPE);
    printf("\n   S_U : ");
    print_cbor_bytestring_to_stdout(S_U, S_U_length);
    printf("\n   S_V : ");
    print_cbor_bytestring_to_stdout(S_V, S_V_length);
    printf("\n   N_V : ");
    print_cbor_bytestring_to_stdout(N_V, N_V_length);
    printf("\n   E_V : ");
	printf("Param_1= %d ", MSG_2.E_V_param_1);
	printf("Param_2= ");
	print_cbor_bytestring_to_stdout_hex(MSG_2.E_V_param_2, ephemeral_key_sz);
	printf(" Param_3= %d", MSG_2.E_V_param_3);
    printf("\n   HKDFs_U : %d",HKDFs_V);
    printf("\n   AEADs_U : %d", AEADs_V);
	printf("\n   CIPHERTEXT len: %d", dec_ciphertext_len);
	printf("\n   DECRYPTED APP_2:\n");
	print_bytes(plaintext, dec_ciphertext_len);
    printf("\n-----END EDHOC MESSAGE DESCRIPTION-----\n");

	printf("\n#### END OF PARSING EDHOC MESSAGE 2 ####\n");
    
	return 0;
}


PKCS7 *parse_edhoc_sym_msg_3(cbor_item_t *MSG)
{
	printf("\n#### PARSING EDHOC MESSAGE 3 ####\n");
    
	cbor_item_t *msg_type;
    msg_type = cbor_array_get(MSG, 0);
    uint8_t MSG_TYPE = cbor_get_uint8(msg_type);
    MSG_3.MSG_TYPE = MSG_TYPE;

	cbor_item_t *s_v;
    s_v = cbor_array_get(MSG, 1);
    size_t S_V_length = cbor_bytestring_length(s_v);
    unsigned char *S_V = cbor_bytestring_handle(s_v);
    MSG_3.S_V = S_V;

	cbor_item_t *cose_enc_3;
	MSG_3.COSE_ENC_3 = cbor_array_get(MSG, 2);

    /*   
     * Separate tag from ciphertext
     */
    unsigned char *ciphertext_with_tag = cbor_bytestring_handle(cbor_array_get(MSG_3.COSE_ENC_3, 2));
	//printf("HERE: %s", ciphertext_with_tag);
    size_t ciphertext_with_tag_len = cbor_bytestring_length(cbor_array_get(MSG_3.COSE_ENC_3, 2));    
	//printf("CIPHERTEXT WITH TAG LEN: %d", ciphertext_with_tag_len);
	unsigned char *ciphertext = malloc(ciphertext_with_tag_len - AES_CCM_64_64_128_tag_sz);
	size_t ciphertext_without_tag_len = ciphertext_with_tag_len - AES_CCM_64_64_128_tag_sz;
	//printf("CIPHERTEXT WITHOUT TAG LEN %d", ciphertext_without_tag_len);
    memcpy(ciphertext, ciphertext_with_tag, ciphertext_without_tag_len);
    unsigned char *tag = malloc(AES_CCM_64_64_128_tag_sz);
    memcpy(tag, ciphertext_with_tag + ciphertext_with_tag_len - AES_CCM_64_64_128_tag_sz, AES_CCM_64_64_128_tag_sz);
	//printf("TAG LEN: %s", tag);
	//printf("WITH TAG>>>>>: %s", &ciphertext_with_tag[630]);
	//printf(ciphertext_with_tag[663]);
	//printf(ciphertext_with_tag[663]);
	//printf(ciphertext_with_tag[663]);
	//printf(ciphertext_with_tag[663]);
	//printf(ciphertext_with_tag[663]);
    
    /*
     * Create data_3 for AAD_3
     */  
    cbor_item_t *message_3_data = cbor_new_indefinite_array();
    cbor_array_push(message_3_data, msg_type);
    cbor_array_push(message_3_data, s_v);
    unsigned char *buffer_data_3;
    size_t buffer_data_3_sz, data_3_length = cbor_serialize_alloc(message_3_data, &buffer_data_3, &buffer_data_3_sz);
    
	message_1 = import_msg("./edhoc_server_INBOX/edhoc_sym_msg1_RAW.txt", &message_1_len);
	//message_2 = import_msg("./edhoc_server_INBOX/edhoc_sym_msg1_RAW.txt", &message_2_len);
		
	//unsigned char *aad_3 = malloc(message_1_len + message_2_len + data_3_length + 1);
	unsigned char *msg_1_msg_2 = malloc(message_1_len + message_2_len);
    memcpy(msg_1_msg_2, message_1, message_1_len);
    memcpy(msg_1_msg_2 + message_1_len, message_2, message_2_len + 1);
	size_t msg_1_msg_2_len = message_1_len + message_2_len;
	cbor_item_t *MSG_1_MSG_2 = cbor_new_definite_bytestring();
	MSG_1_MSG_2 = cbor_build_bytestring(msg_1_msg_2, msg_1_msg_2_len);
	//memcpy(aad_3 + message_1_len + message_2_len, buffer_data_3, buffer_data_3_sz);
   
	unsigned char *msg_1_msg_2_hash = hash_aad(MSG_1_MSG_2, MSG_TYPE);
	//msg_1_msg_2_hash_len = strlen();


	unsigned char *msg_1_msg_2_data_3 = malloc(AAD_HASH_SZ + data_3_length);
	memcpy(msg_1_msg_2_data_3, msg_1_msg_2_hash, AAD_HASH_SZ);
	memcpy(msg_1_msg_2_data_3 + AAD_HASH_SZ, buffer_data_3, data_3_length);
	//memcpy(msg_1_msg_2_data_3 + message_1_len + message_2_len, buffer_data_3, buffer_data_3_sz);
	cbor_item_t *MSG_1_MSG_2_DATA_3 = cbor_new_definite_bytestring();
	MSG_1_MSG_2_DATA_3 = cbor_build_bytestring(msg_1_msg_2_data_3, AAD_HASH_SZ + data_3_length);
	unsigned char *msg_1_msg_2_data3_hash = hash_aad(MSG_1_MSG_2_DATA_3, MSG_TYPE);
	//size_t msg_1_msg_2_hash_len = strlen((const char *)msg_1_msg_2_hash);

	//size_t aad_3_sz = msg_1_msg_2_hash_len + data_3_length;
	//printf("\nSize of H(H(message_1 | message_2) | data_3) = %zu\n", aad_3_sz);
	
	unsigned char *aad_3 = malloc(AAD_HASH_SZ + data_3_length + 1);
	memcpy(aad_3, msg_1_msg_2_hash, AAD_HASH_SZ);
	memcpy(aad_3 + AAD_HASH_SZ, buffer_data_3, data_3_length + 1);
	//size_t aad_3_hash_sz = AAD_HASH_SZ + 

	cbor_item_t *AAD_3 = cbor_new_definite_bytestring();
	AAD_3 = cbor_build_bytestring(aad_3, AAD_HASH_SZ + data_3_length);

	unsigned char *aad_3_hash = hash_aad(AAD_3, MSG_TYPE);
	
	//size_t aad_3_sz = message_1_len + message_2_len;
    //cbor_item_t *AAD_2 = cbor_build_bytestring(aad_2, aad_2_sz);

    /*   
     * Hash AAD_3
     */  
    //unsigned char *aad_3_hash = hash_aad(AAD_3, MSG_TYPE);
    
    /*   
     * Import our session pkey
     */  
    EVP_PKEY *session_pkey = NULL;
    FILE *keyfile_pu = fopen("./input_parameters/server_PUBKEY.txt", "r");
    PEM_read_PUBKEY(keyfile_pu, &session_pkey, NULL, NULL);
    FILE *keyfile_pr = fopen("./input_parameters/server_PrivateKey.txt", "r");
    PEM_read_PrivateKey(keyfile_pr, &session_pkey, NULL, NULL);
    fclose(keyfile_pu);
    fclose(keyfile_pr);
    
	/*   
     * Create COSE Enc_structure to produce the AAD used for decryption
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
    unsigned char *aad_hash = aad_3_hash;
    ext_aad = cbor_build_bytestring(aad_hash, AAD_HASH_SZ);
    if (!cbor_array_push(ENC_STRUCT, ext_aad))
    {    
        printf("\ncbor_array_push ext_aad FAILED.\n");
    }    
    unsigned char *enc_struct_buffer;
    size_t enc_struct_buffer_sz, length = cbor_serialize_alloc(ENC_STRUCT, &enc_struct_buffer, &enc_struct_buffer_sz);
  
    /*   
     * Generate K_i and IV for decryption
     */
    unsigned char *k_i = gen_K_i(aad_3_hash, session_pkey, MSG_TYPE, (unsigned char *)"", (unsigned char *)"SERVER");
    unsigned char *iv = gen_K_i(aad_3_hash, session_pkey, MSG_TYPE, (unsigned char *)"IV-GENERATION", (unsigned char *)"SERVER");
  
    /*   
     * Decryption
	 */
    unsigned char *plaintext = malloc(ciphertext_with_tag_len - AES_CCM_64_64_128_tag_sz);
	//printf("T A G: %s", tag);
	//printf("CIPHERTEXT WITHOUT TAG LEN: %d", ciphertext_without_tag_len);
	//printf("\nTAG used for decryption: %s \n", tag);
	printf("\nTAG used for decryption:\n");
	print_bytes(tag, AES_CCM_64_64_128_tag_sz);
	//printf("CIPHERTEXT: %d \n %s", ciphertext_without_tag_len, ciphertext);
	printf("CIPHERTEXT:\n");
	print_bytes(ciphertext, ciphertext_without_tag_len);
    int dec_ciphertext_len = decrypt_ccm(ciphertext, ciphertext_without_tag_len, enc_struct_buffer, enc_struct_buffer_sz, tag, k_i, iv, plaintext);


	
    //unsigned char *x509_der_buf = cbor_bytestring_handle(plaintext);
	
	unsigned char *x509_der = malloc(dec_ciphertext_len);

	memcpy(x509_der, plaintext + 3, dec_ciphertext_len - 3);

	//printf("X509 DER: \n %s", plaintext);
	// printf("\n---------------------\n");
    //    for (int i = 0; i < 659; i++)
    //    {
    //        printf("%x ", x509_der[i]);
   
   //     }
    //    printf("\n---------------------\n");

	X509_REQ *x509_req;
	x509_req = NULL;
	//x509_der = plaintext;
	
	x509_req = d2i_X509_REQ(NULL, &x509_der, dec_ciphertext_len - 3);

	if (x509_req == NULL)
	{
		printf("\nX509 REQ is NULL\n");
	}
	//unsigned char *p;

	//int len;

	/* Something to setup buf and len */

	//p = plaintext;

 /* Set up buf and len to point to the input buffer. */
     /* error */

	//d2i_X509_REQ(&x509_req, (const unsigned char **)&plaintext, dec_ciphertext_len);
	//if (x509_req == NULL)
	//{
	//	printf("\nX509 REQ is NULL\n");
	//}
	//{
	//	printf("\n\nERRRRROOOOOR\n\n");
	//}
	//if (x509_req == NULL)
	//{
	//	printf("\nERROR");
	//}

	//if (x == NULL)
    /* Some error */

	//x509_req = d2i(plaintext, dec_ciphertext_len);
	//FILE *out;
    //out = fopen("./CSR-server.pem", "w+");
    //PEM_write_X509_REQ(out, x509_req);
    //fflush(out);
    //fclose(out);

	//SIGN CSR
	//sign_csr(plaintext, dec_ciphertext_len);
	//X509_REQ *x509; 
	//d2i_X509_REQ(x509, plaintext, dec_ciphertext_len);
	//FILE *out;
	//out = fopen("./csr-test.pem", "wb");
	//PEM_write_X509_REQ(out, x509);
	//printf("TAG....... %s", tag);
	//printf("CIPHERTEXT LEN>>>>>>>>>>>>>>>> %d", ciphertext_with_tag_len - AES_CCM_64_64_128_tag_sz);
	//fflush(out);
	//fclose(out);
	//
    printf("\n-----BEGIN EDHOC MESSAGE DESCRIPTION-----\n");
    printf("   MSG_TYPE : %d",MSG_TYPE);
    printf("\n   S_V : ");
    print_cbor_bytestring_to_stdout(S_V, S_V_length);
	printf("\n   CIPHERTEXT len: %d", dec_ciphertext_len);
	printf("\n   DECRYPTED APP_3:\n");
	print_bytes(plaintext, dec_ciphertext_len);
    
    printf("\n-----END EDHOC MESSAGE DESCRIPTION-----\n");

	printf("\n#### END OF PARSING EDHOC MESSAGE 3 ####\n");
    
	//gen_msg_4_sym(x509_req);
	PKCS7 *cert = sign_CSR(x509_req);
	
	return cert;
}


void *parse_edhoc_sym_msg_4(cbor_item_t *MSG)
{
	printf("\n#### PARSING EDHOC MESSAGE 4 ####\n");
	
	cbor_item_t *s_u;
    s_u = cbor_array_get(MSG, 0);
    size_t S_U_length = cbor_bytestring_length(s_u);
    unsigned char *S_U = cbor_bytestring_handle(s_u);
	MSG_4.S_U = cbor_array_get(MSG, 0);
    
	cbor_item_t *COSE_ENC_4;
    MSG_4.COSE_ENC_4 = cbor_array_get(MSG, 1);
    
	/*   
    * Separate tag from ciphertext
    */
    unsigned char *ciphertext_with_tag = cbor_bytestring_handle(cbor_array_get(MSG_4.COSE_ENC_4, 2));
    //printf("HERE: %s", ciphertext_with_tag);
    size_t ciphertext_with_tag_len = cbor_bytestring_length(cbor_array_get(MSG_4.COSE_ENC_4, 2));
    //printf("CIPHERTEXT WITH TAG LEN: %d", ciphertext_with_tag_len);
    unsigned char *ciphertext = malloc(ciphertext_with_tag_len - AES_CCM_64_64_128_tag_sz);
    size_t ciphertext_without_tag_len = ciphertext_with_tag_len - AES_CCM_64_64_128_tag_sz;
    //printf("CIPHERTEXT WITHOUT TAG LEN %d", ciphertext_without_tag_len);
    memcpy(ciphertext, ciphertext_with_tag, ciphertext_without_tag_len);
    unsigned char *tag = malloc(AES_CCM_64_64_128_tag_sz);
    memcpy(tag, ciphertext_with_tag + ciphertext_with_tag_len - AES_CCM_64_64_128_tag_sz, AES_CCM_64_64_128_tag_sz);



	/*
    * Create data_4 for AAD_4
    */
	message_1 = import_msg("./edhoc_server_INBOX/edhoc_sym_msg1_RAW.txt", &message_1_len);
	message_2 = import_msg("./edhoc_client_INBOX/edhoc_sym_msg2_RAW.txt", &message_2_len);
	message_3 = import_msg("./edhoc_server_INBOX/edhoc_sym_msg3_RAW.txt", &message_3_len);

	unsigned char *msg1_msg2 = malloc(message_1_len + message_2_len);
	memcpy(msg1_msg2, message_1, message_1_len);
	memcpy(msg1_msg2 + message_1_len, message_2, message_2_len + 1);
	size_t msg1_msg2_len = message_1_len + message_2_len;

	cbor_item_t *MSG1_MSG2 = cbor_new_definite_bytestring();
	MSG1_MSG2 = cbor_build_bytestring(msg1_msg2, msg1_msg2_len);

	unsigned char *msg1_msg2_hash = hash_aad(MSG1_MSG2, 7);

	//cbor_item_t *

	unsigned char *msg1_msg2_msg3 = malloc(AAD_HASH_SZ + message_3_len);
	memcpy(msg1_msg2_msg3, msg1_msg2_hash, AAD_HASH_SZ);
	memcpy(msg1_msg2_msg3 + AAD_HASH_SZ, message_3, message_3_len);

	cbor_item_t *MSG1_MSG2_MSG3 = cbor_new_definite_bytestring();
	MSG1_MSG2_MSG3 = cbor_build_bytestring(msg1_msg2_msg3, AAD_HASH_SZ + message_3_len);

	printf("\naad_4 (size = %zu):", 12345);
	print_cbor_array_to_stdout(msg1_msg2_msg3, AAD_HASH_SZ + message_3_len);

	unsigned char *msg1_msg2_msg3_hash = hash_aad(MSG1_MSG2_MSG3, 7);

	unsigned char *aad_4 = malloc(AAD_HASH_SZ + message_3_len + 1);
	memcpy(aad_4, msg1_msg2_hash, AAD_HASH_SZ);
    memcpy(aad_4 + AAD_HASH_SZ, message_3, message_3_len + 1);

	cbor_item_t *AAD_4 = cbor_new_definite_bytestring();
    AAD_4 = cbor_build_bytestring(aad_4, AAD_HASH_SZ + message_3_len);

    unsigned char *aad_4_hash = hash_aad(AAD_4, 7);
	printf("AAD 4 with print bytes:\n");
	print_bytes(aad_4_hash, AAD_HASH_SZ);
	
	/*   
    * Import our session pkey
    */
    EVP_PKEY *session_pkey = NULL;
    FILE *keyfile_pu = fopen("./input_parameters/client_PUBKEY.txt", "r");
    PEM_read_PUBKEY(keyfile_pu, &session_pkey, NULL, NULL);
    FILE *keyfile_pr = fopen("./input_parameters/client_PrivateKey.txt", "r");
    PEM_read_PrivateKey(keyfile_pr, &session_pkey, NULL, NULL);
    fclose(keyfile_pu);
    fclose(keyfile_pr);

	/*   
    * Create COSE Enc_structure to produce the AAD used for decryption
    */
    cbor_item_t *ENC_STRUCT = NULL;
	ENC_STRUCT = cbor_new_definite_array(COSE_ENC_STRUCTURE_SZ);
  
    cbor_item_t *ctx_string = NULL;
	ctx_string = cbor_new_definite_string();
    ctx_string = cbor_build_string(ENC_STRUCT_CTX);
    if (!cbor_array_push(ENC_STRUCT, ctx_string))
    {
		printf("\ncbor_array_push ctx_string FAILED.\n");
    }
  
    cbor_item_t *protected_attr = NULL;
	protected_attr = cbor_new_definite_bytestring();
    unsigned char protected_attr_data[] = "";
    protected_attr = cbor_build_bytestring(protected_attr_data, ENC_STRUCT_PROTECTED_ATTR_SZ);
    if (!cbor_array_push(ENC_STRUCT, protected_attr))
    {
		printf("\ncbor_array_push protected_attr FAILED.\n");
    }
  
    cbor_item_t *ext_aad = cbor_new_definite_bytestring();
    unsigned char *aad_hash = aad_4_hash;
    ext_aad = cbor_build_bytestring(aad_hash, AAD_HASH_SZ);
    if (!cbor_array_push(ENC_STRUCT, ext_aad))
    {
		printf("\ncbor_array_push ext_aad FAILED.\n");
    }
    unsigned char *enc_struct_buffer = NULL;
	size_t enc_struct_buffer_sz, length = cbor_serialize_alloc(ENC_STRUCT, &enc_struct_buffer, &enc_struct_buffer_sz);
	print_bytes(aad_hash, enc_struct_buffer_sz);
	for (int i = 45; i < enc_struct_buffer_sz; i++)
	{
		enc_struct_buffer[i] = 0;
	}
	printf("\n Print bytes enc struct buffer:\n");
	print_bytes(enc_struct_buffer, enc_struct_buffer_sz);

    /*   
    * Generate K_i and IV for decryption
    */
    unsigned char *k_i = gen_K_i(aad_4_hash, session_pkey, 7, (unsigned char *)"", (unsigned char *   )"CLIENT");
    unsigned char *iv = gen_K_i(aad_4_hash, session_pkey, 7, (unsigned char *)"IV-GENERATION",      (unsigned char *)"CLIENT");
  
    /*   
    * Decryption
    */

	unsigned char *dec_tag = malloc(AES_CCM_64_64_128_tag_sz);
	memcpy(dec_tag, tag, AES_CCM_64_64_128_tag_sz);
	printf("DEC_TAG:\n");
	print_bytes(dec_tag, AES_CCM_64_64_128_tag_sz);
	//tag = "123456";
	//ciphertext = "ajkdhkahsdkhaskjdhkajsdhkashd";
	//k_i = "kadlajdlaldkja";

	//unsigned char *ciphertext_test = malloc(ciphertext_without_tag_len);
	//memcpy(ciphertext_test, ciphertext, ciphertext_with_tag_len);

    //unsigned char *plaintext = malloc(ciphertext_with_tag_len - AES_CCM_64_64_128_tag_sz);
    unsigned char *plaintext = malloc(ciphertext_without_tag_len);
    //unsigned char *plaintext = malloc(ciphertext_with_tag_len);
    //printf("T A G: %s", tag);
    //printf("CIPHERTEXT WITHOUT TAG LEN: %d", ciphertext_without_tag_len);
	//printf("\nENC STRUCT BUFFER AND >> SZ: %s %zu \n", enc_struct_buffer, enc_struct_buffer_sz);
    printf("\nTAG used for decryption:\n");
	print_bytes(dec_tag, AES_CCM_64_64_128_tag_sz);
	printf("CIPHERTEXT:\n");
	print_bytes(ciphertext, ciphertext_without_tag_len);
    int dec_ciphertext_len = decrypt_ccm(ciphertext, ciphertext_without_tag_len, enc_struct_buffer,   enc_struct_buffer_sz, dec_tag, k_i, iv, plaintext);

	printf("DECRYPTION STATUS = %d", dec_ciphertext_len);
	fflush(stdout);

	unsigned char *pkcs7_der = malloc(dec_ciphertext_len - 3);

	memcpy(pkcs7_der, plaintext + 3, dec_ciphertext_len -3);

	BIO *bio_out;
	bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);
	//PKCS7_print_ctx(bio_out, pkcs7_der, 0, NULL);
	
	//printf("PKCS7 INTERNAL: \n");
	//print_bytes(signed_cert, dec_ciphertext_len);
	





	PKCS7 *signed_cert = d2i_PKCS7(NULL, &pkcs7_der, dec_ciphertext_len - 3);
	PKCS7_print_ctx(bio_out, signed_cert, 0, NULL);
	
	//PKCS7 *signed_cert = d2i_PKCS7(NULL, &pkcs7_der, dec_ciphertext_len);

	FILE *client_signed_cert;
	client_signed_cert = fopen("./edhoc_client_INBOX/client-certificate.p7b", "wb+");
	PEM_write_PKCS7(client_signed_cert, signed_cert);


	printf("\n-----BEGIN EDHOC MESSAGE DESCRIPTION-----\n");
    //printf("   MSG_TYPE : %d", MSG_TYPE);
    printf("\n   S_U : ");
	print_cbor_bytestring_to_stdout(S_U, S_U_length);
    //printf("\n   DECRYPTED APP_4: %s", plaintext);
    printf("\n   CIPHERTEXT len: %d \n", dec_ciphertext_len);
    printf("\n   DECRYPTED APP_4:");
	//BIO *bio_out;
	bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);
	PKCS7_print_ctx(bio_out, signed_cert, 0, NULL);
  
    printf("\n-----END EDHOC MESSAGE DESCRIPTION-----\n");
  
    printf("\n#### END OF PARSING EDHOC MESSAGE 4 ####\n");
  
    //gen_msg_4_sym(x509_req);
    //X509 *cert = sign_CSR(x509_req);

	return 0;
}


int process_edhoc_sym_msg_1(unsigned char *nonce_database)
{
	printf("\n#### PROCESSING EDHOC SYMMETRIC MESSAGE 1 ####\n");

	if (strcmp((const char*)MSG_1.N_U, (const char*)nonce_database) == 0)
	{
		printf("\nEDHOC DISCONTINUED. NONCE is already in database.\n");
		return 1;
	}
	else
	{
		printf("\nNONCE OK.\n");
	}
	
	if (MSG_1.ECDH_Curves_U != X25519)
	{
		printf("\nEDHOC DISCONTINUED. ECDH_Curve_U is not supported.\n.");
		return 1;
	}
	else
	{
		printf("\nECDH_Curve_U SUPPORTED.\n");
	}

	if (MSG_1.HKDFs_U != ECDH_SS_HKDF_256)
	{
		printf("\nEDHOC DISCONTINUED. HKDF_U is not supported.\n.");
		return 1;
	}
	else
	{
		printf("\nHKDF_U SUPPORTED.\n");
	}

	if (MSG_1.AEADs_U != AES_CCM_64_64_128)
	{
		printf("\nEDHOC DISCONTINUED. AEAD_U is not supported.\n.");
		return 1;
	}
	else
	{
		printf("\nAEAD_U SUPPORTED.\n");
	}

	/* TODO: Verify that E_U is a valid point */

	return 0;
}


int process_edhoc_sym_msg_2()
{
	/* TODO: Use session identifier to retrieve protocol state */

	/* TODO: Validate that E_V is a valid point */

	unsigned char *ciphertext = cbor_bytestring_handle(cbor_array_get(MSG_2.COSE_ENC_2, 2));

	unsigned char *plaintext = malloc(500);
	//int dec_ciphertext_len = decrypt_ccm(ciphertext, ciphertext_len, enc_struct_buffer, enc_struct_buffer_sz, tag, k_i, iv, plaintext);
	printf("\nDECRYPTED output:\n%s\n", plaintext);

	return 0;
}
