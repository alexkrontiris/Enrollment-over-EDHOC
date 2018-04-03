#ifndef EDHOC_DEFINE_H_
#define EDHOC_DEFINE_H_


#define AAD_HASH_SZ 32
#define AEADs_ARRAY 3
#define AES_CCM_64_64_128_block_sz 16
#define AES_CCM_64_64_128_tag_sz 8
#define COSE_ENC_2_SIZE 2
#define COSE_ENC_STRUCTURE_SZ 3
#define COSE_KDF_CTX_SZ 6
#define COSE_KDF_CTX_keyDataLength 128
#define COSE_KDF_CTX_keyDataLength_IV 56
#define COSE_KDF_CTX_protected ""
#define COSE_KDF_CTX_protected_sz 0
#define COSE_key_object_type 1
#define ECDH_Curves_ARRAY 1
#define EDHOC_MODE "symmetric"
#define EDHOC_SYM_MSG_1 4
#define EDHOC_SYM_MSG_2 5
#define EDHOC_SYM_MSG_3 6
#define ENC_STRUCT_CTX "Encrypt0"
#define ENC_STRUCT_PROTECTED_ATTR ""
#define ENC_STRUCT_PROTECTED_ATTR_SZ 0
#define ENC_STRUCT_UNPROTECTED_ATTR_SZ 0
#define E_U_map_param_1 -1
#define E_U_map_param_2 -2
#define E_U_map_param_3 1
#define E_U_map_size 3
#define E_V_map_param_1 -1
#define E_V_map_param_2 -2
#define E_V_map_param_3 1
#define E_V_map_size 3
#define HKDF_OUT_SZ 16
#define HKDFs_ARRAY 4
#define NONCE_size_bits 64
#define NONCE_size_bytes 8
#define PRE_SHARED_KEY_ID "key_1" // Established out-of-band
#define PSK "presharedkey" // Established out-of-band
#define S_ID_MAX_SIZE 8
#define S_ID_MIN_SIZE 5
#define S_ID_PARTY_U "SIDU" // Established out-of-band
#define S_ID_PARTY_V "SIDV"
#define X25519_OKP_value 4


#endif // EDHOC_DEFINE_H_
