#ifndef EDHOC_ENUM_H_
#define EDHOC_ENUM_H_


typedef enum
{
    AES_CCM_16_64_128 = 10,
    AES_CCM_16_64_256 = 11,
    AES_CCM_64_64_128 = 12,
    AES_CCM_64_64_256 = 13,
    AES_CCM_16_128_128 = 30,
    AES_CCM_16_128_256 = 31,
    AES_CCM_64_128_128 = 32,
    AES_CCM_64_128_256 = 33,
}AEAD_algorithms;


typedef enum
{
    X25519 = 4,
}ECDH_Curves_algorithms;


typedef enum
{
    ECDH_ES_HKDF_256 = -25,
    ECDH_ES_HKDF_512 = -26,
    ECDH_SS_HKDF_256 = -27,
    ECDH_SS_HKDF_512 = -28,
}HKDF_algorithms;


#endif // EDHOC_ENUM_H_
