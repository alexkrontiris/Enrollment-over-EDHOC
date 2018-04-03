#include "other_functions.h"


bool CBOR_ITEM_T_init(cbor_item_t *item)
{
    if (item == NULL)
    {
        return false;
    }
    else
    {
        return true;
    }
}


char *decode(const char *input, int input_sz, int *output_sz)
{
    char *output = (char*)malloc(input_sz);

    /* Keep track of our decoded position */
    char *c = output;

    /* Store the number of bytes decoded by a single call */
    int cnt = 0;

    base64_decodestate s;

    /*---------- START DECODING ----------*/
    base64_init_decodestate(&s);

    cnt = base64_decode_block(input, strlen(input), c, &s);
    /* Store the size of the decoded data for later use */
    *output_sz = cnt;
    c += cnt;
    /* Note: there is no base64_decode_blockend! */
    /*---------- STOP DECODING  ----------*/

    /* We want to print the decoded data, so null-terminate it: */
    *c = 0;

    return output;
}


char *encode(const char* input, int buf_sz)
{
	/* set up a destination buffer large enough to hold the encoded data */
	char* output = (char*)malloc(buf_sz);

	/* keep track of our encoded position */
	char* c = output;

	/* store the number of bytes encoded by a single call */
	int cnt = 0;

	/* we need an encoder state */
	base64_encodestate s;
	
	/*---------- START ENCODING ----------*/
	/* initialise the encoder state */
	base64_init_encodestate(&s);

	/* gather data from the input and send it to the output */
	cnt = base64_encode_block(input, strlen(input), c, &s);
	c += cnt;

	/* since we have encoded the entire input string, we know that 
	   there is no more input data; finalise the encoding */
	cnt = base64_encode_blockend(c, &s);
	c += cnt;
	/*---------- STOP ENCODING  ----------*/
	
	/* we want to print the encoded data, so null-terminate it: */
	*c = 0;
	
	return output;
}


/* Part of CBOR streaming parser
 */
/*
const char *key = "-1";
bool key_found = false;


void find_string(void * _ctx, cbor_data buffer, size_t len)
{
    if (key_found) {
        printf("Found the value: %*s\n", (int) len, buffer);
        key_found = false;
    } else if (len == strlen(key)) {
        key_found = (memcmp(key, buffer, len) == 0);
    }
}
*/


unsigned char *key_add_headers(unsigned char *key, size_t key_sz, const char *filepath)
{
	const char begin_header[] = "-----BEGIN PUBLIC KEY-----\n";
	const char pem_header[] = "MCowBQYDK2VuAyEA";
	const char end_header[] = "\n-----END PUBLIC KEY-----";

	//int base64_buf_sz = 4*(key_sz/3) + 4;
	int base64_buf_sz = 500;
	char *key_base64 = malloc(500);
	key_base64 = encode((const char *)key, base64_buf_sz);

	int key_base64_sz = 44;
	
	unsigned char *key_pem = malloc(strlen(begin_header) + strlen(pem_header) + key_base64_sz + strlen(end_header) + 1);

	memcpy(key_pem, begin_header, strlen(begin_header));
	memcpy(key_pem + strlen(begin_header), pem_header, strlen(pem_header));
	memcpy(key_pem + strlen(begin_header) + strlen(pem_header), key_base64, key_base64_sz);
	memcpy(key_pem + strlen(begin_header) +strlen(pem_header) + key_base64_sz, end_header, strlen(end_header) + 1);

	FILE *out = fopen(filepath, "wb+");
	//fputs(key_pem, out);
	fwrite(key_pem, 114, 1, out);
	fflush(out);
	fclose(out);
	free(key_base64);
	
	return key_pem;
}


unsigned char *strip_pkey(EVP_PKEY *pkey, int *pure_key_sz)
{
    BIO *b = BIO_new(BIO_s_mem());
    if (!PEM_write_bio_PUBKEY(b, pkey))
    {
        printf("\nPEM_write_bio_PUBKEY FAILED.\n");
    }

    /* Get size of the public key. */
    int bio_sz = (int) BIO_get_mem_data(b, NULL);
    //printf("\nAlice's PUBKEY size in PEM format: %d", bio_sz);

    unsigned char *bio_buffer = NULL;
    bio_buffer = malloc(bio_sz);
    BIO_read(b, bio_buffer, bio_sz);
    free(bio_buffer);
    //printf("\nAlice's PUBKEY from bio_buffer:\n");

    /* Remove BEGIN and END headers from key */
    int begin_header;
    int end_header;
    for (int i = 0; i < bio_sz; i++)
    {
        if (bio_buffer[i] == '\n' && bio_buffer[i-1] == '-' && bio_buffer[i+1] != '\0')
        {
            begin_header = i + 1;
        }
        if (bio_buffer[i] == '\n' && bio_buffer[i+1] == '-')
        {
            end_header = i;
        }
    }
    printf("\n1st byte of PUBKEY: %d Last byte of PUBKEY: %d\n", begin_header, end_header);

    unsigned char *headless_key;
    int headless_key_sz = bio_sz - begin_header - (bio_sz - end_header);
    headless_key = malloc(headless_key_sz + 1);
    printf("\nSize of key without BEGIN and END headers: %d\n", headless_key_sz);

    memcpy(headless_key, bio_buffer + begin_header, headless_key_sz);
	headless_key[headless_key_sz] = '\0';
    printf("\nPublic key without BEGIN and END headers:\n%s\n", headless_key);

    int *output_sz = malloc(sizeof(int));
    char *decoded = decode((const char*)headless_key, headless_key_sz, output_sz);
    /*
    printf("\nDecoded PUBKEY: \n");
    for (int i = 0; i < *output_sz; i++)
    {
        printf("%02x ", decoded[i] &0xff);
    }
    */

    /* Remove PEM header from decoded key */
    int pem_header_sz = 12;
    *pure_key_sz = *output_sz - pem_header_sz;
    unsigned char *pure_key = malloc(*pure_key_sz);
    memcpy(pure_key, decoded + pem_header_sz, *pure_key_sz);
    printf("\nPUBKEY ready for transport (spaces are NOT in the bytestring): \n");
    for (int i = 0; i < *pure_key_sz; i++)
    {
        printf("%02x ", pure_key[i]);
    }
    printf("\n");
    
	free(headless_key);
    free(output_sz);

    return pure_key;
}
