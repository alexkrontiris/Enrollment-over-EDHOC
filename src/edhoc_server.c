#include "edhoc_messages.h"
#include <unistd.h>


int main(int argc, char *argv[])
{
	print_title();
	srand(time(NULL));

	//unsigned char app_1[] = "Hello, my name is EDHOC!";
	unsigned char app_2[] = "If you can read this then message_2 has SUCCEEDED!";
	//unsigned char app_3[] = "Last but not least... message_3!";

	//size_t app_1_sz = sizeof(app_1);
	size_t app_2_sz = sizeof(app_2);
	//size_t app_3_sz = sizeof(app_3);

	EVP_PKEY *session_pkey = gen_x25519();
	//EVP_PKEY *session_pkey = NULL;
	FILE *keyfile_pu = fopen("./input_parameters/server_PUBKEY.txt", "w");
	FILE *keyfile_pr = fopen("./input_parameters/server_PrivateKey.txt", "w");
	PEM_write_PUBKEY(keyfile_pu, session_pkey);
	PEM_write_PrivateKey(keyfile_pr, session_pkey, NULL, NULL, 0, NULL, NULL);
	//PEM_read_PUBKEY(keyfile_pu, &session_pkey, NULL, NULL);
	//PEM_read_PrivateKey(keyfile_pr, &session_pkey, NULL, NULL);
	fclose(keyfile_pu);
	fclose(keyfile_pr);

	const char *filepath_msg_1 = "./edhoc_server_INBOX/edhoc_sym_msg1_RAW.txt";
	const char *filepath_msg_2 = "./edhoc_client_INBOX/edhoc_sym_msg2_RAW.txt";
	const char *filepath_msg_3 = "./edhoc_server_INBOX/edhoc_sym_msg3_RAW.txt";
	const char *filepath_msg_4 = "./edhoc_client_INBOX/edhoc_sym_msg4_RAW.txt";

	// Receive message 1
	printf("\nWaiting for MESSAGE 1...\n");
	fflush(stdout);
    while (access(filepath_msg_1, F_OK) == -1) 
    {   
        continue;
    }   
    printf("\nMESSAGE 1 received....\n");
	sleep(1);

	cbor_item_t *received_msg_1 = print_and_get_cbor_array(filepath_msg_1);
	parse_edhoc_sym_msg_1(received_msg_1);
	
	// Send message 2
	size_t *msg_1_len = malloc(sizeof(size_t));
	unsigned char *msg_1 = import_msg(filepath_msg_1, msg_1_len);
	gen_msg_2_sym(app_2, app_2_sz, session_pkey, filepath_msg_2, msg_1, *msg_1_len);

	// Receive message 3
	printf("\nWaiting for MESSAGE 3...\n");
	fflush(stdout);
    while (access(filepath_msg_3, F_OK) == -1) 
    {   
        continue;
    }   
    printf("\nMESSAGE 3 received...\n");
	sleep(1);

	cbor_item_t *received_msg_3 = print_and_get_cbor_array(filepath_msg_3);
	PKCS7 *cert = parse_edhoc_sym_msg_3(received_msg_3);

	size_t cert_sz = strlen((const char *)cert);

	//size_t *msg_1_len = malloc(sizeof(size_t));
	size_t *msg_2_len = malloc(sizeof(size_t));
	size_t *msg_3_len = malloc(sizeof(size_t));
	//unsigned char *msg_1 = import_msg(filepath_msg_1, msg_1_len);
	unsigned char *msg_2 = import_msg(filepath_msg_2, msg_2_len);
	unsigned char *msg_3 = import_msg(filepath_msg_3, msg_3_len);

	gen_msg_4_sym(cert, cert_sz, session_pkey, filepath_msg_4, msg_1, msg_2, msg_3, *msg_1_len, *msg_2_len, *msg_3_len);

	return 0;
}
