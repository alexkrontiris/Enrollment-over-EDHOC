#include "edhoc_messages.h"
#include "x509.h"
#include <unistd.h>


int main(int argc, char *argv[])
{
	print_title();
	srand(time(NULL));

	unsigned char app_1[] = "Hello, my name is EDHOC!";
	//unsigned char app_2[] = "If you can read this then message_2 has SUCCEEDED!";
	
	X509_REQ *x509 = NULL;
	x509 = gen_csr();

	unsigned char *app_3 = NULL;
	int csr_sz = i2d_X509_REQ(x509, (unsigned char **)&app_3);

	//printf("CSR in DER: \n %s", app_3);
	//int csr_sz = strlen((const char*)app_3);
	printf("CSR size: %d", csr_sz);
	//printf("%s", csr);
	//unsigned char app_3[] = 
	//app_3 = "123";
	//unsigned char app_3[csr_sz];
	//app_3 = csr;
	//unsigned char app_3[] = "Last but not least... message_3!";

	size_t app_1_sz = sizeof(app_1);
	//size_t app_2_sz = sizeof(app_2);
	size_t app_3_sz = csr_sz;

	EVP_PKEY *session_pkey = gen_x25519();
	//EVP_PKEY *session_pkey = NULL;
	FILE *keyfile_pu = fopen("./input_parameters/client_PUBKEY.txt", "w");
	FILE *keyfile_pr = fopen("./input_parameters/client_PrivateKey.txt", "w");
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

	// Send message 1
	gen_msg_1_sym(app_1, app_1_sz, session_pkey, filepath_msg_1);

	// Receive message 2
	printf("\nWaiting for MESSAGE 2...\n");
	fflush(stdout);
	while (access(filepath_msg_2, F_OK) == -1)
	{
		continue;
	}
	printf("\nMESSAGE 2 received...\n");
	sleep(1);

	cbor_item_t *received_msg_2 = print_and_get_cbor_array(filepath_msg_2);
	parse_edhoc_sym_msg_2(received_msg_2);

	// Send message 3
	size_t *msg_1_len = malloc(sizeof(size_t));
	size_t *msg_2_len = malloc(sizeof(size_t));
	unsigned char *msg_1 = import_msg(filepath_msg_1, msg_1_len);
	unsigned char *msg_2 = import_msg(filepath_msg_2, msg_2_len);
	// Enrollment start
	
	
	// -Enrollment end
	gen_msg_3_sym(app_3, app_3_sz, session_pkey, filepath_msg_3, msg_1, msg_2, *msg_1_len, *msg_2_len);
	fflush(stdout);

	// Receive message 4
	printf("\nWaiting for MESSAGE 4...\n");
	fflush(stdout);
	while (access(filepath_msg_4, F_OK) == -1)
	{
		continue;
	}
	printf("\nMESSAGE 4 received...\n");
	sleep(1);

	cbor_item_t *received_msg_4 = print_and_get_cbor_array(filepath_msg_4);
	parse_edhoc_sym_msg_4(received_msg_4);
	
	return 0;
}
