#include "define.h"
#include "io_functions.h"


unsigned char *import_msg(const char *filepath, size_t *len)
{
	FILE *in_file = fopen(filepath, "rb");
	if (in_file == NULL)
	{
		printf("ERROR, no EDHOC message found!");
	}
    fseek(in_file, 0, SEEK_END);
    size_t length = (size_t)ftell(in_file);
    fseek(in_file, 0, SEEK_SET);

    unsigned char *buffer = malloc(length);
    fread(buffer, length, 1, in_file);

	*len = length;

	return buffer;
}


cbor_item_t *print_and_get_cbor_array(const char *filepath)
{
    printf("\n#### READING EDHOC MSG... ####\n");
    
	const char *filename = filepath;

	/* 
    const char *filename;
    if (msg_type == EDHOC_SYM_MSG_1)
    {    
        filename = "./received_messages/edhoc_sym_msg1_BINARY.txt";

    }    
    else if (msg_type == EDHOC_SYM_MSG_2)
    {    

        filename = "./received_messages/edhoc_sym_msg2_BINARY.txt";
    }    
    else if (msg_type == EDHOC_SYM_MSG_3)
    {    
        filename = "./received_messages/edhoc_sym_msg3_BINARY.txt";
    }
	*/

    printf("MSG: %s\n", filename);

    FILE *in_file = fopen(filename, "rb");
    if (in_file == NULL)
    {    
        printf("ERROR, no received EDHOC message found!");;
    }    
    fseek(in_file, 0, SEEK_END);
    size_t length = (size_t)ftell(in_file);
    fseek(in_file, 0, SEEK_SET);

    unsigned char *buffer = malloc(length);
    fread(buffer, length, 1, in_file);

    struct cbor_load_result result;
    cbor_item_t *item = cbor_load(buffer, length, &result);
    if (result.error.code != CBOR_ERR_NONE)
    {    
        printf("There was an error while reading the input near byte %zu (read %zu bytes  in     total): ", result.error.position, result.read);
        switch (result.error.code)
        {    
            case CBOR_ERR_MALFORMATED:
            {    
                printf("Malformed data\n");
                break;
            }    
            case CBOR_ERR_MEMERROR:
            {    
                printf("Memory error -- perhaps the input is too large?\n");
                break;
            }    
            case CBOR_ERR_NODATA:
            {    
                printf("The input is empty\n");
                break;
            }    
            case CBOR_ERR_NOTENOUGHDATA:
            {
                printf("Data seem to be missing -- is the input complete?\n");
                break;
            }
            case CBOR_ERR_SYNTAXERROR:
            {
                printf("Syntactically malformed data -- see http://tools.ietf.org/html/          rfc7049\n");
                break;
            }
            case CBOR_ERR_NONE:
            {
                // GCC's cheap dataflow analysis gag
                break;
            }
        }
        exit(1);
    }

    printf("\n-----BEGIN CBOR ARRAY DESCRIPTION-----\n");
    cbor_describe(item, stdout);
    fflush(stdout);
    printf("-----END CBOR ARRAY DESCRIPTION-----\n");

	cbor_item_t *received_msg = item;

    /* Deallocate the result */
    //cbor_decref(&item);
    fclose(in_file);

    return received_msg;
}


void *print_cbor_array_to_stdout(unsigned char *buffer, size_t length)
{
    printf("\n-----BEGIN CBOR ARRAY-----\n");
    for (int i = 0; i < length; i++)
    {
        printf("%02x", buffer[i]);
    }
    printf("\n-----END CBOR ARRAY-----\n");
	fflush(stdout);

    return 0;
}


void *print_cbor_bytestring_to_stdout(unsigned char *buffer, size_t length)
{
	for (int i = 0; i < length; i++)
	{
		printf("%c", buffer[i]);
	}

	return 0;
}


void *print_cbor_bytestring_to_stdout_hex(unsigned char *buffer, size_t length)
{
    for (int i = 0; i < length; i++)
    {   
        printf("%02x", buffer[i]);
    }   
    //printf(" (HEX encoding)");

    return 0;
}


void *print_bytes(unsigned char *buffer, size_t length)
{
    for (int i = 0; i < length; i++)
    {   
        printf("%02x", buffer[i]);
    }   

    return 0;
}


int print_pkey_hr(EVP_PKEY *pkey)
{
    BIO *b_out = BIO_new_fp(stdout, BIO_NOCLOSE);
    printf("\nHuman readable format of PUBKEY:\n");
    EVP_PKEY_print_public(b_out, pkey, 0, NULL);

    return 1;
}


void *print_title()
{
    printf("\n ________  _______   __    __   ______    ______  ");
    printf("\n|        \\|       \\ |  \\  |  \\ /      \\  /      \\ ");
    printf("\n| $$$$$$$$| $$$$$$$\\| $$  | $$|  $$$$$$\\|  $$$$$$\\");
    printf("\n| $$__    | $$  | $$| $$__| $$| $$  | $$| $$   \\$$");
    printf("\n| $$  \\   | $$  | $$| $$    $$| $$  | $$| $$      ");
    printf("\n| $$$$$   | $$  | $$| $$$$$$$$| $$  | $$| $$   __ ");
    printf("\n| $$_____ | $$__/ $$| $$  | $$| $$__/ $$| $$__/  \\");
    printf("\n| $$     \\| $$    $$| $$  | $$ \\$$    $$ \\$$    $$");
    printf("\n \\$$$$$$$$ \\$$$$$$$  \\$$   \\$$  \\$$$$$$   \\$$$$$$ \n");

    return 0;
}


void *write_cbor_array_to_file_RAW(unsigned char *buffer, size_t length, int msg_type, const char *filepath)
{
	const char *filename = filepath;

	/*
	const char *filename;
	if (msg_type == EDHOC_SYM_MSG_1)
	{
		filename = "./output_files/edhoc_sym_msg1_BINARY.txt";
		
	}
	else if (msg_type == EDHOC_SYM_MSG_2)
	{
	
		filename = "./output_files/edhoc_sym_msg2_BINARY.txt";
	}
	else if (msg_type == EDHOC_SYM_MSG_3)
	{
		filename = "./output_files/edhoc_sym_msg3_BINARY.txt";
	}
	*/

    FILE *out;
    out = fopen(filename, "wb");
    fwrite(buffer, 1, length, out);
	fflush(out);
	fclose(out);

    return 0;
}


void *write_cbor_array_to_file_HEX(unsigned char *buffer, size_t length, int msg_type, const char *filepath)
{
	const char *filename = filepath;
	
	/*
	const char *filename;
	if (msg_type == EDHOC_SYM_MSG_1)
	{
		filename = "./output_files/edhoc_sym_msg1_HEX.txt";
		
	}
	else if (msg_type == EDHOC_SYM_MSG_2)
	{
	
		filename = "./output_files/edhoc_sym_msg2_HEX.txt";
	}
	else if (msg_type == EDHOC_SYM_MSG_3)
	{
		filename = "./output_files/edhoc_sym_msg3_HEX.txt";
	}
	*/

    FILE *out;
    out = fopen(filename, "w");
    for (int i = 0; i < length; i++) 
    {    
        fprintf(out, "%02x", buffer[i]);
    }
	fflush(out);
	fclose(out);

    return 0;
}


void *write_X509_to_file(X509_REQ *x509)
{
	FILE *out;
	out = fopen("./edhoc_server_INBOX/CSR.pem", "wb");
	PEM_write_X509_REQ(out, x509);

	fflush(out);
	fclose(out);
}
