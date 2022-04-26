#include <err.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <tee_client_api.h>

#include <TEEencrypt_ta.h>

#define RSA_KEY_SIZE 1024
#define RSA_MAX_PLAIN_LEN_1024 86 // (1024/8) - 42 (padding)
#define RSA_CIPHER_LEN_1024 (RSA_KEY_SIZE / 8)

/*
main function
argv[1] : (-e -> encryption or -d -> decryption)
argv[2] : filename, argv[3] : algorithm(Cesear or RSA)
*/
int main(int argc, char* argv[])
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_TEEencrypt_UUID;
	uint32_t err_origin;
	// Ceasar
	char plaintext[64] = {0,};
	char ciphertext[64] = {0,};
	char enc_text[64] = {0,};
	char enc_key[64] = {0,};
	char dec_text[64] = {0,};
	int length = 64;
	// RSA
	char clear[RSA_MAX_PLAIN_LEN_1024];
	char ciph[RSA_CIPHER_LEN_1024];

	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, err_origin);
	
	memset(&op, 0, sizeof(op));

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_VALUE_INOUT,
					 TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE);

	op.params[0].tmpref.buffer = plaintext;
	op.params[0].tmpref.size = length;	
	op.params[1].value.a = 0;

        // TEEencrypt -e option
	// argv[3] -> Ceasar or RSA 
	if (!strcmp(argv[1], "-e"))
	{
		// argv[3] -> Ceasar
	        if (!strcmp(argv[3], "Ceasar"))
                {
			printf("========================Ceasar Encryption========================\n");	   
			// file read(encrypt)
			FILE *fp = fopen(argv[2], "r");
			if (fp == NULL)
			{
				printf("READ FAIL(NOT EXIST ENCRYPT_FILE or check Input!)\n");
			}

			// read and print plaintext
			fgets(plaintext, sizeof(plaintext), fp);
			printf("Plaintext : %s\n", plaintext);
			fclose(fp);

			// plaintext -> op.params[0].tmpref.buffer(memcopy) 		
			memcpy(op.params[0].tmpref.buffer, plaintext, length);

			// call TA(TA_TEEencrypt_CMD_ENC_VALUE)
			res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_ENC_VALUE, &op,
				 &err_origin);
			if (res != TEEC_SUCCESS)
				errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
					res, err_origin);

			// op.params[0].tmpref.buffer -> ciphertext(memcopy), print ciphertext
		        memcpy(ciphertext, op.params[0].tmpref.buffer, length);
			printf("Ciphertext : %s\n", ciphertext);

			// save ciphertext.txt(encryptedfile.txt)
			fp = fopen("ciphertext.txt", "w");
			fputs(ciphertext, fp); 
			fclose(fp);

                        // save encryptedkey.txt
                        printf("key : %d\n", op.params[1].value.a);
			fp = fopen("encryptedkey.txt", "w");
			fprintf(fp, "%d\n", op.params[1].value.a);
			fclose(fp);
		}
		// argv[3] -> RSA
		else if (!strcmp(argv[3], "RSA")) 
		{

			printf("========================RSA Encryption========================\n");
			// file read(encrypt)
			FILE *fp = fopen(argv[2], "r");
			if (fp == NULL)
			{
				printf("READ FAIL(NOT EXIST ENCRYPT_FILE or check Input!)\n");
			}

			// read and print plaintext
			fgets(plaintext, sizeof(plaintext), fp);
			printf("RSA_plaintext str : %s\n", plaintext);
			fclose(fp);

			op.params[0].tmpref.buffer = clear;
			op.params[0].tmpref.size = RSA_MAX_PLAIN_LEN_1024;
			op.params[2].tmpref.buffer = ciph;
			op.params[2].tmpref.size = RSA_CIPHER_LEN_1024;		
			
			// RSA generate key value
			res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_RSA_CMD_GENKEYS,&op, 
				&err_origin);
			if (res != TEEC_SUCCESS)
				errx(1, "\nTEEC_InvokeCommand(TA_TEEencrypt_RSA_CMD_GENKEYS) failed %#x\n", res);
			
			printf("\n=========== Keys already generated. ==========\n");

			// RSA encrypt
			printf("\n============ RSA ENCRYPT CA SIDE ============\n");

			res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_RSA_CMD_ENCRYPT,&op, 
				&err_origin);

			if (res != TEEC_SUCCESS)
				errx(1, "\nTEEC_InvokeCommand(TA_TEEencrypt_RSA_CMD_ENCRYPT) failed 0x%x origin 0x%x\n",
					res, err_origin);

			// op.params[1].tmpref.buffer -> ciph(memcopy), print ciph
		        memcpy(ciph, op.params[2].tmpref.buffer, length);
			printf("\nThe text sent was encrypted: %s\n", ciph);

			// save ciphertext.txt(encryptedfile.txt)
			fp = fopen("RSA_Ciphertext.txt", "w");
			fputs(ciph, fp); 
			fclose(fp);
			
		}
		// Ceasar, RSA X
		else 
                {
			printf("Wrong Command!\n");			
		}
	}
	// TEEencrypt -d [encryptedtext.txt(ciphertext.txt)][encryptedkey.txt] (RSA X, only Ceasar)
        else if (!strcmp(argv[1], "-d"))
	{
		
		printf("========================Ceasar Decryption========================\n");
		// file read(ciphertext.txt)
		FILE *fp = fopen(argv[2], "r");
		if (fp == NULL)
		{
			printf("READ FAIL(NOT EXIST ENCRYPTEDTEXT_FILE or check Input!)\n");
		}

		// read ciphertext.txt
		fgets(enc_text, sizeof(enc_text), fp);
		printf("Encrypted_text(ciphertext) : %s\n", enc_text);
		fclose(fp);

		// file read(encryptedkey.txt)
		fp = fopen(argv[3], "r");
		if (fp == NULL)
		{
			printf("READ FAIL(NOT EXIST ENCRYPTEDKEY_FILE or check Input!)\n");
		}

		// read encryptedkey.txt
		fgets(enc_key, sizeof(enc_key), fp);
		printf("Encrypted_key(encryptedkey) : %s\n", enc_key);
		fclose(fp);

		// enc_text -> op.params[0].tmpref.buffer(memcopy)
		// atoi = char to int 		
		memcpy(op.params[0].tmpref.buffer, enc_text, length); 
		op.params[1].value.a = atoi(enc_key);
		
		// call TA(TA_TEEencrypt_CMD_DEC_VALUE) 		
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_DEC_VALUE, &op,
				 &err_origin);
		if (res != TEEC_SUCCESS)
			errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
				res, err_origin);
		
		// op.params[0].tmpref.buffer -> decryptedtext(memcopy), print decryptedtext
		memcpy(dec_text, op.params[0].tmpref.buffer, length);
		printf("Decryptedtext : %s\n", dec_text);
		
		// save decryptedtext
		fp = fopen("decryptedtext.txt", "w");
		fputs(dec_text, fp);
		fclose(fp);		

	}
        // Wrong Command
        else 
	{
        	printf("Wrong Commmand!\n");
        }

	TEEC_CloseSession(&sess);

	TEEC_FinalizeContext(&ctx);

	return 0;
}
