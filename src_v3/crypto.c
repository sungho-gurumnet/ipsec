#include "crypto.h"

static void _3des_cbc_encrypt(void* payload, size_t size) 
{
	DES_cblock key1, key2, key3, iv;
	DES_key_schedule ks1, ks2, ks3;

	// 1. Key & IV Extract
	memcpy(key1, &(current_sa->esp_crypto_key[0]), 8);
	memcpy(key2, &(current_sa->esp_crypto_key[1]), 8);
	memcpy(key3, &(current_sa->esp_crypto_key[2]), 8);

	RAND_bytes((unsigned char*)(&(current_sa->iv)), 8);
	memcpy(iv, &(current_sa->iv), 8);

	DES_set_odd_parity(&key1);
	DES_set_odd_parity(&key2);
	DES_set_odd_parity(&key3);

	// Key Validation Check
	if(DES_set_key_checked(&key1, &ks1) ||
	   DES_set_key_checked(&key2, &ks2) ||
	   DES_set_key_checked(&key3, &ks3))
	{
			printf("DES_set_key_checked Error\n");
	}

	DES_ede3_cbc_encrypt((const unsigned char*)payload,
							(unsigned char*)payload, 
							size , &ks1, &ks2, &ks3, &iv, DES_ENCRYPT);
/*
	// 5. Print (for debugging)
	printf("\nEncrypted : \n");
	for(i = 1; i < 1 + len + pad_len + 2; i++)
	{
		printf("%02x ", payload[i - 1]);
		if(i % 16 == 0)
				printf("\n");
	}
	printf("\n");
*/
//	memcpy(packet->body, payload, len + pad_len + 2);

//	free(padding);
}

static void _3des_cbc_decrypt(void* payload, size_t size) 
{
	DES_cblock key1, key2, key3, iv;
	DES_key_schedule ks1, ks2, ks3;

	ESP* esp = (ESP*)payload;
	
	// Key & IV Extract
	memcpy(key1, &(current_sa->esp_crypto_key[0]), 8);
	memcpy(key2, &(current_sa->esp_crypto_key[1]), 8);
	memcpy(key3, &(current_sa->esp_crypto_key[2]), 8);
	memcpy(iv, &(esp->iv), 8);

	// Key Validation Check
	DES_set_odd_parity(&key1);
	DES_set_odd_parity(&key2);
	DES_set_odd_parity(&key3);
	
	if(DES_set_key_checked(&key1, &ks1) ||
	   DES_set_key_checked(&key2, &ks2) ||
	   DES_set_key_checked(&key3, &ks3))
	{
			printf("DES_set_key_checked Error\n");
	}
	
	DES_ede3_cbc_encrypt((const unsigned char*)esp->body, 
							(unsigned char*)esp->body, 
							size , &ks1, &ks2, &ks3, &iv, DES_DECRYPT);
/*	
	PRINT("\nDecrypted : \n");
	int innerIP_len = 0;
#ifndef _TP_
	innerIP_len = 20;
#endif
	for(i = 1; i < 1 + len + innerIP_len; i++)
	{
		PRINT("%02x ", packet->body[i - 1]);
		if(i % 16 == 0)
				PRINT("\n");
	}
	PRINT("\n");
	
//	memcpy(esp->body, payload, len);*/
}


static void _des_cbc_encrypt(void* payload, size_t size) {
}

static void _des_cbc_decrypt(void* payload, size_t size) {
}

Cryptography cryptographys[] = 
{
	{.encrypt = _des_cbc_encrypt, .decrypt = _des_cbc_decrypt},
	{.encrypt = _3des_cbc_encrypt, .decrypt = _3des_cbc_decrypt},
};

Cryptography* get_cryptography(int algorithm) 
{
		return &cryptographys[algorithm];
}

