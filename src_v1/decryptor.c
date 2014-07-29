#include "decryptor.h"

int des3_cbc_decrypt(IP* packet, SA* current_sa)
{
	DES_cblock key1, key2, key3, iv;
	DES_key_schedule ks1, ks2, ks3;
	int len, i;

	// 1. 3Key & IV Extract
	memcpy(key1, &(current_sa->esp_algo->esp_key[0]), 8);
	memcpy(key2, &(current_sa->esp_algo->esp_key[1]), 8);
	memcpy(key3, &(current_sa->esp_algo->esp_key[2]), 8);
	 
	ESP* esp = (ESP*)packet->body;	
//	current_sa->esp_algo->iv = endian64(current_sa->esp_algo->iv);
//	memcpy(iv, &(current_sa->esp_algo->iv), 8);
	memcpy(iv, &(esp->IV), 8);
	// Key Validation Check
	
	DES_set_odd_parity(&key1);
	DES_set_odd_parity(&key2);
	DES_set_odd_parity(&key3);
	
	if(DES_set_key_checked(&key1, &ks1) ||
	   DES_set_key_checked(&key2, &ks2) ||
	   DES_set_key_checked(&key3, &ks3))
	{
			PRINT("DES_set_key_checked Error\n");
			return -1;
	}
	
	// 2. Payload Length Caluculate
	len = endian16(packet->length) - (packet->ihl * 4) - 16; 
		// Entire - IP header - (ESP Header + IV)
	printf("\nPacket Body : \n");
	for(i = 0; i < len + 20; i++)
	{
		printf("%02x ", packet->body[i]);
		if(i % 16 == 0 && i > 0)
				printf("\n");
	}
	printf("\n");
	// 3. Decrypt Payload
//	unsigned char* payload = (unsigned char*)malloc(len);
	uint8_t* payload = packet->body;
	
	DES_ede3_cbc_encrypt((const unsigned char*)esp->body, 
							(unsigned char*)payload, 
							len , &ks1, &ks2, &ks3, &iv, DES_DECRYPT);
	
	// 4. Print (for debugging)
	PRINT("\nDecrypted : \n");
	for(i = 1; i < 1 + len; i++)
	{
		PRINT("%02x ", payload[i - 1]);
		if(i % 16 == 0)
				PRINT("\n");
	}
	PRINT("\n");
	
//	memcpy(esp->body, payload, len);

	PRINT("\npacket body : \n");
for(i = 1; i < 1 + len; i++)
{
	PRINT("%02x ", packet->body[i - 1]);
	if(i % 16 == 0)
			PRINT("\n");
}
PRINT("\n");
	return 0;
}
