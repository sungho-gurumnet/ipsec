#include "encryptor.h"

int des3_cbc_encrypt(IP* packet, SA* current_sa)
{
	DES_cblock key1, key2, key3, iv;
	DES_key_schedule ks1, ks2, ks3;
	int len, pad_len, i;

	// 1. 3Key & IV Extract
	memcpy(key1, &(current_sa->esp_algo->esp_key[0]), 8);
	memcpy(key2, &(current_sa->esp_algo->esp_key[1]), 8);
	memcpy(key3, &(current_sa->esp_algo->esp_key[2]), 8);

	RAND_bytes(&(current_sa->esp_algo->iv), 8);
	
	memcpy(iv, &(current_sa->esp_algo->iv), 8);

	DES_set_odd_parity(&key1);
	DES_set_odd_parity(&key2);
	DES_set_odd_parity(&key3);

	// Key Validation Check
	if(DES_set_key_checked(&key1, &ks1) ||
	   DES_set_key_checked(&key2, &ks2) ||
	   DES_set_key_checked(&key3, &ks3))
	{
			printf("DES_set_key_checked Error\n");
			return -1;
	}

	// 2. Payload Length Caluculate
	switch(current_sp->mode)
	{
		case TRANSPORT :
			len = endian16(packet->length) - (packet->ihl * 4);
			// Entire - IP header 
			break;
		case TUNNEL : 
			len = endian16(packet->length); 
			// Entire - IP header + Inner IP Header
			break;
	}	
	
	// 3. ESP Trailer Addition
	pad_len = 8 - (len + 2) % 8; // Padding length : for 8byte alignment 
	
	//unsigned char* padding = (unsigned char*)malloc(pad_len);
	unsigned char* padding = packet->body + len;

	// Padding fill
	if(pad_len != 0)
	{
		for(i = 0; i < pad_len; i++)
		{
			padding[i] = i + 1;
		}
	}
//	memcpy(&packet->body[len], padding, pad_len);
	// Protocol Field Add
	switch(current_sp->mode)
	{
		case TRANSPORT :
			packet->body[len + pad_len + 1] = packet->protocol;
			break;
		case TUNNEL : 
			packet->body[len + pad_len + 1] = IP_PROTOCOL_IP; 
			break;
	}	
	// Padding Length Add
	packet->body[len + pad_len] = pad_len;
	
	// 4. Encrypt Payload
	//unsigned char* payload = (unsigned char*)malloc(len + pad_len + 2);
	uint8_t* payload = packet->body;

	DES_ede3_cbc_encrypt((const unsigned char*)packet->body, 
							(unsigned char*)payload, 
							len + pad_len + 2 , &ks1, &ks2, &ks3, &iv, DES_ENCRYPT);
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

	return 0;
}
