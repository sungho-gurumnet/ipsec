#include "authenticator.h"

int hmac_md5_icv_calc(IP* packet, SA* current_sa) 
{
//	extern hmac_t;	
	int len = endian16(packet->length);
	// Transport : IP + ESP Header + Payload + ESP Trailer + ICV
	// Tunnel : Outer IP + ESP Header + Inner IP + Payload + ESP Trailer + ICV
	unsigned char* result;// = &(packet->body[len - 20 - 12]);
//	uint64_t hmac_s = cpu_tsc();
	result = HMAC(EVP_md5(), &(current_sa->esp_algo->ah_key), 16, packet->body, len - 20 - 12 , NULL, NULL);
//	uint64_t hmac_e = cpu_tsc();

//	hmac_t = hmac_e - hmac_s;
	
//	uint32_t result[4];
//	md5(packet->body, len - 20 - 12, result);
	// LEN : -IP(20) - ICV(-12)
	
	int i;
	PRINT("ICV Key (16bit) : \n");
	for (i = 1; i < 1 + 16; i++) 
	{
		PRINT("%02x ", result[i-1]);
		if(i % 16 == 0)
			PRINT("\n");
	}
	PRINT("\n");
	
	// ICV Addition (12bit)
	memcpy(&(packet->body[len - 20 - 12]), result, 12);
	// ICV index : LEN - IP(20) - ICV(12)
	for(i = 1; i < 1 + 200 ; i++)
	{
		PRINT("%02x ", packet->body[i - 1]); // Packet - IP Header 
		if( i % 16 == 0 )
			PRINT("\n");
	}
	PRINT("\n");
	return 0;
}

int hmac_md5_icv_check(IP* packet, SA* current_sa)
{
	int len = endian16(packet->length);
	// Transport : IP + ESP Header + Payload + ESP Trailer + ICV
	// Tunnel : Outer IP + ESP Header + Inner IP + Payload + ESP Trailer + ICV

	unsigned char* result;
	result = HMAC(EVP_md5(), &(current_sa->esp_algo->ah_key), 16, packet->body, len -20 - 12 , NULL, NULL);
	// LEN : -IP(20) - ICV(-12)
	
	int i;	
	PRINT("ICV Key (16bit) : \n");
	for (i = 1; i < 1 + 16; i++) 
	{
		PRINT("%02x ", result[i-1]);
		if(i % 16 == 0)
			PRINT("\n");
	}
	PRINT("\n");
	
	if(memcmp(result, &(packet->body[len - 20 - 12]), 12) != 0)
	//	ICV index : LEN - IP(20) - ICV(12)
		return -1;
	else
		return 0;
}
