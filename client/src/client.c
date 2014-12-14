#include "client.h"
int main(void)
{
	setkey_spdflush();
	setkey_flush(0);

	setkey_spdadd(0x0c0a86401, 0xc0a8c801, 
			0xffffff00,0xffffff00,0,0,IP_PROTOCOL_ANY, IN, IPSEC, 
			IP_PROTOCOL_ESP, TUNNEL, 0xac100002, 0xac100001, 0);    

	setkey_spdadd(0x0c0a8c801, 0xc0a86401, 
			0xffffff00,0xffffff00,0,0, IP_PROTOCOL_ANY, OUT, IPSEC, 
			IP_PROTOCOL_ESP, TUNNEL, 0xac100001, 0xac100002, 0);    

	uint64_t crypto_key[3] = 
	{   
		0xaeaeaeaeaeaeaeae,
		0xaeaeaeaeaeaeaeae,
		0xaeaeaeaeaeaeaeae
	};
	uint64_t auth_key[8] = 
	{
		0xaeaeaeaeaeaeaeae,
		0xaeaeaeaeaeaeaeae,
		0xaeaeaeaeaeaeaeae,
		0xaeaeaeaeaeaeaeae,
		0xaeaeaeaeaeaeaeae,
		0xaeaeaeaeaeaeaeae,
	};

	setkey_add(0xac100001, 0xac100002, 
			IP_PROTOCOL_ESP, 0x201, TUNNEL, CRYPTO_3DES_CBC, 
			AUTH_HMAC_SHA384, crypto_key, auth_key);

	setkey_add(0xac100002, 0xac100001,
			IP_PROTOCOL_ESP, 0x301, TUNNEL, CRYPTO_3DES_CBC, 
			AUTH_HMAC_SHA384, crypto_key, auth_key);
	
	setkey_spddump();
	setkey_dump(0);
}
