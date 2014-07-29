#include "auth.h"

static void _hmac_md5(void* payload, size_t size, unsigned char* result) 
{
	result = HMAC(EVP_md5(), &(current_sa->esp_auth_key), 16, payload, size , NULL, NULL);
}

static void _hmac_sha1(void* payload, size_t size, unsigned char* result) 
{

}

Authentication authentications[] =
{
	{.authenticate = _hmac_md5},
	{.authenticate = _hmac_sha1},
};

Authentication* get_authentication(int algorithm) 
{
	return &authentications[algorithm - 1];
}

