#include "ah.h"
#include "auth.h"

static void _hmac_md5(void* payload, size_t size, unsigned char* result, SA* sa) {
	uint64_t* auth_key = NULL;
	int auth_key_length = 0;

	if(sa->ipsec_protocol == IP_PROTOCOL_ESP) {
		auth_key = ((SA_ESP*)sa)->auth_key;
		auth_key_length = ((SA_ESP*)sa)->auth_key_length;
	} else if(sa->ipsec_protocol == IP_PROTOCOL_AH) {
		auth_key = ((SA_AH*)sa)->auth_key;
		auth_key_length = ((SA_AH*)sa)->auth_key_length;
	}

	unsigned char* _result = HMAC(EVP_md5(), auth_key, auth_key_length, payload, size, NULL, NULL);
	memcpy(result, _result, AUTH_DATA_LEN);
	//printf("md len?? %d\n", md_len);
}

static void _hmac_sha1(void* payload, size_t size, unsigned char* result, SA* sa) {
	uint64_t* auth_key = NULL;
	int auth_key_length = 0;
	unsigned int md_len = AUTH_DATA_LEN;

	if(sa->ipsec_protocol == IP_PROTOCOL_ESP) {
		auth_key = ((SA_ESP*)sa)->auth_key;
		auth_key_length = ((SA_ESP*)sa)->auth_key_length;
	} else if(sa->ipsec_protocol == IP_PROTOCOL_AH) {
		auth_key = ((SA_AH*)sa)->auth_key;
		auth_key_length = ((SA_AH*)sa)->auth_key_length;
	}

	unsigned char* _result = HMAC(EVP_sha1(), auth_key, auth_key_length, payload, size, result, &md_len);
	memcpy(result, _result, AUTH_DATA_LEN);
}
/*
   Not implemented : No RFC
*/
static void _keyed_md5(void* payload, size_t size, unsigned char* result, SA* sa) {
}

static void _keyed_sha1(void* payload, size_t size, unsigned char* result, SA* sa) {
}

static void _hmac_sha256(void* payload, size_t size, unsigned char* result, SA* sa) {
	uint64_t* auth_key = NULL;
	int auth_key_length = 0;
	unsigned int md_len = AUTH_DATA_LEN;

	if(sa->ipsec_protocol == IP_PROTOCOL_ESP) {
		auth_key = ((SA_ESP*)sa)->auth_key;
		auth_key_length = ((SA_ESP*)sa)->auth_key_length;
	} else if(sa->ipsec_protocol == IP_PROTOCOL_AH) {
		auth_key = ((SA_AH*)sa)->auth_key;
		auth_key_length = ((SA_AH*)sa)->auth_key_length;
	}

	unsigned char* _result = HMAC(EVP_sha256(), auth_key, auth_key_length, payload, size, result, &md_len);
	memcpy(result, _result, AUTH_DATA_LEN);
}
/*
	TODO : Debug for 384, 512
*/
static void _hmac_sha384(void* payload, size_t size, unsigned char* result, SA* sa) {
	uint64_t* auth_key = NULL;
	int auth_key_length = 0;
	unsigned int md_len = AUTH_DATA_LEN;

	if(sa->ipsec_protocol == IP_PROTOCOL_ESP) {
		auth_key = ((SA_ESP*)sa)->auth_key;
		auth_key_length = ((SA_ESP*)sa)->auth_key_length;
	} else if(sa->ipsec_protocol == IP_PROTOCOL_AH) {
		auth_key = ((SA_AH*)sa)->auth_key;
		auth_key_length = ((SA_AH*)sa)->auth_key_length;
	}

	unsigned char* _result = HMAC(EVP_sha384(), auth_key, auth_key_length, payload, size, result, &md_len);
	memcpy(result, _result, AUTH_DATA_LEN);
}

static void _hmac_sha512(void* payload, size_t size, unsigned char* result, SA* sa) {
	uint64_t* auth_key = NULL;
	int auth_key_length = 0;
	unsigned int md_len = AUTH_DATA_LEN;

	if(sa->ipsec_protocol == IP_PROTOCOL_ESP) {
		auth_key = ((SA_ESP*)sa)->auth_key;
		auth_key_length = ((SA_ESP*)sa)->auth_key_length;
	} else if(sa->ipsec_protocol == IP_PROTOCOL_AH) {
		auth_key = ((SA_AH*)sa)->auth_key;
		auth_key_length = ((SA_AH*)sa)->auth_key_length;
	}

	unsigned char* _result = HMAC(EVP_sha512(), auth_key, auth_key_length, payload, size, result, &md_len);
	memcpy(result, _result, AUTH_DATA_LEN);
}

static void _hmac_ripemd160(void* payload, size_t size, unsigned char* result, SA* sa) {
	uint64_t* auth_key = NULL;
	int auth_key_length = 0;
	unsigned int md_len = AUTH_DATA_LEN;

	if(sa->ipsec_protocol == IP_PROTOCOL_ESP) {
		auth_key = ((SA_ESP*)sa)->auth_key;
	} else if(sa->ipsec_protocol == IP_PROTOCOL_AH) {
		auth_key = ((SA_AH*)sa)->auth_key;
	}

	unsigned char* _result = HMAC(EVP_ripemd160(), auth_key, auth_key_length, payload, size, result, &md_len);
	memcpy(result, _result, AUTH_DATA_LEN);
}
/*
   Not implemented : No openssl function

	   AES-XCBC-MAC is not directly supported. However, it's very simple to
	   implement as it's based on AES-CBC for which there is support.
*/
static void _aes_xcbc_mac(void* payload, size_t size, unsigned char* result, SA* sa) {
}
/* 
   Not implemented : Only for BSD
*/
static void _tcp_md5(void* payload, size_t size, unsigned char* result, SA* sa) {
}

Authentication authentications[] = {
	{.authenticate = _hmac_md5},
	{.authenticate = _hmac_sha1},
	{.authenticate = _keyed_md5},
	{.authenticate = _keyed_sha1},
	{.authenticate = _hmac_sha256},
	{.authenticate = _hmac_sha384},
	{.authenticate = _hmac_sha512},
	{.authenticate = _hmac_ripemd160},
	{.authenticate = _aes_xcbc_mac},
	{.authenticate = _tcp_md5},
};

Authentication* get_authentication(int algorithm) {
	return &authentications[algorithm - 1];
}

