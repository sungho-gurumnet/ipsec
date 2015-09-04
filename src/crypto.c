#include <util/types.h>
#include "esp.h"
#include "crypto.h"

// Key Length : 24 Bytes
static void _3des_cbc_encrypt(ESP* esp, size_t size, SA_ESP* sa) {
	uint64_t iv;
	RAND_bytes((unsigned char*)(&iv), 8);
	esp->iv = iv;

	DES_key_schedule* ks_3 = ((SA_ESP*)sa)->encrypt_key;
	DES_ede3_cbc_encrypt((const unsigned char*)esp->body,
							(unsigned char*)esp->body, 
							size , &ks_3[0], &ks_3[1], &ks_3[2], (unsigned char(*)[8])&iv, DES_ENCRYPT);
}

static void _3des_cbc_decrypt(ESP* esp, size_t size, SA_ESP* sa) {
	DES_key_schedule* ks_3 = ((SA_ESP*)sa)->encrypt_key;
	DES_ede3_cbc_encrypt((const unsigned char*)esp->body, 
							(unsigned char*)esp->body, 
							size , &ks_3[0], &ks_3[1], &ks_3[2], (unsigned char(*)[8])&(esp->iv), DES_DECRYPT);
}

// Key Length : 8 Bytes
static void _des_cbc_encrypt(ESP* esp, size_t size, SA_ESP* sa) {
	uint64_t iv;
	RAND_bytes((unsigned char*)(&iv), 8);
	esp->iv = iv;

	DES_ncbc_encrypt((const unsigned char *)esp->body, 
			(unsigned char *)esp->body,
			size, ((SA_ESP*)sa)->encrypt_key, (unsigned char(*)[8])&iv, DES_ENCRYPT);
}

static void _des_cbc_decrypt(ESP* esp, size_t size, SA_ESP* sa) {
	DES_ncbc_encrypt((const unsigned char *)esp->body, 
			(unsigned char *)esp->body,
			size, ((SA_ESP*)sa)->decrypt_key, (unsigned char(*)[8])&(esp->iv), DES_DECRYPT);
}

// Key Length : 5 ~ 56 Bytes (Default : 16 Bytes)
static void _blowfish_cbc_encrypt(ESP* esp, size_t size, SA_ESP* sa) {
	uint64_t iv;
	RAND_bytes((unsigned char*)(&iv), 8);
	esp->iv = iv;
	
	BF_cbc_encrypt((const unsigned char *)esp->body, 
			(unsigned char *)esp->body, 
			size, ((SA_ESP*)sa)->encrypt_key, (unsigned char*)(&iv), BF_ENCRYPT);
}

static void _blowfish_cbc_decrypt(ESP* esp, size_t size, SA_ESP* sa) {
	BF_cbc_encrypt((const unsigned char *)esp->body, 
			(unsigned char *)esp->body, 
			size, ((SA_ESP*)sa)->decrypt_key, (unsigned char*)(&(esp->iv)), BF_DECRYPT);
}

// Key Length : 5 ~ 56 Bytes (Default : 16 Bytes)
static void _cast128_cbc_encrypt(ESP* esp, size_t size, SA_ESP* sa) {
	uint64_t iv;
	RAND_bytes((unsigned char*)(&iv), 8);
	esp->iv = iv;

	CAST_cbc_encrypt((const unsigned char *)esp->body,
			(unsigned char *)esp->body,
			size, ((SA_ESP*)sa)->encrypt_key, (unsigned char *)&iv, CAST_ENCRYPT);
}

static void _cast128_cbc_decrypt(ESP* esp, size_t size, SA_ESP* sa) {
	CAST_cbc_encrypt((const unsigned char *)esp->body, 
			(unsigned char *)esp->body, 
			size, ((SA_ESP*)sa)->decrypt_key, (unsigned char *)(&(esp->iv)), CAST_DECRYPT);
}

static void _des_deriv_encrypt(ESP* esp, size_t size, SA_ESP* sa){
}

static void _des_deriv_decrypt(ESP* esp, size_t size, SA_ESP* sa){
}

static void _3des_deriv_encrypt(ESP* esp, size_t size, SA_ESP* sa){
}

static void _3des_deriv_decrypt(ESP* esp, size_t size, SA_ESP* sa){
}

// TODO : 16 Byte Alighment for Payload
// Key Length : 16, 24, 32 Bytes (Default : 16 Bytes)
static void _rijndael_cbc_encrypt(ESP* esp, size_t size, SA_ESP* sa) {
	uint64_t iv;
	RAND_bytes((unsigned char*)(&iv), 8);
	esp->iv = iv;
	
	AES_cbc_encrypt((const unsigned char *)esp->body,
			(unsigned char *)esp->body,
			size, ((SA_ESP*)sa)->encrypt_key, (unsigned char *)(&iv), AES_ENCRYPT);
}

static void _rijndael_cbc_decrypt(ESP* esp, size_t size, SA_ESP* sa) {
	AES_cbc_encrypt((const unsigned char *)esp->body, 
			(unsigned char *)esp->body, 
			size, ((SA_ESP*)sa)->decrypt_key, (unsigned char*)(&(esp->iv)), AES_DECRYPT);
}
/*
   Not implemented : No openssl function 

   AES and Triple DES are considered to be strong. Blowfish is still a good algorithm but its author (Bruce Schneier) recommends that you should use the "twofish" algorithm instead if available. Unfortunately twofish is not yet available in the list of openssl ciphers.
*/
static void _twofish_cbc_encrypt(ESP* esp, size_t size, SA_ESP* sa) {
}

static void _twofish_cbc_decrypt(ESP* esp, size_t size, SA_ESP* sa) {
}

static void _aes_ctr_encrypt(ESP* esp, size_t size, SA_ESP* sa) {
	uint64_t iv;
	unsigned int state_num = 0;
	unsigned char state_ecount[AES_BLOCK_SIZE];

	RAND_bytes((unsigned char*)(&iv), 8);
	esp->iv = iv;

	memset(state_ecount, 0x0, AES_BLOCK_SIZE);

	AES_ctr128_encrypt((const unsigned char *)esp->body,
			(unsigned char *)esp->body,
			size, ((SA_ESP*)sa)->encrypt_key, (unsigned char *)&iv, state_ecount, &state_num);
}
static void _aes_ctr_decrypt(ESP* esp, size_t size, SA_ESP* sa) {
	unsigned int state_num = 0;
	unsigned char state_ecount[AES_BLOCK_SIZE];

	memset(state_ecount, 0x0, AES_BLOCK_SIZE);
	
	AES_ctr128_encrypt((const unsigned char *)esp->body, 
			(unsigned char *)esp->body, 
			size, ((SA_ESP*)sa)->decrypt_key, (unsigned char*)&(esp->iv), state_ecount, &state_num);

}

// TODO : 16 Byte Alighment for Payload
// Key Length : 16, 24, 32 Bytes (Default : 16 Bytes)
static void _camellia_cbc_encrypt(ESP* esp, size_t size, SA_ESP* sa) {
	uint64_t iv;
	RAND_bytes((unsigned char*)(&iv), 8);
	esp->iv = iv;
	
	Camellia_cbc_encrypt((const unsigned char *)esp->body,
			(unsigned char *)esp->body,
			size, ((SA_ESP*)sa)->encrypt_key, (unsigned char *)(&iv), CAMELLIA_ENCRYPT);
}

static void _camellia_cbc_decrypt(ESP* esp, size_t size, SA_ESP* sa) {
	Camellia_cbc_encrypt((const unsigned char *)esp->body, 
			(unsigned char *)esp->body, 
			size, ((SA_ESP*)sa)->decrypt_key, (unsigned char *)&(esp->iv), CAMELLIA_DECRYPT);
}

Cryptography cryptographys[] = {
	{.encrypt = _des_cbc_encrypt,	 	.decrypt = _des_cbc_decrypt},
	{.encrypt = _3des_cbc_encrypt, 		.decrypt = _3des_cbc_decrypt},
	{.encrypt = _blowfish_cbc_encrypt, 	.decrypt = _blowfish_cbc_decrypt},
	{.encrypt = _cast128_cbc_encrypt, 	.decrypt = _cast128_cbc_decrypt},
	{.encrypt = _des_deriv_encrypt, 	.decrypt = _des_deriv_decrypt},
	{.encrypt = _3des_deriv_encrypt, 	.decrypt = _3des_deriv_decrypt},
	{.encrypt = _rijndael_cbc_encrypt,  .decrypt = _rijndael_cbc_decrypt},
	{.encrypt = _twofish_cbc_encrypt, 	.decrypt = _twofish_cbc_decrypt},
	{.encrypt = _aes_ctr_encrypt,		.decrypt = _aes_ctr_decrypt},
	{.encrypt = _camellia_cbc_encrypt, 	.decrypt = _camellia_cbc_decrypt},
};

Cryptography* get_cryptography(int algorithm) {
	return &cryptographys[algorithm - 1];
}

