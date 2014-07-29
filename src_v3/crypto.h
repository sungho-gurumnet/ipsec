#ifndef __CRYPTO_H__
#define __CRYPTO_H__

#include <stdio.h>
#include <string.h>
#include <openssl/des.h>
#include <openssl/rand.h>
#include "sa.h"
#include "esp.h"

#define CRYPTO_DES_CBC			0x00
#define CRYPTO_3DES_CBC			0x01
#define CYRPTO_BLOWFISH_CBC		0x02
#define CYRPTO_CAST128_CBC		0x03
#define CYRPTO_DES_DERIV		0x04
#define CYRPTO_3DES_DERIV		0x05
#define CYRPTO_RIJINDAEL_CBC	0x06
#define CYRPTO_TWOFISH_CBC		0x07
#define CYRPTO_AES_CTR			0x08
#define CYRPTO_CAMELLIA_CBC		0x09

typedef struct 
{
	void(*encrypt)(void* payload, size_t size);
	void(*decrypt)(void* payload, size_t size);
} Cryptography;

Cryptography* get_cryptography(int algorithm);

extern SA* current_sa;
#endif 
