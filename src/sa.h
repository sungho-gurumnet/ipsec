#ifndef __SA_H__
#define __SA_H__
#include <stdbool.h>
#include <openssl/des.h>
#include <stdint.h>
#include <util/list.h>
#include <net/ip.h>
#include <string.h>

#include "window.h"
//#include "crypto.h"
//#include "auth.h"

// Direction
#define IN			0x01
#define OUT			0x02

typedef enum {
	SA_NONE,
	SA_SPI,

	SA_IPSEC_PROTOCOL,
	SA_PROTOCOL,
	SA_SOURCE_IP,
	SA_SOURCE_MASK,
	SA_DESTINATION_IP,
	SA_DESTINATION_MASK,
	SA_SOURCE_PORT,
	SA_DESTINATION_PORT,

	SA_CRYPTO_ALGORITHM,
	SA_CRYPTO_KEY,
	SA_IV_SUPPORT,
	SA_AUTH_ALGORITHM,
	SA_AUTH_KEY,

	SA_REPLY,
} SA_ATTRIBUTES;

typedef struct _SA {
	struct _SA* next;
	uint32_t spi;
	uint32_t src_ip;
	uint32_t src_mask;
	uint32_t dest_ip;
	uint32_t dest_mask;
	uint16_t src_port;
	uint16_t dest_port; 
	uint8_t protocol; 
	uint8_t mode;
	uint8_t lifetime;
 	Window* window;
} SA;

typedef struct _SA_ESP {
	SA sa;
	uint64_t iv;
	uint8_t crypto_algorithm;
	void* crypto;
	uint64_t* crypto_key;

	bool iv_support;
	uint8_t auth_algorithm;
	void* auth;
	uint64_t* auth_key;
} SA_ESP;

typedef struct _SA_AH {
	SA sa;
	uint8_t auth_algorithm;
	void* auth;
	uint64_t* auth_key;
} SA_AH;

SA* sa_alloc(NetworkInterface* ni, uint64_t* attrs);
bool sa_free(SA* sa);
#endif /* __SA_H__ */
