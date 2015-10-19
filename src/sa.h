#ifndef __SA_H__
#define __SA_H__
#include <stdbool.h>
#include <openssl/des.h>
#include <stdint.h>
#include <util/list.h>
#include <net/ip.h>
#include <net/ni.h>
#include <string.h>

#include "window.h"
//#include "crypto.h"
//#include "auth.h"

typedef enum {
	SA_NONE,
	SA_IPSEC_MODE,
	SA_TUNNEL_SOURCE_IP,
	SA_TUNNEL_DESTINATION_IP,
	SA_SPI,
	SA_PROTOCOL,
	SA_SOURCE_IP,
	SA_SOURCE_MASK,
	SA_DESTINATION_IP,
	SA_DESTINATION_MASK,
	SA_SOURCE_PORT,
	SA_DESTINATION_PORT,

	SA_CRYPTO_ALGORITHM,
	SA_CRYPTO_KEY,
	SA_CRYPTO_KEY_LENGTH,
	SA_IV_SUPPORT,
	SA_AUTH_ALGORITHM,
	SA_AUTH_KEY,
	SA_AUTH_KEY_LENGTH,

	SA_REPLY,
} SA_ATTRIBUTES;

typedef struct _SA {
	NetworkInterface* ni;
	uint8_t ipsec_protocol;
	uint8_t ipsec_mode;
	uint32_t t_src_ip;
	uint32_t t_dest_ip;
	uint32_t spi;
	uint32_t src_ip;
	uint32_t src_mask;
	uint32_t dest_ip;
	uint32_t dest_mask;
	uint16_t src_port;
	uint16_t dest_port; 
	uint8_t protocol; 
	uint32_t lifetime; //not working
 	Window* window;

	struct _SA* next;
} SA;

typedef struct _SA_ESP {
	SA sa;
	uint64_t iv;
	uint8_t crypto_algorithm;
	void* crypto;
	uint64_t* crypto_key;
	uint16_t crypto_key_length;
	void* encrypt_key;
	void* decrypt_key;

	uint8_t auth_algorithm;
	void* auth;
	uint64_t* auth_key;
	uint16_t auth_key_length;
} SA_ESP;

typedef struct _SA_AH {
	SA sa;
	uint8_t auth_algorithm;
	void* auth;
	uint64_t* auth_key;
	uint16_t auth_key_length;
} SA_AH;

SA* sa_alloc(NetworkInterface* ni, uint64_t* attrs);
bool sa_free(SA* sa);
#endif /* __SA_H__ */
