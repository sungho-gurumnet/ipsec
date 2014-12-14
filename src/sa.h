#ifndef __SA_H__
#define __SA_H__
#include <openssl/des.h>
#include <stdint.h>
#include <util/list.h>
#include <net/ip.h>
#include <string.h>
#include "window.h"

// Direction
#define IN			0x01
#define OUT			0x02

typedef struct SA {
	uint32_t spi;
	uint32_t src_ip;
	uint32_t src_mask;
	uint32_t dst_ip;
	uint32_t dst_mask;
	uint16_t src_port;
	uint16_t dst_port; 
	uint8_t protocol; 
	uint8_t mode;
	uint8_t lifetime;
 	Window* window;
	void* crypto;
	void* auth;
	uint8_t esp_crypto_algorithm;
	uint64_t esp_crypto_key[3];
	uint8_t esp_auth_algorithm;
	uint64_t esp_auth_key[8];
	uint8_t ah_algorithm;
	uint64_t ah_key[3];
	uint64_t iv;
	int iv_mode;
	uint32_t t_src_ip;
	uint32_t t_dst_ip;
}SA;

SA* sa_create(uint32_t src_ip, uint32_t dst_ip, uint8_t protocol, uint32_t spi, uint8_t extensions, uint8_t crypto_algorithm, uint8_t auth_algorithm, uint64_t crypto_key[], uint64_t auth_key[]);
bool sa_delete(SA* sa);
#endif /* __SA_H__ */
