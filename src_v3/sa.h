#ifndef __SA_H__
#define __SA_H__

#include <stdint.h>
#include "list.h"
#include "window.h"

// Direction
#define IN			0x01
#define OUT			0x02

typedef struct _SA
{
	struct list_head list;
	struct _SA* bundle_list;
	uint32_t spi;
	uint32_t src_ip;
	uint32_t dst_ip;
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
	uint64_t esp_auth_key[2];
	uint8_t ah_algorithm;
	uint64_t ah_key[2];
	uint64_t iv;
	int iv_mode;
}__attribute__((packed)) SA;

#endif /* __SA_H__ */
