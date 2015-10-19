#ifndef __CONTENT_H__
#define __CONTENT_H__
#include <stdbool.h>
#include <net/ni.h>
#include "crypto.h"
#include "auth.h"
// Mode

typedef enum {
	NONE,
	CONTENT_IPSEC_MODE,
	CONTENT_TUNNEL_SOURCE_ADDR,
	CONTENT_TUNNEL_DESTINATION_ADDR,
	CONTENT_CRYPTO_ALGORITHM,
	CONTENT_AUTH_ALGORITHM,
} CONTENT_ATTRIBUTES;

typedef struct _Content{
	NetworkInterface* ni;
	uint8_t ipsec_protocol;//rename ipsec_protocol
	uint8_t ipsec_mode; //rename ipsec_mode
} Content;

typedef struct _Content_AH_Transport {
	Content content;

        uint8_t auth_algorithm;
} Content_AH_Transport;

typedef struct _Content_AH_Tunnle {
	Content content;

        uint8_t auth_algorithm;

	uint32_t t_src_ip;
	uint32_t t_dest_ip;
} Content_AH_Tunnel;

typedef struct _Content_ESP_Transport {
	Content content;

	bool iv_mode;
 	uint8_t crypto_algorithm;
        uint8_t auth_algorithm;
} Content_ESP_Transport;

typedef struct _Content_ESP_Tunnel {
	Content content;

	bool iv_mode;
 	uint8_t crypto_algorithm;
        uint8_t auth_algorithm;

	uint32_t t_src_ip;
	uint32_t t_dest_ip;
} Content_ESP_Tunnel;

Content* content_alloc(NetworkInterface* ni, uint64_t* attrs);
void content_free(Content* content);
#endif /*__CONTENT_H__*/
