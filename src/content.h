#ifndef __CONTENT_H__
#define __CONTENT_H__
#include <stdbool.h>
#include "crypto.h"
#include "auth.h"
// Mode
#define TRANSPORT 	0x01
#define TUNNEL 		0x02

typedef struct content{
	uint8_t protocol;
	uint8_t mode;
	uint32_t t_src_ip;
	uint32_t t_dst_ip;
	bool iv_mode;

 	uint8_t crypto_algorithm;
        uint8_t auth_algorithm;
} Content;

Content* create_content(uint8_t protocol, uint8_t mode, uint32_t t_src_ip, uint32_t t_dst_ip, uint8_t crypto_algorithm, uint8_t auth_algorithm);
#endif /*__CONTENT_H__*/
