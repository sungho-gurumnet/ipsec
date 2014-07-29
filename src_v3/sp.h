#ifndef __SP_H__
#define __SP_H__

#include <stdint.h>
#include "list.h"
#include "sa.h"

// Action
#define IPSEC 		0x01
// Mode
#define TRANSPORT 	0x01
#define TUNNEL 		0x02
// Upperspec
#define ICMP6       0x01
#define IP4         0x02
#define GRE         0x03
#define ANY         0x04
// Direction
#define IN          0x01
#define OUT         0x02
// Direction
#define IN			0x01
#define OUT			0x02
// Level
#define DEFAULT     0x01    
#define USE         0x02
#define REQUIRE     0x03
#define UNIQUE      0x04

typedef struct
{
	struct list_head list;
	uint32_t src_ip;
	uint32_t t_src_ip;
	uint32_t dst_ip;
	uint32_t t_dst_ip;
	uint32_t src_mask;
	uint32_t dst_mask;
	uint16_t src_port;
	uint16_t dst_port;
	uint8_t action;
	uint8_t protocol;
	uint8_t mode;
	uint8_t upperspec;
	uint8_t direction;
	uint8_t level;
	SA* sa_pointer;
}__attribute__((packed)) SP;

#endif /* __SP_H__ */
