#ifndef __sp_H__
#define __sp_H__

#include <stdint.h>
#include <util/list.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/udp.h>
#include "sa.h"
#include "content.h"

#define IP_ANY	0x0
#define PORT_ANY 0x0
// Action
#define IPSEC 		0x01
#define BYPASS 		0x02
// protocol
#define IP_PROTOCOL_ANY         0x00
#define ICMP6       0x01
#define IP4         0x02
#define GRE         0x03
// Direction
#define IN          0x01
#define OUT         0x02
#define INOUT	    0x03
// Level
#define DEFAULT     0x01    
#define USE         0x02
#define REQUIRE     0x03
#define UNIQUE      0x04

typedef struct SP{
	uint8_t direction;

	uint32_t src_ip;
	uint32_t src_mask;
	bool src_ip_share;
	uint16_t src_port;
	bool src_port_share;
	uint32_t dst_ip;
	uint32_t dst_mask;
	bool dst_ip_share;
	uint16_t dst_port;
	bool dst_port_share;

	uint8_t action;
	uint8_t protocol;
	bool protocol_share;

	List* sa_inbound;
	List* sa_outbound;

	List* contents;
} SP;

SP* sp_create(uint8_t direction, uint32_t src_ip, uint32_t src_mask, uint32_t dst_ip, uint32_t dst_mask, uint16_t src_port, uint16_t dst_port, uint8_t action, uint8_t protocol);
bool sp_delete(SP* sp);
bool sp_content_add(SP* sp, Content* content, int priority);
bool sp_content_delete(SP* sp, int index);
bool sp_sa_add(SP* sp, SA* sa, uint8_t direction);
SA* sp_sa_get(SP* sp, Content* con, IP* ip, uint8_t direction);
#endif /* __sp_H__ */
