#ifndef __sp_H__
#define __sp_H__

#include <stdint.h>
#include <util/list.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/udp.h>

#include "sa.h"
#include "content.h"

/* Action */
#define BYPASS 		0x00
#define IPSEC 		0x01
/* protocol */
#define IP_PROTOCOL_ANY         0x00
// #define IP_PROTOCOL_IP          0x04	///< IP protocol number for IP
// #define IP_PROTOCOL_UDP		0x11	///< IP protocol number for UDP
// #define IP_PROTOCOL_TCP		0x06	///< IP protocol number for TCP

/* Direction */
#define IN          0x01
#define OUT         0x02
#define INOUT	    0x03
/* Level */
#define DEFAULT     0x01    
#define USE         0x02
#define REQUIRE     0x03
#define UNIQUE      0x04

typedef enum {
	SP_NONE,
	SP_DIRECTION,

	SP_PROTOCOL,
	SP_IS_PROTOCOL_SA_SHARE,
	SP_SOURCE_IP_ADDR,
	SP_IS_SOURCE_IP_SA_SHARE,
	SP_SOURCE_NET_MASK,
	SP_SOURCE_PORT,
	SP_IS_SOURCE_PORT_SA_SHARE,

	SP_OUT_NI,
	SP_DESTINATION_IP_ADDR,
	SP_IS_DESTINATION_IP_SA_SHARE,
	SP_DESTINATION_NET_MASK,
	SP_DESTINATION_PORT,
	SP_IS_DESTINATION_PORT_SHARE,

	SP_ACTION,
} SP_ATTRIBUTES;

typedef struct _SP{
	uint8_t direction;

	uint8_t protocol;
	bool is_protocol_sa_share;

	uint32_t src_ip;
	uint32_t src_mask;
	bool is_src_ip_sa_share;
	uint16_t src_port;
	bool is_src_port_sa_share;

	NetworkInterface* out_ni;
	uint32_t dest_ip;
	uint32_t dest_mask;
	bool is_dest_ip_sa_share;
	uint16_t dest_port;
	bool is_dest_port_sa_share;

	uint8_t action;

	List* sa_inbound;
	List* sa_outbound;

	List* contents;
} SP;

SP* sp_alloc(NetworkInterface* ni, uint64_t* attrs);
bool sp_free(NetworkInterface* ni, SP* sp);
bool sp_content_add(SP* sp, Content* content, int priority);
bool sp_content_delete(SP* sp, int index);
bool sp_sa_add(SP* sp, SA* sa, uint8_t direction);
SA* sp_sa_get(SP* sp, Content* con, IP* ip, uint8_t direction);
#endif /* __sp_H__ */
