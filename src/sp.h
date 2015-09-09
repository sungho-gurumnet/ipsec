#ifndef __sp_H__
#define __sp_H__

#include <stdint.h>
#include <util/list.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/udp.h>

#include "sa.h"
#include "content.h"

/* protocol */
#define IP_PROTOCOL_ANY         0x00
/* in net/ip.h */
// #define IP_PROTOCOL_IP          0x04	///< IP protocol number for IP
// #define IP_PROTOCOL_UDP		0x11	///< IP protocol number for UDP
// #define IP_PROTOCOL_TCP		0x06	///< IP protocol number for TCP
#define PORT_ANY		0x00

/* Direction */
#define DIRECTION_IN		0x01
#define DIRECTION_OUT		0x02
//#define DIRECTION_BI		0x03

/* Level */
#define DEFAULT			0x01    
#define USE			0x02
#define REQUIRE			0x03
#define UNIQUE			0x04

typedef enum {
	SP_NONE,
	SP_DIRECTION,
	SP_IPSEC_ACTION,

	SP_PROTOCOL,
	SP_IS_PROTOCOL_SA_SHARE,
	SP_SOURCE_IP,
	SP_IS_SOURCE_IP_SA_SHARE,
	SP_SOURCE_NET_MASK,
	SP_SOURCE_PORT,
	SP_IS_SOURCE_PORT_SA_SHARE,

	SP_OUT_NI,
	SP_DESTINATION_IP,
	SP_IS_DESTINATION_IP_SA_SHARE,
	SP_DESTINATION_NET_MASK,
	SP_DESTINATION_PORT,
	SP_IS_DESTINATION_PORT_SHARE,
} SP_ATTRIBUTES;

typedef struct _SP{
	NetworkInterface* ni;
	NetworkInterface* out_ni;
	uint8_t direction;
	uint8_t ipsec_action;

	uint8_t protocol;
	bool is_protocol_sa_share;

	uint32_t src_ip;
	uint32_t src_mask;
	bool is_src_ip_sa_share;
	uint16_t src_port;
	bool is_src_port_sa_share;

	uint32_t dest_ip;
	uint32_t dest_mask;
	bool is_dest_ip_sa_share;
	uint16_t dest_port;
	bool is_dest_port_sa_share;

	List* sa_list;

	List* contents;
} SP;

SP* sp_alloc(NetworkInterface* ni, uint64_t* attrs);
bool sp_free(SP* sp);
bool sp_add_content(SP* sp, Content* content, int priority);
Content* sp_remove_content(SP* sp, int index);
bool sp_add_sa(SP* sp, SA* sa);
bool sp_remove_sa(SP* sp, SA* sa);
SA* sp_get_sa(SP* sp, IP* ip);
SA* sp_find_sa(SP* sp, IP* ip);
bool sp_verify_sa(SP* sp, List* sa_list, IP* ip);
#endif /* __sp_H__ */
