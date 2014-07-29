#ifndef __NET_IP_H__
#define __NET_IP_H__

#include <byteswap.h>
#include <stdint.h>

#define IP_LEN			20

#define IP_PROTOCOL_ICMP	0x01
#define IP_PROTOCOL_IP 		0x04
#define IP_PROTOCOL_TCP		0x06
#define IP_PROTOCOL_UDP		0x11
#define IP_PROTOCOL_ESP 	0x32
#define IP_PROTOCOL_AH		0x33
typedef struct {
	uint8_t		ihl: 4;
	uint8_t		version: 4;
	uint8_t		ecn: 2;
	uint8_t		dscp: 6;
	uint16_t	length;
	uint16_t	id;
	uint16_t	flags_offset;
	uint8_t		ttl;
	uint8_t		protocol;
	uint16_t	checksum;
	uint32_t	source;
	uint32_t	destination;
	
	uint8_t		body[0];
} __attribute__ ((packed)) IP;

#define endian8(v)  (v)
#define endian16(v) bswap_16((v))
#define endian32(v) bswap_32((v))
#define endian48(v) (bswap_64((v)) >> 16)
#define endian64(v) bswap_64((v))

#endif /* __NET_IP_H__ */
