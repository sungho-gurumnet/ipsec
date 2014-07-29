#ifndef __SP_H__
#define __SP_H__

#include <stdint.h>

//Action
#define IPSEC 		0x01
//Protocol
#define P_IP 		0x04 // 4  (IP) 
#define P_ESP 		0x32 // 50 (ESP)
#define P_AH		0x33 // 51 (AH)
//Mode
#define TRANSPORT 	0x01
#define TUNNEL 		0x02
//Direction
#define IN			0x01
#define OUT			0x02

typedef struct
{
		uint32_t source;
		uint32_t t_source;
		uint32_t destination;
		uint32_t t_destination;
		uint8_t action;
		uint8_t protocol;
		uint8_t mode;
		uint8_t direction;
}__attribute__((packed)) SP;

#endif
