#ifndef __IPSEC_H__
#define __IPSEC_H__

#include <stdbool.h>
#include <net/packet.h>

/* Action */
#define IPSEC_ACTION_BYPASS		0x00
#define IPSEC_ACTION_IPSEC		0x01

#define IPSEC_MODE_TRANSPORT 		0x01
#define IPSEC_MODE_TUNNEL 		0x02

bool ipsec_process(Packet* packet);
bool ipsec_init();

#endif /* __IPSEC_H__ */
