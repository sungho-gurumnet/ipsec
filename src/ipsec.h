#ifndef __IPSEC_H__
#define __IPSEC_H__

#include <stdbool.h>
#include <net/packet.h>

bool ipsec_process(Packet* packet);
bool ipsec_init();

#endif /* __IPSEC_H__ */
