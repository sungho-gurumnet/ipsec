#ifndef __IPSEC_H__
#define __IPSEC_H__

#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <net/ip.h>
#include <net/checksum.h>
#include <net/packet.h>
#include <net/ether.h>
#include "spd.h"
#include "sad.h"
#include "crypto.h"
#include "auth.h"
#include "receiver.h"
#include "content.h"
#include "ah.h"
#include "socket.h"
#include "ike.h"

int ipsec_inbound(Packet* packet);
int ipsec_outbound(Packet* packet);
bool ipsec_init();

#endif /* __IPSEC_H__ */
