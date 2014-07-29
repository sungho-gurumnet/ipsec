#ifndef __IPSEC_H__
#define __IPSEC_H__

#include "common.h"

int IPSecModule(void);
int inbound(IP* packet);
int outbound(IP* packet);
#endif
