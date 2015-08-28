#ifndef __IKE_H__
#define __IKE_H__
#include <net/ip.h>
#include <stdbool.h>
#include "sp.h"
#include "content.h"

typedef struct _IKE {
	uint32_t ip;
	uint16_t port;
} IKE;

bool ike_init();
SA* ike_sa_get(IP* ip, SP* sp);

#endif
