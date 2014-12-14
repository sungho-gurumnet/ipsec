#ifndef __sad_H__
#define __sad_H__

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <net/ip.h>
#include <net/ether.h>
#include <openssl/des.h>
#include <util/map.h>
#include "esp.h"
#include "sa.h"

typedef struct {
	Map* map_spi;
}SAD;

SAD sad;

bool sad_init();
SA* sad_get(uint32_t spi, uint32_t dst_ip, uint8_t protocol);
bool sad_sa_add(SA* sa);
void sad_delete(SA* sa);
#endif
