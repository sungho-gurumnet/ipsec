#ifndef __spd_H__
#define __spd_H__

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <net/ether.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/udp.h>
#include "sa.h"
#include "sp.h"
#include "content.h"

typedef struct {
	List* sp_list;
	size_t max_size;
} SPD;

bool spd_init();
SP* spd_get_index(int index);
SP* spd_get(IP* ip);
bool spd_sp_add(SP* sp, int priority);
bool spd_sp_delete(int index);
void spd_all_delete(void);
#endif
