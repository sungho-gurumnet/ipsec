#ifndef __spd_H__
#define __spd_H__

#include <stdbool.h>
#include <net/ni.h>
#include "sp.h"
//#include "content.h"

#define SPD_IN		"net.ipsec.spd_in"
#define SPD_OUT 	"net.ipsec.spd_out"

List* spd_get(NetworkInterface* ni, uint8_t direction);
SP* spd_get_sp(NetworkInterface* ni, uint8_t direction, IP* ip);
SP* spd_get_sp_index(NetworkInterface* ni, uint8_t direction, uint16_t index);
bool spd_add_sp(NetworkInterface* ni, uint8_t direction, SP* sp, int priority);
void spd_delete_all(NetworkInterface* ni, uint8_t direction);
#endif
