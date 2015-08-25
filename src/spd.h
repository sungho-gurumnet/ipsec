#ifndef __spd_H__
#define __spd_H__

#include <stdbool.h>
#include <net/ni.h>
#include "sp.h"
//#include "content.h"

#define SPD "net.ipsec.spd"

List* spd_get(NetworkInterface* ni);
SP* spd_get_sp(NetworkInterface* ni, IP* ip);
SP* spd_get_sp_index(NetworkInterface* ni, uint16_t index);
bool spd_add_sp(NetworkInterface* ni, SP* sp, int priority);
bool spd_delete_sp(NetworkInterface* ni, int index);
void spd_delete_all(NetworkInterface* ni);
#endif
