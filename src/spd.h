#ifndef __spd_H__
#define __spd_H__

#include <stdbool.h>
#include <net/ni.h>
#include "sp.h"
#include "rwlock.h"

#define IPSEC_SPD	"net.ipsec.spd"

typedef struct _SPD {
	List* out_database;
	RWLock* out_rwlock;
	List* in_database;
	RWLock* in_rwlock;
} SPD;

bool spd_init();
SPD* spd_get(NetworkInterface* ni);
SP* spd_get_sp(NetworkInterface* ni, uint8_t direction, IP* ip);
SP* spd_get_sp_index(NetworkInterface* ni, uint8_t direction, uint16_t index);
bool spd_add_sp(NetworkInterface* ni, uint8_t direction, SP* sp, int priority);
bool spd_remove_sp(NetworkInterface* ni, uint8_t direction, int index);
void spd_delete_all(NetworkInterface* ni, uint8_t direction);

void spd_inbound_rlock(NetworkInterface* ni);
void spd_inbound_un_rlock(NetworkInterface* ni); 
void spd_inbound_wlock(NetworkInterface* ni);
void spd_inbound_un_wlock(NetworkInterface* ni); 
void spd_outbound_rlock(NetworkInterface* ni);
void spd_outbound_un_rlock(NetworkInterface* ni);
void spd_outbound_wlock(NetworkInterface* ni);
void spd_outbound_un_wlock(NetworkInterface* ni);
#endif
