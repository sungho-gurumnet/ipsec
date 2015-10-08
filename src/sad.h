#ifndef __sad_H__
#define __sad_H__

#include <stdbool.h>

#include "sa.h"
#include "rwlock.h"

#define	IPSEC_SAD	"net.ipsec.sad"

typedef struct _SAD {
	Map* database;
	RWLock* rwlock;
} SAD;

bool sad_init();
SAD* sad_get(NetworkInterface* ni);
void sad_remove_all(NetworkInterface* ni);
SA* sad_get_sa(NetworkInterface* ni, uint32_t spi, uint32_t dst_ip, uint8_t protocol);
bool sad_add_sa(NetworkInterface* ni, SA* sa);
bool sad_remove_sa(NetworkInterface* ni, uint32_t spi, uint32_t dest_ip, uint8_t protocol);

void sad_rlock(NetworkInterface* ni);
void sad_un_rlock(NetworkInterface* ni); 
void sad_wlock(NetworkInterface* ni);
void sad_un_wlock(NetworkInterface* ni); 
#endif
