#include <stdio.h>

#include <stdint.h>
#include <malloc.h>
#define DONT_MAKE_WRAPPER
#include <_malloc.h>
#undef DONT_MAKE_WRAPPER
#include <net/ether.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <util/list.h>

#include "spd.h"
#include "sp.h"
#include "rwlock.h"

bool spd_init() {
	int count = ni_count();

	for(int i = 0; i < count; i++) {
		NetworkInterface* ni = ni_get(i);
		SPD* spd = __malloc(sizeof(SPD), ni->pool);
		if(!spd) {
			printf("Can't create SPD\n");
			goto fail;
		}

		spd->out_database = list_create(ni->pool);
		if(!spd->out_database) {
			__free(spd, ni->pool);
			printf("Can't create SPD Outbound Database\n");
			goto fail;
		}
		spd->out_rwlock = __malloc(sizeof(RWLock), ni->pool);
		if(!spd->out_rwlock) {
			list_destroy(spd->out_database);
			__free(spd, ni->pool);
			printf("Can't create SPD Outbound RWLock\n");
			goto fail;
		}
		rwlock_init(spd->out_rwlock);

		spd->in_database = list_create(ni->pool);
		if(!spd->in_database) {
			__free(spd->out_rwlock, ni->pool);
			list_destroy(spd->out_database);
			__free(spd, ni->pool);
			printf("Can't create SPD Outbound Database\n");
			goto fail;
		}
		spd->in_rwlock = __malloc(sizeof(RWLock), ni->pool);
		if(!spd->in_rwlock) {
			list_destroy(spd->in_database);
			__free(spd->out_rwlock, ni->pool);
			list_destroy(spd->out_database);
			__free(spd, ni->pool);
			printf("Can't create SPD Outbound RWLock\n");
			goto fail;
		}
		rwlock_init(spd->in_rwlock);

		if(!ni_config_put(ni, IPSEC_SPD, spd)) {
			__free(spd->in_rwlock, ni->pool);
			list_destroy(spd->in_database);
			__free(spd->out_rwlock, ni->pool);
			list_destroy(spd->out_database);
			__free(spd, ni->pool);
			printf("Can't add SPD Outbound\n");
			goto fail;
		}
	}

	return true;

fail:
	for(int i = 0; i < count; i++) {
		NetworkInterface* ni = ni_get(i);
		SPD* spd = ni_config_get(ni, IPSEC_SPD);
		if(!spd)
			continue;

		list_destroy(spd->out_database);
		__free(spd->out_rwlock, ni->pool);
		list_destroy(spd->in_database);
		__free(spd->in_rwlock, ni->pool);

		ni_config_remove(ni, IPSEC_SPD);
	}

	return false;
}

SPD* spd_get(NetworkInterface* ni) {
	return ni_config_get(ni, IPSEC_SPD);
}

SP* spd_get_sp_index(NetworkInterface* ni, uint8_t direction, uint16_t index) {
	SPD* spd = ni_config_get(ni, IPSEC_SPD);
	SP* sp = NULL;
	switch(direction) {
		case DIRECTION_OUT:
			;
			sp = list_get(spd->out_database, index);

			break;
		case DIRECTION_IN:
			;
			sp = list_get(spd->in_database, index);

			break;
	}

	return sp;
}

SP* spd_get_sp(NetworkInterface* ni, uint8_t direction, IP* ip) {
	SPD* spd = ni_config_get(ni, IPSEC_SPD);
	List* database = NULL;
	switch(direction) {
		case DIRECTION_OUT:
			database = spd->out_database;
			break;
		case DIRECTION_IN:
			database = spd->in_database;
			break;
	}

	ListIterator iter;

	list_iterator_init(&iter, database);
	while(list_iterator_has_next(&iter)) {
		SP* sp = list_iterator_next(&iter);
		if(sp->protocol && (ip->protocol != sp->protocol))
			continue;

		if(sp->src_ip && ((endian32(ip->source) & sp->src_mask) != (sp->src_ip & sp->src_mask)))
			continue;

		if(sp->dest_ip && ((endian32(ip->destination) & sp->dest_mask) != (sp->dest_ip & sp->dest_mask)))
			continue;

		switch(ip->protocol) {
			case IP_PROTOCOL_TCP:
				;
				TCP* tcp = (TCP*)ip->body;
				if(sp->src_port && (endian16(tcp->source) != sp->src_port))
					continue;

				if(sp->dest_port && (endian16(tcp->destination) != sp->dest_port))
					continue;

				return sp;
			case IP_PROTOCOL_UDP:
				;
				UDP* udp = (UDP*)ip->body;
				if(sp->src_port && (endian16(udp->source) != sp->src_port))
					continue;

				if(sp->dest_port && (endian16(udp->destination) != sp->dest_port))
					continue;

				return sp;

			default:
				return sp;
		}
	}

	return NULL;
}

bool spd_add_sp(NetworkInterface* ni, uint8_t direction, SP* sp, int priority) {
	SPD* spd = ni_config_get(ni, IPSEC_SPD);
	List* database = NULL;
	switch(direction) {
		case DIRECTION_OUT:
			database = spd->out_database;
			break;
		case DIRECTION_IN:
			database = spd->in_database;
			break;
	}

	bool result = list_add_at(database, priority, sp);

	return result;
}

bool spd_remove_sp(NetworkInterface* ni, uint8_t direction, int index) {
	SPD* spd = ni_config_get(ni, IPSEC_SPD);
	List* database = NULL;
	switch(direction) {
		case DIRECTION_OUT:
			database = spd->out_database;
			break;
		case DIRECTION_IN:
			database = spd->in_database;
			break;
	}

	SP* sp = list_remove(database, index);
	sp_free(sp);

	return sp;
}

void spd_delete_all(NetworkInterface* ni, uint8_t direction) {
	SPD* spd = ni_config_get(ni, IPSEC_SPD);
	List* database = NULL;
	switch(direction) {
		case DIRECTION_OUT:
			database = spd->out_database;
			break;
		case DIRECTION_IN:
			database = spd->in_database;
			break;
	}

	ListIterator iter;
	list_iterator_init(&iter, database);
	while((list_iterator_has_next(&iter))) {
		SP* sp = list_iterator_remove(&iter);
		sp_free(sp);
	}
}

/* SPD Read & Write Lock */
inline void spd_inbound_rlock(NetworkInterface* ni) {
	SPD* spd = ni_config_get(ni, IPSEC_SPD);
	RWLock* rwlock = spd->in_rwlock;

	rwlock_read_lock(rwlock);
}

inline void spd_inbound_un_rlock(NetworkInterface* ni) {
	SPD* spd = ni_config_get(ni, IPSEC_SPD);
	RWLock* rwlock = spd->in_rwlock;

	rwlock_read_unlock(rwlock);
}

inline void spd_inbound_wlock(NetworkInterface* ni) {
	SPD* spd = ni_config_get(ni, IPSEC_SPD);
	RWLock* rwlock = spd->in_rwlock;

	rwlock_write_lock(rwlock);
}

inline void spd_inbound_un_wlock(NetworkInterface* ni) {
	SPD* spd = ni_config_get(ni, IPSEC_SPD);
	RWLock* rwlock = spd->in_rwlock;

	rwlock_write_unlock(rwlock);
}

inline void spd_outbound_rlock(NetworkInterface* ni) {
	SPD* spd = ni_config_get(ni, IPSEC_SPD);
	RWLock* rwlock = spd->out_rwlock;

	rwlock_read_lock(rwlock);
}

inline void spd_outbound_un_rlock(NetworkInterface* ni) {
	SPD* spd = ni_config_get(ni, IPSEC_SPD);
	RWLock* rwlock = spd->out_rwlock;

	rwlock_read_unlock(rwlock);
}

inline void spd_outbound_wlock(NetworkInterface* ni) {
	SPD* spd = ni_config_get(ni, IPSEC_SPD);
	RWLock* rwlock = spd->out_rwlock;

	rwlock_write_lock(rwlock);
}

inline void spd_outbound_un_wlock(NetworkInterface* ni) {
	SPD* spd = ni_config_get(ni, IPSEC_SPD);
	RWLock* rwlock = spd->out_rwlock;

	rwlock_write_unlock(rwlock);
}
