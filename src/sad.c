#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <malloc.h>
#define DONT_MAKE_WRAPPER
#include <_malloc.h>
#undef DONT_MAKE_WRAPPER
#include <net/ni.h>
#include <net/ip.h>
#include <net/ether.h>
#include <openssl/des.h>
#include <util/map.h>

#include "ipsec.h"
#include "sad.h"
#include "sa.h"
#include "rwlock.h"

// KEY : Packet's dest_ip, ipsec_protocol, spi   

bool sad_init() {
	int count = ni_count();

	for(int i = 0; i < count; i++) {
		NetworkInterface* ni = ni_get(i);
		SAD* sad = __malloc(sizeof(SAD), ni->pool);
		if(!sad) {
			printf("Can't create SAD\n");
			goto fail;
		}
		sad->database = map_create(16, NULL, NULL, ni->pool);
		if(!sad->database) {
			printf("Can't create SAD Map\n");
			__free(sad, ni->pool);

			goto fail;
		}
		sad->rwlock = __malloc(sizeof(RWLock), ni->pool);
		if(!sad->rwlock) {
			printf("Can't create SAD RWLock\n");
			map_destroy(sad->database);
			__free(sad, ni->pool);
			goto fail;
		}
		rwlock_init(sad->rwlock);

		if(!ni_config_put(ni, IPSEC_SAD, sad)) {
			printf("Can't add SAD\n");
			__free(sad->rwlock, ni->pool);
			map_destroy(sad->database);
			__free(sad, ni->pool);
			goto fail;
		}
	}

	return true;

fail:

	for(int i = 0; i < count; i++) {
		NetworkInterface* ni = ni_get(i);
		SAD* sad = ni_config_get(ni, IPSEC_SAD);
		if(!sad) {
			continue;
		}
		map_destroy(sad->database);
		__free(sad->rwlock, ni->pool);
		ni_config_remove(ni, IPSEC_SAD);
	}

	return false;
}

SAD* sad_get(NetworkInterface* ni) {
	return  ni_config_get(ni, IPSEC_SAD);
}

void sad_remove_all(NetworkInterface* ni) {
	SAD* sad = ni_config_get(ni, IPSEC_SAD);

	MapIterator iter;

	map_iterator_init(&iter, sad->database);
	while(map_iterator_has_next(&iter)) {
		MapEntry* entry = map_iterator_next(&iter);
		Map* protocol_map = entry->data;

		MapIterator _iter;
		map_iterator_init(&_iter, protocol_map);
		while(map_iterator_has_next(&_iter)) {
			MapEntry* _entry = map_iterator_next(&_iter);
			SA* sa = _entry->data;
			sa_free(sa);
			map_iterator_remove(&_iter);
		}
		map_destroy(protocol_map);
		map_iterator_remove(&iter);
	}
	map_destroy(sad->database);
	ni_config_remove(ni, IPSEC_SAD);
}

SA* sad_get_sa(NetworkInterface* ni, uint32_t spi, uint32_t dest_ip, uint8_t protocol) {
	SAD* sad = ni_config_get(ni, IPSEC_SAD);

	uint64_t key = ((uint64_t)protocol << 32) | (uint64_t)spi;
	List* dest_list = map_get(sad->database, (void*)key);
	if(!dest_list) {
		return NULL;
	}

	bool compare(void* data, void* context) {
		uint32_t dest_addr = (uint32_t)(uint64_t)data;
		SA* sa = context;

		if(sa->ipsec_mode == IPSEC_MODE_TUNNEL) {
			if(dest_addr == sa->t_dest_ip) { 
				return true;
			}
		} else {
			if((dest_addr & sa->dest_mask) == (sa->dest_ip & sa->dest_mask)) {
				return true;
			}
		}

		return false;
	}

	int index = list_index_of(dest_list, (void*)(uint64_t)dest_ip, compare);
	SA* sa = (SA*)list_get(dest_list, index);
	if(!sa) {
		return NULL;
	}

	return sa;
}

bool sad_add_sa(NetworkInterface* ni, SA* sa) {
	SAD* sad = ni_config_get(ni, IPSEC_SAD);

	uint64_t key = ((uint64_t)sa->ipsec_protocol << 32) | (uint64_t)sa->spi; /* Protocol(8) + SPI(32)*/

	List* dest_list = map_get(sad->database, (void*)key);
	if(!dest_list) {
		dest_list = list_create(ni->pool);
		if(!dest_list) {
			//printf("Can't create list\n");
			goto protocol_map_create_fail;
		}
		if(!map_put(sad->database, (void*)key, dest_list)) {
			//printf("Can't put list\n");
			goto protocol_map_put_fail;
		}
	}

	if(!list_add(dest_list, (void*)(uint64_t)sa)) {
		//printf("Can't add SA\n");
		goto sa_put_fail;
	}

	return true;

sa_put_fail:
protocol_map_put_fail:
	if(list_is_empty(dest_list)) {
		list_destroy(dest_list);
		map_remove(sad->database, (void*)key);
	}

protocol_map_create_fail:

	return false;
}

bool sad_remove_sa(NetworkInterface* ni, uint32_t spi, uint32_t dest_ip, uint8_t protocol) {
	SAD* sad = ni_config_get(ni, IPSEC_SAD);

	uint64_t key = ((uint64_t)protocol << 32) | (uint64_t)spi; /* Protocol(8) + SPI(32)*/

	List* dest_list = map_get(sad->database, (void*)(uint64_t)key);
	if(!dest_list) { 
		//printf("Can'nt found SA\n");

		return false;
	}

	bool compare(void* data, void* context) {
		uint32_t dest_addr = (uint32_t)(uint64_t)context;
		SA* sa = data;

		if((dest_addr & sa->dest_mask) == (sa->dest_ip & sa->dest_mask)) {
			return true;
		}

		return false;
	}

	int index = list_index_of(dest_list, (void*)(uint64_t)dest_ip, compare);
	SA* sa = (SA*)list_remove(dest_list, index);
	if(!sa) { 
		printf("Can'nt found SA\n");
		return false;
	}

	if(list_is_empty(dest_list)) {
		list_destroy(dest_list);
		map_remove(sad->database, (void*)key);
	}

	return sa_free(sa);
}

/* SAD Read & Write Lock */
inline void sad_rlock(NetworkInterface* ni) {
	SAD* sad = ni_config_get(ni, IPSEC_SAD);
	RWLock* rwlock = sad->rwlock;

	rwlock_read_lock(rwlock);
}

inline void sad_un_rlock(NetworkInterface* ni) {
	SAD* sad = ni_config_get(ni, IPSEC_SAD);
	RWLock* rwlock = sad->rwlock;

	rwlock_read_unlock(rwlock);
}

inline void sad_wlock(NetworkInterface* ni) {
	SAD* sad = ni_config_get(ni, IPSEC_SAD);
	RWLock* rwlock = sad->rwlock;

	rwlock_write_lock(rwlock);
}

inline void sad_un_wlock(NetworkInterface* ni) {
	SAD* sad = ni_config_get(ni, IPSEC_SAD);
	RWLock* rwlock = sad->rwlock;

	rwlock_write_unlock(rwlock);
}
