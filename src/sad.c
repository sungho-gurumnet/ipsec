#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <net/ni.h>
#include <net/ip.h>
#include <net/ether.h>
#include <openssl/des.h>
#include <util/map.h>

#include "ipsec.h"
#include "sad.h"
#include "sa.h"

// KEY : Packet's dest_ip, ipsec_protocol, spi   

Map* sad_get(NetworkInterface* ni) {
	return  ni_config_get(ni, SAD);
}

void sad_remove_all(NetworkInterface* ni) {
	Map* sad = ni_config_get(ni, SAD);
	if(!sad)
		return;

	MapIterator iter;
	map_iterator_init(&iter, sad);
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
	map_destroy(sad);
	ni_config_remove(ni, SAD);
}

SA* sad_get_sa(NetworkInterface* ni, uint32_t spi, uint32_t dest_ip, uint8_t protocol) {
	Map* sad = ni_config_get(ni, SAD);
	if(!sad)
		return NULL;

	uint64_t key = ((uint64_t)protocol << 32) | (uint64_t)spi;
	List* dest_list = map_get(sad, (void*)key);
	if(!dest_list)
		return NULL;

	bool compare(void* data, void* context) {
		uint32_t dest_addr = (uint32_t)(uint64_t)data;
		SA* sa = context;

		if(sa->ipsec_mode == IPSEC_MODE_TUNNEL) {
			if(dest_addr == sa->t_dest_ip)
				return true;
		} else {
			if((dest_addr & sa->dest_mask) == (sa->dest_ip & sa->dest_mask))
				return true;
		}

		return false;
	}

	int index = list_index_of(dest_list, (void*)(uint64_t)dest_ip, compare);
	SA* sa = (SA*)list_get(dest_list, index);
	if(!sa)
		return NULL;

	return sa;
}

bool sad_add_sa(NetworkInterface* ni, SA* sa) {
	Map* sad = ni_config_get(ni, SAD);
	if(!sad) {
		sad = map_create(16, NULL, NULL, ni->pool);
		if(!sad) {
			printf("Can'nt create SAD\n");
			goto sad_create_fail;
		}
		if(!ni_config_put(ni, SAD, sad)) {
			printf("Can'nt add SAD\n");
			goto sad_put_fail;
		}
	}

	uint64_t key = ((uint64_t)sa->ipsec_protocol << 32) | (uint64_t)sa->spi; /* Protocol(8) + SPI(32)*/

	List* dest_list = map_get(sad, (void*)key);
	if(!dest_list) {
		dest_list = list_create(ni->pool);
		if(!dest_list) {
			printf("Can'nt create map\n");
			goto protocol_map_create_fail;
		}
		if(!map_put(sad, (void*)key, dest_list)) {
			printf("Can'nt put map\n");
			goto protocol_map_put_fail;
		}
	}

	if(!list_add(dest_list, (void*)(uint64_t)sa))
		goto sa_put_fail;

	return true;

sa_put_fail:
protocol_map_put_fail:
	if(list_is_empty(dest_list)) {
		list_destroy(dest_list);
		map_remove(sad, (void*)key);
	}
protocol_map_create_fail:
sad_put_fail:
	if(map_is_empty(sad)) {
		map_destroy(sad);
		ni_config_remove(ni, SAD);
	}

sad_create_fail:
	return false;
}

SA* sad_remove_sa(NetworkInterface* ni, uint32_t spi, uint32_t dest_ip, uint8_t protocol) {
	Map* sad = ni_config_get(ni, SAD);
	if(!sad) {
		printf("Can'nt found SA\n");
		return NULL;
	}

	uint64_t key = ((uint64_t)protocol << 32) | (uint64_t)spi; /* Protocol(8) + SPI(32)*/

	List* dest_list = map_get(sad, (void*)(uint64_t)key);
	if(!dest_list) { 
		printf("Can'nt found SA\n");
		return NULL;
	}

	bool compare(void* data, void* context) {
		uint32_t dest_addr = (uint32_t)(uint64_t)context;
		SA* sa = data;

		if((dest_addr & sa->dest_mask) == (sa->dest_ip & sa->dest_mask))
			return true;

		return false;
	}

	int index = list_index_of(dest_list, (void*)(uint64_t)dest_ip, compare);
	SA* sa = (SA*)list_remove(dest_list, index);
	if(!sa) { 
		printf("Can'nt found SA\n");
		return NULL;
	}

	if(list_is_empty(dest_list)) {
		list_destroy(dest_list);
		map_remove(sad, (void*)key);
	}
	
	if(map_is_empty(sad)) {
		map_destroy(sad);
		ni_config_remove(ni, SAD);
	}

	return sa;
}
