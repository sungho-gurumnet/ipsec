#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <net/ni.h>
#include <net/ip.h>
#include <net/ether.h>
#include <openssl/des.h>
#include <util/map.h>

#include "sad.h"
#include "sa.h"

// KEY : Packet's dest_ip, ipsec_protocol, spi   
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
}

SA* sad_get_sa(NetworkInterface* ni, uint32_t spi, uint32_t dest_ip, uint8_t protocol) {
	Map* sad = ni_config_get(ni, SAD);
	if(!sad) {
		printf("Can'nt found SA\n");
		return NULL;
	}

	uint64_t key = ((uint64_t)endian32(spi) << 32) | (uint64_t)dest_ip;
	Map* protocol_map = map_get(sad, (void*)key);
	if(protocol_map == NULL) {
		printf("Can'nt found SA\n");
		return NULL;
	}

	SA* sa = map_get(protocol_map, (void*)(uint64_t)protocol);
	if(!sa) {
		printf("Can'nt found SA\n");
		return NULL;
	}

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

	uint64_t key = ((uint64_t)endian32(sa->spi) << 32) | (uint64_t)sa->dest_ip; /* SPI(32) + Destination Address(32)*/

	Map* protocol_map = map_get(sad, (void*)key);
	if(!protocol_map) {
		protocol_map = map_create(8, NULL, NULL, ni->pool);
		if(!protocol_map) {
			printf("Can'nt create map\n");
			goto protocol_map_create_fail;
		}
		if(!map_put(sad, (void*)key, protocol_map)) {
			printf("Can'nt put map\n");
			goto protocol_map_put_fail;
		}
	}

	if(!map_put(protocol_map, (void*)(uint64_t)sa->protocol, (void*)(uint64_t)sa))
		goto sa_put_fail;

	return true;

sa_put_fail:
protocol_map_put_fail:
	if(map_is_empty(protocol_map)) {
		map_destroy(protocol_map);
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

	uint64_t key = ((uint64_t)spi << 32) | (uint64_t)dest_ip;

	Map* protocol_map = map_get(sad, (void*)(uint64_t)key);
	if(!protocol_map) { 
		printf("Can'nt found SA\n");
		return NULL;
	}

	SA* sa = (SA*)map_remove(protocol_map, (void*)(uint64_t)protocol);
	if(!sa) { 
		printf("Can'nt found SA\n");
		return NULL;
	}

	if(map_is_empty(protocol_map)) {
		map_destroy(protocol_map);
		map_remove(sad, (void*)key);
	}

	return sa;
}

void sad_dump(NetworkInterface* ni) {
 //	Map* sad = ni_config_get(ni, SAD);
 //	if(!sad)
 //		return;
 //
 //	int index = 0;
 //	MapIterator iter;
 //	map_iterator_init(&iter, sad);
 //	while(map_iterator_has_next(&iter)) {
 //		MapEntry* entry = map_iterator_next(&iter);
 //
 //		MapIterator _iter;
 //		map_iterator_init(&_iter, entry->data);
 //		while(map_iterator_has_next(&_iter)) {
 //			MapEntry* _entry = map_iterator_next(&_iter);
 //			SA* sa = _entry->data;
 //
 //			void protocol_dump(uint8_t protocol) {
 //				switch(protocol) {
 //					case IP_PROTOCOL_ESP:
 //						printf("ESP");
 //						break;
 //					case IP_PROTOCOL_AH:
 //						printf("AH");
 //						break;
 //				}
 //			}
 //
 //			printf("INDEX[%d] ", index++);
 //			printf("Protocol ");
 //			protocol_dump(sa->protocol);
 //			printf("\n");
 //			printf("Source ip %x mask %x port %d\n", sa->src_ip, sa->src_port);
 //			printf("Destination ip %x mask %x port %d\n", sa->dest_ip, sa->dest_port);
 //			for(int i = 0; i < 3; i++)
 //				printf("%d %0x\n", i, sa->esp_crypto_key[i]);
 //			for(int i = 0; i < 8; i++)
 //				printf("%d %0x\n", i, sa->esp_auth_key[i]);
 //			
 //		}
 //	}
}
