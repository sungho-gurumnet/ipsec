#include "sad.h"
#include "content.h"

// KEY : Packet's dst_ip, ipsec_protocol, spi   
bool sad_init() {
	sad.map_spi = map_create(4096, NULL, NULL, NULL);
	if(sad.map_spi == NULL)
		return false;
	else
		return true;
}

SA* sad_get(uint32_t spi, uint32_t dst_ip, uint8_t protocol) {
	Map* map_dst_ip = map_get(sad.map_spi, (void*)(uint64_t)endian32(spi));
	if(map_dst_ip == NULL)
		return NULL;

	Map* map_sad = map_get(map_dst_ip, (void*)(uint64_t)endian32(dst_ip));
	if(map_sad == NULL)
		return NULL;

	return map_get(map_sad, (void*)(uint64_t)protocol);
}

bool sad_sa_add(SA* sa) {
	Map* map_dst_ip = map_get(sad.map_spi, (void*)(uint64_t)sa->spi);
	if(map_dst_ip == NULL) {
		map_dst_ip = map_create(4096, NULL, NULL, NULL);
		map_put(sad.map_spi, (void*)(uint64_t)sa->spi, (void*)(uint64_t)map_dst_ip);
	}
	Map* map_sad = map_get(map_dst_ip, (void*)(uint64_t)sa->dst_ip);
	if(map_sad == NULL) {
		map_sad = map_create(4096, NULL, NULL, NULL);
		map_put(map_dst_ip, (void*)(uint64_t)sa->dst_ip, (void*)(uint64_t)map_sad);
	}

	return map_put(map_sad, (void*)(uint64_t)sa->protocol, (void*)(uint64_t)sa);
}

void sad_delete(SA* sa) {
	Map* map_dst_ip = map_get(sad.map_spi, (void*)(uint64_t)endian32(sa->spi));

	Map* map_sad = NULL;
	if(map_dst_ip != NULL)
		map_sad = map_get(map_dst_ip, (void*)(uint64_t)endian32(sa->dst_ip)); 
	else
		return;

	if(map_sad != NULL)
		sa = (SA*)map_remove(map_sad, (void*)(uint64_t)sa->protocol);
	else
		return;

	if(sa != NULL)
		free(sa);

	if(map_is_empty(map_sad)) {
		map_remove(map_dst_ip, (void*)(uint64_t)endian32(sa->dst_ip));
		map_destroy(map_sad);
		if(map_is_empty(map_dst_ip)) {
			map_remove(sad.map_spi, (void*)(uint64_t)endian32(sa->spi));
			map_destroy(map_dst_ip);
		}
	}
}

void sad_dump() {
	MapEntry* entry;
	int index = 0;

	MapIterator iter_spi;
	map_iterator_init(&iter_spi, sad.map_spi);
	while(map_iterator_has_next(&iter_spi)) {
		entry = map_iterator_next(&iter_spi);
		MapIterator iter_dst_ip;
		map_iterator_init(&iter_dst_ip, entry->data);

		while(map_iterator_has_next(&iter_dst_ip)) {
			entry = map_iterator_next(&iter_dst_ip);
			MapIterator iter_sad;
			map_iterator_init(&iter_sad, entry->data);

			while(map_iterator_has_next(&iter_sad)) {
				MapEntry* entry = map_iterator_next(&iter_sad);
				SA* sa = entry->data;

				void protocol_dump(uint8_t protocol) {
					switch(protocol) {
						case IP_PROTOCOL_ESP:
							printf("ESP");
							break;
						case IP_PROTOCOL_AH:
							printf("AH");
							break;
					}
				}

				printf("INDEX[ %d] ", index++);
				printf("Protocol ");
				protocol_dump(sa->protocol);
				printf("\n");
				printf("Source ip %x mask %x port %d\n", sa->src_ip, sa->src_mask, sa->src_port);
				printf("Destination ip %x mask %x port %d\n", sa->dst_ip, sa->dst_mask, sa->dst_port);
				for(int i = 0; i < 3; i++)
					printf("%d %0x\n", i, sa->esp_crypto_key[i]);
				for(int i = 0; i < 8; i++)
					printf("%d %0x\n", i, sa->esp_auth_key[i]);
				
			}
		}
	}

}
