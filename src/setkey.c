#include <util/list.h>
#include "sad.h"
#include "spd.h"

#include "setkey.h"

// TODO : Extensions addition, Duplciation check
int setkey_add(uint32_t src_ip, uint32_t dst_ip, uint8_t protocol, uint32_t spi, uint8_t extensions, uint8_t crypto_algorithm, uint8_t auth_algorithm, uint64_t crypto_key[], uint64_t auth_key[]) {
	SA* sa = sa_create(src_ip, dst_ip, protocol, spi, extensions, crypto_algorithm, auth_algorithm, crypto_key, auth_key);

	if(sa == NULL) {
		printf("Can't create the SA\n");
		return -1;
	}

	if(sad_sa_add(sa)) {
		return 0;
	} else {
		printf("Can't add the SA to SAD\n");
		return -2;
	}
}

int setkey_get(uint32_t src_ip, uint32_t dst_ip, uint8_t protocol, uint32_t spi) {
 	SA* tmp = 0;

	ListIterator iter;
	list_iterator_init(&iter, sad);
	while((tmp = list_iterator_next(&iter)) != NULL) {
		if(spi == tmp->spi) {
			if(protocol == tmp->protocol) {
				if(src_ip == tmp->src_ip) {
					if(dst_ip == tmp->dst_ip) {
						printf("SPI : %x\n", tmp->spi);
						printf("Source IP : %x Destination IP : %x\n", tmp->src_ip, tmp->dst_ip);
						printf("Source Port : %d Destination Port : %d\n", tmp->src_port, tmp->dst_port);
						printf("Protocol : %x\n", tmp->protocol);
						printf("ESP Crypto Algorithm : %x\n", tmp->esp_crypto_algorithm); 
						printf("ESP Auth Algorithm : %x\n", tmp->esp_auth_algorithm); 
						printf("Mode ( 1: Transport, 2: Tunnel ) : %d\n", tmp->mode);
						printf("Crypto Key : 0x%lx%lx%lx\n", tmp->esp_crypto_key[0], tmp->esp_crypto_key[1], tmp->esp_crypto_key[2]);
						printf("Auth Key : 0x%lx%lx%lx\n", tmp->esp_auth_key[0], tmp->esp_auth_key[1], tmp->esp_auth_key[2]);
						printf("\n");
					}
				}
			}
		}
	}
	return 0;
}

int setkey_delete(uint32_t src_ip, uint32_t dst_ip, uint8_t protocol, uint32_t spi) {
	/*
	ListIterator iter;
	list_iterator_init(&iter, sad.sa_list);

 	SA* tmp = 0;
	while((tmp = list_iter_next(&iter)) != NULL) {
		if(spi == tmp->spi) {
			if(protocol == tmp->protocol) {
				if(src_ip == tmp->src_ip) {
					if(dst_ip == tmp->dst_ip) {
						free(tmp->window);
						list_del(&(tmp->list));
						free(tmp);

						return 0;
					}
				}
			}
		}
	}

	printf("No matched SA for deleting\n");
	*/
	return 0;
}

int setkey_deleteall(uint32_t src_ip, uint32_t dst_ip, uint8_t protocol) {
	/*
	ListIterator iter;
	list_iterator_init(&iter, sad.sa_list);

 	SA* tmp = 0;
	while((tmp = list_iter_next(&iter)) != NULL) {
		if(protocol == tmp->protocol) {
			if(src_ip == tmp->src_ip) {
				if(dst_ip == tmp->dst_ip) {
					free(tmp->window);				
					list_del(&(tmp->list));
					free(tmp);
				}
			}
		}
	}
	
	printf("No matched SA for deleting\n");
	*/
	return 0;
}

int setkey_flush(uint8_t protocol) {
	/*
	ListIterator iter;
	list_iterator_init(&iter, sad.sa_list);

 	SA* tmp = 0;
	while((tmp = list_iter_next(&iter)) != NULL) {
		if(protocol == 0 || protocol == tmp->protocol) {
			list_remove_data(sad.sa_list, tmp);
			free(tmp);
		}
	}
	*/
	return 0;
}

int setkey_dump(uint8_t protocol) {
	printf("=== SETKEY_DUMP ===\n");
	MapIterator iter_spi;

	map_iterator_init(&iter_spi, sad.map_spi);
	MapEntry* spi_entry;
	while((spi_entry = map_iterator_next(&iter_spi)) != NULL) {
		Map* map_dst_ip = spi_entry->data;
		MapIterator iter_dst_ip;
		map_iterator_init(&iter_dst_ip, map_dst_ip);
		MapEntry* dst_ip_entry;

		while((dst_ip_entry = map_iterator_next(&iter_dst_ip)) != NULL) {
			Map* map_protocol = dst_ip_entry->data;
			MapIterator iter_protocol;
			map_iterator_init(&iter_protocol, map_protocol);
			MapEntry* protocol_entry;

			while((protocol_entry = map_iterator_next(&iter_protocol)) != NULL) {
				SA* sa = protocol_entry->data;

				if(protocol == 0 || protocol == sa->protocol) {
					printf("SPI : %x\n", sa->spi);
					printf("Source IP : %x Destination IP : %x\n", sa->src_ip, sa->dst_ip);
					printf("Source Port : %d Destination Port : %d\n", sa->src_port, sa->dst_port);
					printf("Protocol : %x\n", sa->protocol);
					printf("ESP Crypto Algorithm : %x\n", sa->esp_crypto_algorithm); 
					printf("ESP Auth Algorithm : %x\n", sa->esp_auth_algorithm); 
					printf("Mode ( 1: Transport, 2: Tunnel ) : %d\n", sa->mode);
					printf("Crypto Key : 0x%lx%lx%lx\n", sa->esp_crypto_key[0], sa->esp_crypto_key[1], sa->esp_crypto_key[2]);
					printf("Auth Key : 0x%lx%lx%lx\n", sa->esp_auth_key[0], sa->esp_auth_key[1], sa->esp_auth_key[2]);
					printf("\n");
				}
			}
		}
	}
 	
	return 0;
}

// TODO : Duplication check
int setkey_spdadd(uint32_t src_ip, uint32_t dst_ip, uint32_t src_mask, uint32_t dst_mask, uint16_t src_port, uint16_t dst_port, uint8_t upperspec, uint8_t direction, uint8_t action, uint8_t protocol, uint8_t mode, uint32_t t_src_ip, uint32_t t_dst_ip, uint8_t level) {
	//sp_add(src_ip, dst_ip, src_mask, dst_mask,. srdc_port, dst_port, upperspec, direction, action, protocol, mode, t_src_ip, t_dst_ip, level);
	SP* sp = sp_create(direction, src_ip, src_mask, dst_ip, dst_mask, src_port, dst_port, action, upperspec);
	if(sp == NULL)
		return -1;
	
	spd_sp_add(sp, 0);

	return 0;
}

int setkey_spdupdate(uint32_t src_ip, uint32_t dst_ip, uint32_t src_mask, uint32_t dst_mask, uint16_t src_port, uint16_t dst_port, uint8_t upperspec, uint8_t direction, uint8_t action) {

	/*
 	SP* tmp = 0;
	while((tmp = list_iterator_remove(&iter)) != NULL) {
		if((src_ip & src_mask) == (tmp->src_ip & tmp->src_mask)) {
			if((dst_ip & dst_mask) == (tmp->dst_ip & tmp->dst_mask)) {
				if((src_port == tmp->src_port) && (dst_port == tmp->dst_port)) {
					if(upperspec == tmp->upperspec) {
						tmp->direction = direction;

						tmp->action = action;
					}
				}
			}
		}
	}
	*/
	return 0;
}

int setkey_spddelete(int index) {
	return 0;
}

int setkey_spdflush() {
	/*
	ListIterator iter;
	list_iterator_init(&iter, spd.sp_list);

 	SP* tmp = 0;
	while((tmp = list_iterator_remove(&iter)) != NULL) {
		free(tmp);
	}
	*/
	return 0;
}

int setkey_spddump() {
	printf("=== SETKEY_SPDDUMP ===\n");
	
	SP* tmp;
	while((tmp = list_iterator_next(&iter)) != NULL) {
		printf("Source IP : %x Destination IP : %x\n", tmp->src_ip, tmp->dst_ip);
		printf("Source IP : %x Destination IP : %x (Tunnel)\n ", tmp->t_src_ip, tmp->t_dst_ip);
		printf("Source Mask : %x Destination Mask : %x\n", tmp->src_mask, tmp->dst_mask);
		printf("Source Port : %d Destination Port : %d\n", tmp->src_port, tmp->dst_port);
		printf("Action : %x\n", tmp->action);
		printf("Protocol : %x\n", tmp->protocol);
		printf("Mode ( 1: Transport, 2: Tunnel ) : %d\n", tmp->mode);
		printf("Upperspec : %x\n", tmp->upperspec);
		printf("Direction ( 1: IN,  2: OUT ) : %d \n", tmp->direction);
		printf("Level : %x\n", tmp->level);
		printf("SA Pointer (SPI) : %x\n", tmp->sa_pointer->spi);
		printf("\n");
	}
	return 0;
}
