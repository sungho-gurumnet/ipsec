#include <stdio.h>
#include <stdint.h>
#include <net/ether.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <util/list.h>

#include "spd.h"
#include "sp.h"

List* spd_get(NetworkInterface* ni, uint8_t direction) {
	List* spd = NULL;

	switch(direction) {
		case DIRECTION_IN:
			spd = ni_config_get(ni, SPD_IN);
			break;
		case DIRECTION_OUT:
			spd = ni_config_get(ni, SPD_OUT);
			break;
	}

	return spd;
}

SP* spd_get_sp_index(NetworkInterface* ni, uint8_t direction, uint16_t index) {
	List* spd = NULL;
	switch(direction) {
		case DIRECTION_IN:
			spd = ni_config_get(ni, SPD_IN);
			break;
		case DIRECTION_OUT:
			spd = ni_config_get(ni, SPD_OUT);
			break;
	}
	if(!spd)
		return NULL;

	return list_get(spd, index);
}

SP* spd_get_sp(NetworkInterface* ni, uint8_t direction, IP* ip) {
	List* spd = NULL;
	switch(direction) {
		case DIRECTION_IN:
			spd = ni_config_get(ni, SPD_IN);
			break;
		case DIRECTION_OUT:
			spd = ni_config_get(ni, SPD_OUT);
			break;
	}
	if(!spd)
		return NULL;

	ListIterator iter;
	list_iterator_init(&iter, spd);
	
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
	List* spd = NULL;
	switch(direction) {
		case DIRECTION_IN:
			spd = ni_config_get(ni, SPD_IN);
			if(!spd) {
				spd = list_create(ni->pool);
			}
			if(!spd) { 
				printf("Can'nt create SPD\n");
				return false;
			}
			if(!ni_config_put(ni, SPD_IN, spd)) {
				list_destroy(spd);
				printf("Can'nt add SPD\n");
				return false;
			}
			break;
		case DIRECTION_OUT:
			spd = ni_config_get(ni, SPD_OUT);
			if(!spd) {
				spd = list_create(ni->pool);
			}
			if(!spd) { 
				printf("Can'nt create SPD\n");
				return false;
			}
			if(!ni_config_put(ni, SPD_OUT, spd)) {
				list_destroy(spd);
				printf("Can'nt add SPD\n");
				return false;
			}
			break;
	}

	return list_add_at(spd, priority, sp);
}

SP* spd_remove_sp(NetworkInterface* ni, uint8_t direction, int index) {
	List* spd = NULL;
	switch(direction) {
		case DIRECTION_IN:
			spd = ni_config_get(ni, SPD_IN);
			break;
		case DIRECTION_OUT:
			spd = ni_config_get(ni, SPD_OUT);
			break;
	}
	if(!spd)
		return NULL;

	SP* sp = list_remove(spd, index);
	if(!sp) {
		printf("Can'nt found SP\n");
		return NULL;
	}

	if(list_is_empty(spd)) {
		list_destroy(spd);
		switch(direction) {
			case DIRECTION_IN:
				ni_config_remove(ni, SPD_IN);
				break;
			case DIRECTION_OUT:
				ni_config_remove(ni, SPD_OUT);
				break;
		}
	}

	return sp;
}

void spd_delete_all(NetworkInterface* ni, uint8_t direction) {
	List* spd = NULL;
	switch(direction) {
		case DIRECTION_IN:
			spd = ni_config_get(ni, SPD_IN);
			break;
		case DIRECTION_OUT:
			spd = ni_config_get(ni, SPD_OUT);
			break;
	}
	if(!spd)
		return;

	ListIterator iter;
	list_iterator_init(&iter, spd);

	while((list_iterator_has_next(&iter))) {
		SP* sp = list_iterator_remove(&iter);
		sp_free(sp);
	}
}
