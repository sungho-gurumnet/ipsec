#include <stdio.h>
#include <stdint.h>
#include <net/ether.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <util/list.h>

#include "spd.h"

List* spd_get(NetworkInterface* ni) {
	List* spd = ni_config_get(ni, SPD);

	return spd;
}

SP* spd_get_sp_index(NetworkInterface* ni, uint16_t index) {
	List* spd = ni_config_get(ni, SPD);
	if(!spd)
		return NULL;

	return list_get(spd, index);
}

SP* spd_get_sp(NetworkInterface* ni, IP* ip) {
	List* spd = ni_config_get(ni, SPD);
	if(!spd)
		return NULL;

	ListIterator iter;
	list_iterator_init(&iter, spd);
	
	printf("spd_get_sp\n");
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

				printf("return\n");
				return sp;

			default:
				printf("return\n");
				return sp;
		}
	}
	return NULL;
}

bool spd_add_sp(NetworkInterface* ni, SP* sp, int priority) {
	List* spd = ni_config_get(ni, SPD);
	if(!spd) {
		spd = list_create(ni->pool);
		if(!spd) { 
			printf("Can'nt create SPD\n");
			return false;
		}
		if(!ni_config_put(ni, SPD, spd)) {
			list_destroy(spd);
			printf("Can'nt add SPD\n");
			return false;
		}
	}

	return list_add_at(spd, priority, sp);
}

SP* spd_remove_sp(NetworkInterface* ni, int index) {
	List* spd = ni_config_get(ni, SPD);
	if(!spd) {
		printf("Can'nt found SP\n");
		return NULL;
	}

	SP* sp = list_remove(spd, index);
	if(!sp) {
		printf("Can'nt found SP\n");
		return NULL;
	}

	if(list_is_empty(spd)) {
		list_destroy(spd);
		ni_config_remove(ni, SPD);
	}

	return sp;
}

void spd_delete_all(NetworkInterface* ni) {
	List* spd = ni_config_get(ni, SPD);
	if(!spd)
		return;

	ListIterator iter;
	list_iterator_init(&iter, spd);

	while((list_iterator_has_next(&iter))) {
		SP* sp = list_iterator_remove(&iter);
		sp_free(sp);
	}
}
