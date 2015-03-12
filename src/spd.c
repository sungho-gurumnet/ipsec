#include "spd.h"

static SPD spd;

// KEY : src_ip arrange, dst_ip arrange, xpt_protocol(upperspec), (src_port), (dst_port) TODO : port
bool spd_init() {
	spd.sp_list = list_create(NULL);
	if(spd.sp_list == NULL)
		return false;
	else
		return true;
}

SP* spd_get_index(int index) {
	return list_get(spd.sp_list, index);
}

SP* spd_get(IP* ip) {
	ListIterator iter;
	list_iterator_init(&iter, spd.sp_list);
	
	SP* tmp = NULL;
	while((tmp = list_iterator_next(&iter)) != NULL) {
		if((tmp->protocol == IP_PROTOCOL_ANY) || ip->protocol == tmp->protocol) {
			if((tmp->src_ip == IP_ANY) || ((endian32(ip->source) & tmp->src_mask) == (tmp->src_ip & tmp->src_mask))) {
				if((tmp->dst_ip == IP_ANY) || ((endian32(ip->destination) & tmp->dst_mask) == (tmp->dst_ip & tmp->dst_mask))) {
					switch(ip->protocol) {
						case IP_PROTOCOL_TCP:;
							TCP* tcp = (TCP*)ip->body;
							if((tmp->src_port == PORT_ANY) || (endian16(tcp->source) == tmp->src_port)) {
								if((tmp->dst_port == PORT_ANY) || (endian16(tcp->destination) == tmp->dst_port)) {
									return tmp;
								}
							}
							break;

						case IP_PROTOCOL_UDP:;
							UDP* udp = (UDP*)ip->body;
							if((tmp->src_port == PORT_ANY) || (endian16(udp->source) == tmp->src_port)) {
								if((tmp->dst_port == PORT_ANY) || (endian16(udp->destination) == tmp->dst_port)) {
									return tmp;
								}
							}
							break;
					}
				}
			}
		}
	}
	return NULL;
}

bool spd_sp_add(SP* sp, int priority) {
	return list_add_at(spd.sp_list, priority, sp);
}

bool spd_sp_delete(int index) {
	SP* sp = list_remove(spd.sp_list, index);
	if(sp == NULL)
		return false;
	else
		sp_delete(sp);

	return true;
}

void spd_all_delete(void) {
	ListIterator iter;
	list_iterator_init(&iter, spd.sp_list);

	SP* tmp = NULL;
	while((tmp = list_iterator_remove(&iter)) != NULL) {
		sp_delete(tmp);
	}
}
