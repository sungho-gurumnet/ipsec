#include "sp.h"

SP* sp_create(uint8_t direction, uint32_t src_ip, uint32_t src_mask, uint32_t dst_ip, uint32_t dst_mask, uint16_t src_port, uint16_t dst_port, uint8_t action, uint8_t protocol) {
	SP* sp = (SP*)malloc(sizeof(SP));
	if(sp == NULL)
		return NULL;

	sp->direction = direction;
	sp->src_ip = src_ip;
	sp->src_mask = src_mask;
	sp->dst_ip = dst_ip;
	sp->dst_mask = dst_mask;
	sp->src_port = src_port;
	sp->dst_port = dst_port;
	sp->action = action;
	sp->protocol = protocol;

	sp->sa_inbound = list_create(NULL);
	sp->sa_outbound = list_create(NULL);
	sp->contents = list_create(NULL);

	sp->src_ip_share = true;
	sp->dst_ip_share = true;
	sp->src_port_share = true;
	sp->dst_port_share = true;
	sp->protocol_share = true;

	return sp;
}

bool sp_delete(SP* sp) {
	list_destroy(sp->sa_inbound);
	list_destroy(sp->sa_outbound);
	list_destroy(sp->contents);

	free(sp);

	return true;
}

bool sp_content_add(SP* sp, Content* content, int priority) {
	return list_add_at(sp->contents, priority, content);
}

bool sp_content_delete(SP* sp, int index) {
	if(sp == NULL)
		return false;

	Content* content = list_remove(sp->contents, index);
	if(content == NULL)
		return false;
	else
		free(content);

	return true;
}

bool sp_sa_add(SP* sp, SA* sa, uint8_t direction) {
	if(sp == NULL)
		return false;
	if(sa == NULL)
		return false;

        if(direction == IN) {
		return list_add(sp->sa_inbound, sa);
        } else if(direction == OUT) {
		return list_add(sp->sa_outbound, sa);
        }

	return false;
}

SA* sp_sa_get(SP* sp, Content* cont, IP* ip, uint8_t direct) {
	List* list_sa = NULL;
	if(direct == IN) {
		list_sa = sp->sa_inbound;
	} else if(direct == OUT) {
		list_sa = sp->sa_outbound;
	}

	ListIterator iter;
	list_iterator_init(&iter, list_sa);
	SA* sa = NULL;
	printf("HERE\n");
	while((sa = list_iterator_next(&iter)) != NULL) {
	printf("HERE\n");
		if((sp->protocol_share == true) || (cont->protocol == sa->protocol)) {
	printf("HERE\n");
			if((sp->src_ip_share == true) || endian32(ip->source) == sa->src_ip) {
	printf("HERE\n");
				if((sp->dst_ip_share == true) || endian32(ip->destination) == sa->dst_ip) {
	printf("HERE\n");
					switch(ip->protocol) {
						case IP_PROTOCOL_TCP:;
							TCP* tcp = (TCP*)ip->body;
							if((sp->src_port_share == true) || (endian16(tcp->source) == sa->src_port)) {
								if((sp->dst_port_share == true) || (endian16(tcp->destination) == sa->dst_port)) {
									return sa;
								}
							}
							break;

						case IP_PROTOCOL_UDP:;
							UDP* udp = (UDP*)ip->body;
							if((sp->src_port_share == true) || (endian16(udp->source) == sa->src_port)) {
								if((sp->dst_port_share == true) || (endian16(udp->destination) == sa->dst_port)) {
									return sa;
								}
							}
							break;

						default:
							return sa;
					}
				}
				
			}
		}
	}

	return NULL;
}
