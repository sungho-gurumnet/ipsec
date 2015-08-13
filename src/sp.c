#include "sp.h"

SP* sp_alloc(NetworkInterface* ni, uint64_t* attrs) {
        SP* sp = (SP*)__malloc(sizeof(SP), ni->pool);
	if(sp == NULL) {
		printf("Can'nt allocate SP\n");
		return NULL;
	}
	memset(sp, 0, sizeof(SP));

	for(int i = 0; attrs[i * 2] != SP_NONE; i++) {
		switch(attrs[i * 2]) {
			case SP_DIRECTION:
				sp->direction = attrs[i * 2 + 1];
				break;
			case SP_PROTOCOL:
				sp->protocol = attrs[i * 2 + 1];
				break;
			case SP_IS_PROTOCOL_SA_SHARE:
				sp->is_protocol_share = attrs[i * 2 + 1];
				break;
			case SP_SOURCE_IP_ADDR:
				sp->src_ip = attrs[i * 2 + 1];
				break;
			case SP_SOURCE_NET_MASK:
				sp->src_mask = attrs[i * 2 + 1];
				break;
			case SP_IS_SOURCE_IP_SA_SHARE:
				sp->is_src_ip_sa_share = attrs[i * 2 + 1];
				break;
			case SP_SOURCE_PORT:
				sp->src_port = attrs[i * 2 + 1];
				break;
			case SP_IS_SOURCE_PORT_SA_SHARE:
				sp->is_src_port_sa_share = attrs[i * 2 + 1];
				break;
			case SP_OUT_NI:
				sp->out_ni = attrs[i * 2 + 1];
				break;
			case SP_DESTINATION_IP_ADDR:
				sp->dest_ip = attrs[i * 2 + 1];
				break;
			case SP_DESTINATION_NET_MASK:
				sp->dest_mask = attrs[i * 2 + 1];
				break;
			case SP_IS_DESTINATION_IP_ADDR:
				sp->is_dest_ip_sa_share = attr[i * 2 + 1];
				break;
			case SP_DESTINATION_PORT:
				sp->dest_port = attrs[i * 2 + 1];
				break;
			case SP_DESTINATION_PORT_SHARE:
				sp->is_dest_port_sa_share = attrs[i * 2 + 1];
				break;
			case SP_ACTION:
				sp->action = attrs[i * 2 + 1];
				break;
		}
	}

	return sp;
}

bool sp_free(NetworkInterface* ni, SP* sp) {
	if(sp->sa_inbound)
		list_destroy(sp->sa_inbound);
	if(sp->sa_outbound)
		list_destroy(sp->sa_outbound);
	if(sp->contents)
		list_destroy(sp->contents);

	__free(sp, ni->pool);

	return true;
}

bool sp_add_content(SP* sp, Content* content, int priority) {
	if(!sp->contents) {
		sp->contents = list_create(ni->pool);
		if(!sp->contents) {
			printf("Can'nt allocate contents list\n");
			return false;
		}
	}
	if(!list_add_at(sp->contents, priority, content)) {
		if(list_is_empty(sp->contents)) {
			list_destroy(sp->contents);
			sp->contents = NULL;
		}

		return false;
	}

	return true;
}

Content* sp_get_content(SP* sp, int index) {
	if(!sp->contents)
		return NULL;

	Content* content = list_get(sp->contetns, index);

	return content;
}

Content* sp_remove_content(SP* sp, int index) {
	if(!sp->contents)
		return NULL;

	Content* content = list_remove(sp->contents, index);
	if(!content)
		return NULL;

	if(list_is_empty(sp->contents)) {
		list_destroy(sp->contents);
		sp->contents = NULL;
	}

	return content;
}

bool sp_add_sa(SP* sp, SA* sa, uint8_t direction) {
	switch(direction) {
		case IN:
			return list_add(sp->sa_inbound, sa);
		case OUT:
			return list_add(sp->sa_outbound, sa);
		case INOUT:
			//TODO
			break;
	}

	return false;
}

bool sp_remove_sa(SP* sp, SA* sa) {
	//TODO
}

//TODO
SA* sp_get_sa(SP* sp, Content* cont, IP* ip, uint8_t direct) {
	ListIterator iter;

	if(direct == IN) {
		if(!sp->sa_inbound)
			return NULL;
		list_iterator_init(&iter, sp->sa_inbound);
	} else if(direct == OUT) {
		if(!sp->sa_outbound)
			return NULL;
		list_iterator_init(&iter, sp->sa_outbound);
	} else
		return NULL;

	while(list_iterator_has_next(&iter)) {
		SA* sa = list_iterator_next(&iter);
		if(sp->is_protocol_share || (sp->protocol == sa->protocol)) {
			if(sp->src_ip_share || endian32(ip->source) == sa->src_ip) {
				if(sp->dest_ip_share || endian32(ip->destination) == sa->dest_ip) {
					switch(ip->protocol) {
						case IP_PROTOCOL_TCP:;
							TCP* tcp = (TCP*)ip->body;
							if((sp->src_port_share == true) || (endian16(tcp->source) == sa->src_port)) {
								if((sp->dest_port_share == true) || (endian16(tcp->destination) == sa->dest_port)) {
									return sa;
								}
							}
							break;

						case IP_PROTOCOL_UDP:;
							UDP* udp = (UDP*)ip->body;
							if((sp->src_port_share == true) || (endian16(udp->source) == sa->src_port)) {
								if((sp->dest_port_share == true) || (endian16(udp->destination) == sa->dest_port)) {
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
