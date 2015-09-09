#include <malloc.h>
#define DONT_MAKE_WRAPPER
#include <_malloc.h>
#undef DONT_MAKE_WRAPPER
#include <util/map.h>

#include "ipsec.h"
#include "sp.h"
#include "sad.h"

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
				sp->is_protocol_sa_share = attrs[i * 2 + 1];
				break;
			case SP_SOURCE_IP:
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
				sp->out_ni = (NetworkInterface*)attrs[i * 2 + 1];
				break;
			case SP_DESTINATION_IP:
				sp->dest_ip = attrs[i * 2 + 1];
				break;
			case SP_DESTINATION_NET_MASK:
				sp->dest_mask = attrs[i * 2 + 1];
				break;
			case SP_IS_DESTINATION_IP_SA_SHARE:
				sp->is_dest_ip_sa_share = attrs[i * 2 + 1];
				break;
			case SP_DESTINATION_PORT:
				sp->dest_port = attrs[i * 2 + 1];
				break;
			case SP_IS_DESTINATION_PORT_SHARE:
				sp->is_dest_port_sa_share = attrs[i * 2 + 1];
				break;
			case SP_IPSEC_ACTION:
				sp->ipsec_action = attrs[i * 2 + 1];
				break;
		}
	}

	sp->ni = ni;

	return sp;
}

bool sp_free(SP* sp) {
	if(sp->sa_list)
		list_destroy(sp->sa_list);

	if(sp->contents) {
		if(!list_is_empty(sp->contents))
			return false;

		list_destroy(sp->contents);
	}

	__free(sp, sp->ni->pool);

	return true;
}

bool sp_add_content(SP* sp, Content* content, int priority) {
	if(!sp->contents) {
		sp->contents = list_create(sp->ni->pool);
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

	Content* content = list_get(sp->contents, index);

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

bool sp_add_sa(SP* sp, SA* sa) {
	if(!sp->sa_list) {
		sp->sa_list = list_create(sp->ni->pool);
	}
	if(!sp->sa_list)
		return false;

	return list_add(sp->sa_list, sa);
}

bool sp_remove_sa(SP* sp, SA* sa) {
	if(!sp->sa_list)
		return false;

	if(!list_remove_data(sp->sa_list, sa)) {
		return false;
	}

	if(list_is_empty(sp->sa_list)) {
		list_destroy(sp->sa_list);
		sp->sa_list = NULL;
	}

	return true;
}
//TODO
SA* sp_get_sa(SP* sp, IP* ip) {
	if(!sp->sa_list)
		return NULL;

	ListIterator iter;
	list_iterator_init(&iter, sp->sa_list);
	while(list_iterator_has_next(&iter)) {
		SA* sa = list_iterator_next(&iter);
		uint8_t protocol;
		if(sp->is_protocol_sa_share) {
			protocol = sp->protocol;
		} else {
			protocol = ip->protocol;
		}
		if(protocol != sa->protocol)
			continue;

		if(sp->is_src_ip_sa_share) {
			if(sp->src_mask != sa->src_mask) {
				continue;
			}

			uint32_t src_ip = sp->src_ip;
			if(!src_ip && ((src_ip & sp->src_mask) != (sa->src_ip & (sp->src_mask))))
				continue;
		} else {
			if(sa->src_mask != 0xffffffff)
				continue;

			uint32_t src_ip = endian32(ip->source);
			if(src_ip != sa->src_ip)
				continue;
		}

		if(sp->is_dest_ip_sa_share) {
			if(sp->dest_mask != sa->dest_mask)
				continue;

			uint32_t dest_ip = sp->dest_ip;
			if(!dest_ip && ((dest_ip & sp->dest_mask) != (sa->dest_ip & (sp->dest_mask))))
				continue;
		} else {
			if(sa->dest_mask != 0xffffffff)
				continue;

			uint32_t dest_ip = endian32(ip->destination);
			if(dest_ip != sa->dest_ip)
				continue;
		}

		switch(ip->protocol) {
			case IP_PROTOCOL_TCP:
				;
				TCP* tcp = (TCP*)ip->body;
				if(sp->is_src_port_sa_share) {
					uint16_t src_port = sp->src_port;
					if(src_port != sa->src_port)
						continue;
				} else {
					uint16_t src_port = endian16(tcp->source);
					if(src_port != sa->src_port)
						continue;
				}

				if(sp->is_dest_port_sa_share) {
					uint16_t dest_port = sp->dest_port;
					if(dest_port != sa->dest_port)
						continue;
				} else {
					uint16_t dest_port = endian16(tcp->destination);
					if(dest_port != sa->dest_port)
						continue;
				}

				return sa;
			case IP_PROTOCOL_UDP:
				;
				UDP* udp = (UDP*)ip->body;
				if(sp->is_src_port_sa_share) {
					uint16_t src_port = sp->src_port;
					if(src_port != sa->src_port)
						continue;
				} else {
					uint16_t src_port = endian16(udp->source);
					if(src_port != sa->src_port)
						continue;
				}

				if(sp->is_dest_port_sa_share) {
					uint16_t dest_port = sp->dest_port;
					if(dest_port != sa->dest_port)
						continue;
				} else {
					uint16_t dest_port = endian16(udp->destination);
					if(dest_port != sa->dest_port)
						continue;
				}

				return sa;
			default:
				return sa;
		}

	}

	return NULL;
}

//return SA or SA Bundle
SA* sp_find_sa(SP* sp, IP* ip) {
	SA* first_sa = NULL;
	SA* pre_sa = NULL;
	Map* sad = sad_get(sp->ni);

	if(!sp->contents)
		return NULL;

	if(!sad)
		return NULL;

	ListIterator iter;
	list_iterator_init(&iter, sp->contents);
	while(list_iterator_has_next(&iter)) {
		SA* next_sa = NULL;
		Content* content = list_iterator_next(&iter);

		MapIterator sad_iter;
		map_iterator_init(&sad_iter, sad);
		while(map_iterator_has_next(&sad_iter)) {
			MapEntry* entry = map_iterator_next(&sad_iter);
			List* dest_list = entry->data;

			ListIterator list_iter;
			list_iterator_init(&list_iter, dest_list);
			while(list_iterator_has_next(&list_iter)) {
				SA* sa = list_iterator_next(&list_iter);
				if(content->ipsec_protocol != sa->ipsec_protocol)
					continue;

				//mode check
				if(content->ipsec_mode != sa->ipsec_mode)
					continue;

				//algorithm check
				switch(content->ipsec_mode) {
					case IPSEC_MODE_TRANSPORT:
						if(content->ipsec_protocol == IP_PROTOCOL_ESP) {
							if(((Content_ESP_Transport*)content)->crypto_algorithm != ((SA_ESP*)sa)->crypto_algorithm)
								continue;

							if(((Content_ESP_Transport*)content)->auth_algorithm != ((SA_ESP*)sa)->auth_algorithm)
								continue;
						} else {
							if(((Content_AH_Transport*)content)->auth_algorithm != ((SA_AH*)sa)->auth_algorithm)
								continue;
						}

						break;
					case IPSEC_MODE_TUNNEL:
						;
						uint32_t t_src_ip;
						uint32_t t_dest_ip;
						if(content->ipsec_protocol == IP_PROTOCOL_ESP) {
							if(((Content_ESP_Tunnel*)content)->crypto_algorithm != ((SA_ESP*)sa)->crypto_algorithm) {
								continue;
							}

							if(((Content_ESP_Tunnel*)content)->auth_algorithm != ((SA_ESP*)sa)->auth_algorithm)
								continue;
							
							t_src_ip = ((Content_ESP_Tunnel*)content)->t_src_ip;
							t_dest_ip = ((Content_ESP_Tunnel*)content)->t_dest_ip;
						} else {
							if(((Content_AH_Tunnel*)content)->auth_algorithm != ((SA_AH*)sa)->auth_algorithm)
								continue;

							t_src_ip = ((Content_AH_Tunnel*)content)->t_src_ip;
							t_dest_ip = ((Content_AH_Tunnel*)content)->t_dest_ip;
						}
						
						//ip check
						if(sa->t_src_ip != t_src_ip)
							continue;

						if(sa->t_dest_ip != t_dest_ip)
							continue;
						break;
				}

				//address check
				if(!first_sa) {
					//TODO add protocol
					if(sp->is_src_ip_sa_share) {
						if(sp->src_ip != sa->src_ip || sp->src_mask != sa->src_mask)
							continue;
					} else {
						uint32_t src_ip = endian32(ip->source);
						if(src_ip != sa->src_ip || sa->src_mask != 0xffffffff)
							continue;
					}

					if(sp->is_dest_ip_sa_share) {
						if(sp->dest_ip != sa->dest_ip || sp->dest_mask != sa->dest_mask)
							continue;
					} else {
						uint32_t dest_ip = endian32(ip->source);
						if(dest_ip != sa->dest_ip || sa->dest_mask != 0xffffffff)
							continue;
					}

					//TODO add port
				} else {
					if(pre_sa->src_ip != sa->src_ip || pre_sa->src_mask != sa->src_mask)
						continue;

					if(pre_sa->dest_ip != sa->dest_ip || pre_sa->dest_mask != sa->dest_mask)
						continue;
				}
				
				next_sa = sa;
				goto next;
			}
		}

next:
		if(!next_sa) {
			printf("Can'nt found SA\n");
			return NULL;
		}
		if(!first_sa) {
			first_sa = next_sa;
			pre_sa = next_sa;
		} else {
			pre_sa->next = next_sa;
			pre_sa = next_sa;
		}
	}

	if(!sp->sa_list)
		sp->sa_list = list_create(sp->ni->pool);

	if(sp->sa_list) {
		list_add(sp->sa_list, first_sa);
	}

	return first_sa;
}

bool sp_verify_sa(SP* sp, List* sa_list, IP* ip) {
	SA* pre_sa = NULL;
	ListIterator iter;
	list_iterator_init(&iter, sp->contents);
	while(list_iterator_has_next(&iter)) {
		SA* sa = list_remove_first(sa_list);
		if(!sa)
			return false;

		Content* content = list_iterator_next(&iter);
		// verification SA

		if(content->ipsec_protocol != sa->ipsec_protocol)
			return false;

		//mode check
		if(content->ipsec_mode != sa->ipsec_mode)
			return false;
		
		switch(content->ipsec_mode) {
			case IPSEC_MODE_TRANSPORT:
				if(content->ipsec_protocol == IP_PROTOCOL_ESP) {
					if(((Content_ESP_Transport*)content)->crypto_algorithm != ((SA_ESP*)sa)->crypto_algorithm)
						return false;

					if(((Content_ESP_Transport*)content)->auth_algorithm != ((SA_ESP*)sa)->auth_algorithm)
						return false;
				} else {
					if(((Content_AH_Transport*)content)->auth_algorithm != ((SA_AH*)sa)->auth_algorithm)
						return false;
				}

				break;
			case IPSEC_MODE_TUNNEL:
				;
				uint32_t t_src_ip;
				uint32_t t_dest_ip;
				if(content->ipsec_protocol == IP_PROTOCOL_ESP) {
					if(((Content_ESP_Tunnel*)content)->crypto_algorithm != ((SA_ESP*)sa)->crypto_algorithm) {
						return false;
					}

					if(((Content_ESP_Tunnel*)content)->auth_algorithm != ((SA_ESP*)sa)->auth_algorithm)
						return false;
					
					t_src_ip = ((Content_ESP_Tunnel*)content)->t_src_ip;
					t_dest_ip = ((Content_ESP_Tunnel*)content)->t_dest_ip;
				} else {
					if(((Content_AH_Tunnel*)content)->auth_algorithm != ((SA_AH*)sa)->auth_algorithm)
						return false;

					t_src_ip = ((Content_AH_Tunnel*)content)->t_src_ip;
					t_dest_ip = ((Content_AH_Tunnel*)content)->t_dest_ip;
				}
				
				//ip check
				if(sa->t_src_ip != t_src_ip)
					return false;

				if(sa->t_dest_ip != t_dest_ip)
					return false;
				break;
		}

		//address check
		if(!pre_sa) {
			//TODO add protocol
			if(sp->is_src_ip_sa_share) {
				if(sp->src_ip != sa->src_ip || sp->src_mask != sa->src_mask)
					return false;
			} else {
				uint32_t src_ip = endian32(ip->source);
				if(src_ip != sa->src_ip || sa->src_mask != 0xffffffff)
					return false;
			}

			if(sp->is_dest_ip_sa_share) {
				if(sp->dest_ip != sa->dest_ip || sp->dest_mask != sa->dest_mask)
					return false;
			} else {
				uint32_t dest_ip = endian32(ip->source);
				if(dest_ip != sa->dest_ip || sa->dest_mask != 0xffffffff)
					return false;
			}

			//TODO add port
		} else {
			if(pre_sa->src_ip != sa->src_ip || pre_sa->src_mask != sa->src_mask)
				return false;

			if(pre_sa->dest_ip != sa->dest_ip || pre_sa->dest_mask != sa->dest_mask)
				return false;
		}

		pre_sa = sa;
	}

	return true;
}
