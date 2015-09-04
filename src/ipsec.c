#include <net/ether.h>
#include <net/arp.h>
#include <net/icmp.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/checksum.h>
#include <util/event.h>

#include "ipsec.h"
#include "esp.h"
#include "ah.h"
#include "socket.h"
#include "spd.h"
#include "sad.h"
#include "ike.h"
#include "mode.h"

bool ipsec_init() {
	/*nothing*/
	EVP_MD_CTX_init(EVP_MD_CTX_create());

	return true;
}

static bool ipsec_decrypt(Packet* packet, SA* sa) { 
	Ether* ether = (Ether*)(packet->buffer + packet->start);
        IP* ip = (IP*)ether->payload;
	//int origin_length = endian16(ip->length);

	// 2. Seq# Validation
	ESP* esp = (ESP*)ip->body;
	if(checkWindow(sa->window, esp->seq_num) < 0) {
		printf(" 2. Seq# Validation : Dicard Packet \n");
		return false;
	}

	int size = endian16(ip->length) - (ip->ihl * 4) - ICV_LEN; 
	
	if((size + ICV_LEN) > packet->end) {
		printf(" 3. ICV Validation : Discard Packet \n");
		return false;
	}

	uint8_t result[12];
	if(((SA_ESP*)sa)->auth) {
		((Authentication*)(((SA_ESP*)sa)->auth))->authenticate(&(ip->body), size, result, sa);
		if(memcmp(result, ip->body + size, 12) != 0) {
			printf(" 3. ICV Validation : Discard Packet \n");
			return false;
		}
	}

	((Cryptography*)(((SA_ESP*)sa)->crypto))->decrypt(esp, size, (SA_ESP*)sa); 
	
	// 5. ESP Header & Trailer Deletion
	ESP_T* esp_trailer = (ESP_T*)(ip->body + endian16(ip->length) - (ip->ihl * 4) - ESP_TRAILER_LEN);
	int padding_len = esp_trailer->pad_len;
	if(sa->ipsec_mode == IPSEC_MODE_TRANSPORT) {
		ip->protocol = esp_trailer->next_hdr;
		ip->ttl--;
		transport_unset(packet, ESP_HEADER_LEN, padding_len + ESP_TRAILER_LEN);

	} else if(sa->ipsec_mode == IPSEC_MODE_TUNNEL) {
		tunnel_unset(packet, ESP_HEADER_LEN, padding_len + ESP_TRAILER_LEN);
	}

	return true;
}

static bool ipsec_encrypt(Packet* packet, Content* content, SA* sa) {
	Ether* ether = (Ether*)(packet->buffer + packet->start);
        IP* ip = (IP*)ether->payload;

	int padding_len = (endian16(ip->length) + 2) % 8;
	if(padding_len != 0)
		padding_len = 8 - padding_len;

	if(content->ipsec_mode == IPSEC_MODE_TRANSPORT) {
		if(!transport_set(packet, ESP_HEADER_LEN, padding_len + ESP_TRAILER_LEN))
			return false;
	} else if(content->ipsec_mode == IPSEC_MODE_TUNNEL) {
		if(!tunnel_set(packet, ESP_HEADER_LEN, padding_len + ESP_TRAILER_LEN))
			return false;
	}

	ether = (Ether*)(packet->buffer + packet->start);
        ip = (IP*)ether->payload;
	//Set ESP Trailer
	ESP_T* esp_trailer = (ESP_T*)(ip->body + endian16(ip->length) - (ip->ihl * 4) - ESP_TRAILER_LEN);
	esp_trailer->pad_len = padding_len;
	if(content->ipsec_mode == IPSEC_MODE_TRANSPORT) {
		esp_trailer->next_hdr = ip->protocol;
	} else if(content->ipsec_mode == IPSEC_MODE_TUNNEL) {
		esp_trailer->next_hdr = IP_PROTOCOL_IP;
	}

	ESP* esp = (ESP*)ip->body;
	// 5. Seq# Validation
	((Cryptography*)(((SA_ESP*)sa)->crypto))->encrypt(esp, endian16(ip->length) - IP_LEN - ESP_HEADER_LEN, (SA_ESP*)sa);
	esp->seq_num = endian32(++sa->window->seq_counter);
	esp->spi = endian32(sa->spi);
	
	if(((SA_ESP*)sa)->auth) {
		int size = endian16(ip->length) - IP_LEN;
		((Authentication*)(((SA_ESP*)sa)->auth))->authenticate(ip->body, size, ip->body + size, sa);
		ip->length = endian16(endian16(ip->length) + ICV_LEN);
		packet->end += ICV_LEN;
	}

	ip->protocol = IP_PROTOCOL_ESP;

	switch(content->ipsec_mode) {
		case IPSEC_MODE_TRANSPORT:
			ip->ttl--;
			ip->checksum = 0;
			ip->checksum = endian16(checksum(ip, ip->ihl * 4));
			break;
		case IPSEC_MODE_TUNNEL:
			ip->ttl = IP_TTL;
			ip->source = endian32(((Content_ESP_Tunnel*)content)->t_src_ip);
			ip->destination = endian32(((Content_ESP_Tunnel*)content)->t_dest_ip);
			ip->checksum = 0;
			ip->checksum = endian16(checksum(ip, ip->ihl * 4));
			break;
	}

	printf("ipsec encrypt succes\n");
	return true;
}

//Check auth
static bool ipsec_proof(Packet* packet, SA* sa) {
	Ether* ether = (Ether*)(packet->buffer + packet->start);
        IP* ip = (IP*)ether->payload;
	AH* ah = (AH*)ip->body;

	ah->seq_num = endian32(++sa->window->seq_counter);

	uint8_t ecn = ip->ecn;
	uint8_t dscp = ip->dscp;
	uint16_t flags_offset = ip->flags_offset;
	uint8_t ttl = ip->ttl;
	uint8_t auth_data[ICV_LEN];
	memcpy(auth_data, ah->auth_data, ICV_LEN);

	//Authenticate
	ip->ecn = 0; //tos
	ip->dscp = 0; //tos
	ip->ttl = 0;
	ip->flags_offset = 0;
	memset(ah->auth_data, 0, ICV_LEN);
	((Authentication*)(((SA_AH*)sa)->auth))->authenticate(ip, endian16(ip->length), ah->auth_data, sa);

	if(memcmp(auth_data, ah->auth_data, ICV_LEN)) {
		ip->ecn = ecn;
		ip->dscp = dscp;
		ip->ttl = ttl;
		memcpy(ah->auth_data, auth_data, ICV_LEN);

		return false;
	}

	if(ah->next_hdr == IP_PROTOCOL_IP)
		//Tunnel mode
		tunnel_unset(packet, AH_HEADER_LEN, 0);
	else {
		//Transport mode
		ip->protocol = ah->next_hdr;
		transport_unset(packet, AH_HEADER_LEN, 0);
		ip->ecn = ecn;
		ip->dscp = dscp;
		ip->ttl = ttl;
		ip->flags_offset = flags_offset;
	}

	return true;
}

static bool ipsec_auth(Packet* packet, Content* content, SA* sa) {
	Ether* ether = NULL;
        IP* ip = NULL;
	AH* ah = NULL;

	if(content->ipsec_mode == IPSEC_MODE_TRANSPORT) {
		if(!transport_set(packet, AH_HEADER_LEN, 0))
			return false;

		ether = (Ether*)(packet->buffer + packet->start);
		ip = (IP*)ether->payload;
		ah = (AH*)ip->body;

		//ip->length = endian16(endian16(ip->length) + AH_HEADER_LEN + ICV_LEN);
		ah->next_hdr = ip->protocol;
	} else if(content->ipsec_mode == IPSEC_MODE_TUNNEL) {
		if(!tunnel_set(packet, AH_HEADER_LEN, 0))
			return false;

		ether = (Ether*)(packet->buffer + packet->start);
		ip = (IP*)ether->payload;
		ah = (AH*)ip->body;

		//ip->length = endian16(endian16(ip->length) + IP_LEN + AH_HEADER_LEN + ICV_LEN);
		ah->next_hdr = IP_PROTOCOL_IP;
	}

	ah->len = 4; //check
	ah->spi = endian32(sa->spi);
	ah->seq_num = endian32(++sa->window->seq_counter);

	uint8_t ecn = ip->ecn;
	uint8_t dscp = ip->dscp;
	uint8_t ttl = ip->ttl;
	uint16_t flags_offset = ip->flags_offset;

	ip->ecn = 0;
	ip->dscp = 0;
	ip->ttl = 0;
	ip->protocol = IP_PROTOCOL_AH;
	ip->flags_offset = 0;
	memset(ah->auth_data, 0, ICV_LEN);

	((Authentication*)(((SA_AH*)sa)->auth))->authenticate(ip, endian16(ip->length), ah->auth_data, sa);

	ip->ecn = ecn;
	ip->dscp = dscp;
	ip->ttl = ttl;
	ip->flags_offset = flags_offset;

	switch(content->ipsec_mode) {
		case IPSEC_MODE_TRANSPORT:
			ip->ttl--;
			ip->checksum = 0;
			ip->checksum = endian16(checksum(ip, ip->ihl * 4));
			break;
		case IPSEC_MODE_TUNNEL:
			ip->ttl = IP_TTL;
			ip->source = endian32(((Content_AH_Tunnel*)content)->t_src_ip);
			ip->destination = endian32(((Content_AH_Tunnel*)content)->t_dest_ip);
			ip->checksum = 0;
			ip->checksum = endian16(checksum(ip, ip->ihl * 4));
			break;
	}

	printf("ipsec auth success\n");
	return true;
}

static bool inbound_process(Packet* packet) {
	printf("inbound process\n");
	Ether* ether = (Ether*)(packet->buffer + packet->start);
        IP* ip = (IP*)ether->payload;

	if(ip->protocol != IP_PROTOCOL_ESP && (ip->protocol != IP_PROTOCOL_AH))
		return false;
	// 1. SAD Lookup
	SA* sa = NULL;
	while((ip->protocol == IP_PROTOCOL_ESP) || (ip->protocol == IP_PROTOCOL_AH)) {
		switch(ip->protocol) {
			case IP_PROTOCOL_ESP:
				;
				ESP* esp = (ESP*)ip->body;
				sa = sad_get_sa(packet->ni, endian32(esp->spi), endian32(ip->destination), ip->protocol);
				if(!sa) {
					printf(" 1. SAD Lookup : Discard ip \n");
					return false;
				}
				ipsec_decrypt(packet, sa);
				break;

			case IP_PROTOCOL_AH:
				;
				AH* ah = (AH*)ip->body;
				sa = sad_get_sa(packet->ni, endian32(ah->spi), endian32(ip->destination), ip->protocol);
				if(!sa) {
					printf(" 1. SAD Lookup : Discard ip \n");
					return false;
				}
				ipsec_proof(packet, sa);
				break;
		}

		ether = (Ether*)(packet->buffer + packet->start);
		ip = (IP*)ether->payload;
	}

	// 6. SPD Lookup 
	SP* sp = spd_get_sp(packet->ni, ip);
	if(!sp) {
		//printf(" 6. SPD Lookup : Discard ip \n");
		return false;
	}

	ether = (Ether*)(packet->buffer + packet->start);
        ip = (IP*)ether->payload;
	ether->smac = endian48(sp->out_ni->mac);
	ether->dmac = endian48(arp_get_mac(sp->out_ni, endian32(ip->destination), endian32(ip->source)));
	ether->type = endian16(ETHER_TYPE_IPv4);

	ni_output(sp->out_ni, packet);

	return true;
}

static bool outbound_process(Packet* packet) {
	printf("outbound process\n");
	NetworkInterface* ni = packet->ni;
	Ether* ether = (Ether*)(packet->buffer + packet->start);
        IP* ip = (IP*)ether->payload;
	
	Socket* socket = NULL;
	SP* sp = NULL;
	SA* sa = NULL;
	if(ip->protocol == IP_PROTOCOL_TCP) { //tcp use socket pointer 
		TCP* tcp = (TCP*)ip->body;
		socket = socket_get(ni, endian32(ip->source), endian16(tcp->source));
		if(socket) {
			/*This Packet Is TCP Packet*/
			sp = socket->sp;
			sa = socket->sa;
			if(tcp->fin) {
				socket->fin = true;
				bool delete_socket(void* context) {
					//delete socket
					return false;
				}
				event_timer_add(delete_socket, socket, 5000000, 5000000);
				//socket free
				//TODO timer event
				//socket_delete(endian32(ip->source), endian16(tcp->source));
			}
			goto tcp_packet;
		}
	}

	if(!sp)
		sp = spd_get_sp(packet->ni, ip);

	if(!sp) {
		printf("Can'nt found sp\n");
		return false;
	}

tcp_packet:
	if(sp->ipsec_action == IPSEC_ACTION_BYPASS) {
		if((ip->protocol == IP_PROTOCOL_TCP && !socket)) {
			TCP* tcp = (TCP*)ip->body;
			socket = socket_create(ni, sp, NULL);
			socket_add(ni, endian32(ip->source), endian16(tcp->source), socket);
		}
		
		//set dmac
		ni_output(sp->out_ni, packet);
		return true;
	}

	//get already pointed SA, SA bundle
	if(!sa) {
		sa = sp_get_sa(sp, ip, OUT);
		if(sa)
			printf("SA get!\n");
	}

	if(!sa) {
		//get SA, SA bundle from sad
		sa = sp_find_sa(sp, ip);
		if(sa)
			printf("SA find!\n");
	}

	if(!sa) {
		sa = ike_sa_get(ip, sp); //this function not work;
	}

	if(!sa) {
		ni_free(packet);
		printf("Can'nt found SA\n");
		return true;
	}

	if(ip->protocol == IP_PROTOCOL_TCP) {
		TCP* tcp = (TCP*)ip->body;
		Socket* socket = socket_create(ni, sp, sa);
		socket_add(ni, endian32(ip->source), endian16(tcp->source), socket);
	}

	ListIterator iter;
	list_iterator_init(&iter, sp->contents);
	while(list_iterator_has_next(&iter)) {
		Content* content = list_iterator_next(&iter);

		if(!sa) {
			ni_free(packet);
			printf("Can'nt found SA\n");
			return true;
		}

		switch(content->ipsec_protocol) {
			case IP_PROTOCOL_ESP:
				if(!ipsec_encrypt(packet, content, sa)) {
					printf("Can'nt encrypt packet\n");
					ni_free(packet);
					return true;
				}
				break;

			case IP_PROTOCOL_AH:
				if(!ipsec_auth(packet, content, sa)) {
					printf("Can'nt authenticate packet\n");
					ni_free(packet);
					return true;
				}
				break;
		}

		sa = sa->next;
	}

	ether = (Ether*)(packet->buffer + packet->start);
        ip = (IP*)ether->payload;
	ether->smac = endian48(sp->out_ni->mac);
	ether->dmac = endian48(arp_get_mac(sp->out_ni, endian32(ip->destination), endian32(ip->source)));
	ether->type = endian16(ETHER_TYPE_IPv4);

	ni_output(sp->out_ni, packet);

	return true;
}

bool ipsec_process(Packet* packet) {
	if(arp_process(packet))
		return true;

 //	if(icmp_process(packet))
 //		return true;

	Ether* ether = (Ether*)(packet->buffer + packet->start);
	if(endian16(ether->type) == ETHER_TYPE_IPv4) {
		if(outbound_process(packet)) {
			return true;
		}

		if(inbound_process(packet)) {
			return true;
		}


		return false;
	} else {
	}

	return false;
}
