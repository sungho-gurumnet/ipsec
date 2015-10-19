#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <net/ether.h>
#include <net/packet.h>
#include <net/ether.h>
#include <net/ip.h>

bool transport_set(Packet* packet, uint16_t header_len, uint16_t tail_len) {
	//check size
	if(packet->start > header_len && (packet->end + tail_len) < packet->size) { 
		printf("type3\n");
		Ether* _ether = (Ether*)(packet->buffer + packet->start);
		IP* _ip = (IP*)_ether->payload;
		_ip->length = endian16(endian16(_ip->length) + header_len + tail_len);

		packet->start -= header_len;
		packet->end += tail_len;
		Ether* ether = (Ether*)(packet->buffer + packet->start);
		memmove(ether, _ether, ETHER_LEN + _ip->ihl * 4 /*Ether + IP Header Length*/);

		return true;
	} else if(packet->end + header_len + tail_len < packet->size) {
		printf("type4\n");
		Ether* _ether = (Ether*)(packet->buffer + packet->start);
		IP* _ip = (IP*)_ether->payload;
		_ip->length = endian16(endian16(_ip->length) + header_len + tail_len);
		memmove(_ip->body + header_len, _ip->body, _ip->length - _ip->ihl * 4 /* Body length*/);

		return true;
	} else {
		printf("packet has not enough padding\n");

		return false;
	}

	return true;
}

bool transport_unset(Packet* packet, uint16_t header_len, uint16_t tail_len) {
	Ether* _ether = (Ether*)(packet->buffer + packet->start);
	IP* _ip = (IP*)_ether->payload;
	_ip->length = endian16(endian16(_ip->length) - header_len - tail_len);

	memmove(_ether + header_len, _ether, ETHER_LEN + _ip->ihl * 4);

	packet->start += header_len;
	packet->end -= tail_len;

	return true;
}


bool tunnel_set(Packet* packet, uint16_t header_len, uint16_t tail_len) {
	//check size
	if((packet->start > (header_len + IP_LEN)) && (packet->end + tail_len) < packet->size) { 
		Ether* _ether = (Ether*)(packet->buffer + packet->start);
		IP* _ip = (IP*)_ether->payload;

		unsigned char* padding = NULL;
		packet->start -= (IP_LEN + header_len);
		padding = packet->buffer + packet->end;
		for(int i = 0; i < tail_len; i++) {
			padding[i] = i + 1;
		}
		packet->end += tail_len;

		Ether* ether = (Ether*)(packet->buffer + packet->start);
		IP* ip = (IP*)ether->payload;
		ip->ihl = _ip->ihl;
		ip->version = _ip->version;
		ip->ecn = _ip->ecn;
		ip->dscp = _ip->dscp;
		ip->length = endian16(endian16(_ip->length) + IP_LEN + header_len + tail_len);
		ip->id = _ip->id;
		ip->flags_offset = _ip->flags_offset;

		return true;
	} else if(packet->end + IP_LEN + header_len + tail_len < packet->size) {
		Ether* ether = (Ether*)(packet->buffer + packet->start);
		IP* ip = (IP*)ether->payload;
		memmove(ip->body + header_len, ip, ip->length);

		ip->length = endian16(IP_LEN + endian16(ip->length) + header_len + tail_len);
		packet->end += IP_LEN + header_len + tail_len;

		return true;
	} else {
		printf("packet has not enough padding\n");

		return false;
	}

	return true;
}

bool tunnel_unset(Packet* packet, uint16_t header_len, uint16_t tail_len) {
	packet->start += (header_len + IP_LEN);
	packet->end -= tail_len;

 //	Ether* ether = (Ether*)(packet->buffer + packet->start);
 //	IP* ip = (IP*)ether->payload;
 //
 //	ether->type = endian16(ETHER_TYPE_IPv4);

	return true;
}
