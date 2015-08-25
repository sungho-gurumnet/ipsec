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
		Ether* _ether = (Ether*)(packet->buffer + packet->start);
		IP* _ip = (IP*)_ether->payload;
		_ip->length = endian16(endian16(_ip->length) + header_len + tail_len);

		packet->start -= header_len;
		packet->end += tail_len;
		Ether* ether = (Ether*)(packet->buffer + packet->start);
		memmove(ether, _ether, ETHER_LEN + _ip->ihl * 4 /*Ether + IP Header Length*/);

		return true;
	} else if(packet->end + header_len + tail_len < packet->size) {
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
		packet->start -= (IP_LEN + header_len);
		packet->end += tail_len;

		Ether* ether = (Ether*)(packet->buffer + packet->start);
		IP* ip = (IP*)ether->payload;
		ip->length = endian16(endian16(_ip->length) + header_len + tail_len);

		return true;
	} else if(packet->end + IP_LEN + header_len + tail_len < packet->size) {
		Ether* ether = (Ether*)(packet->buffer + packet->start);
		IP* ip = (IP*)ether->payload;
		memmove(ip->body + header_len, ip, ip->length);

		ip->length = endian16(endian16(ip->length) + header_len + tail_len);

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
