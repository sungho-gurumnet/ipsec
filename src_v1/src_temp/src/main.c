#include <stdio.h>
#include <thread.h>
#include <net/ni.h>
#include <net/ether.h>
#include <net/ip.h>
#include <net/icmp.h>
#include <net/checksum.h>
#include <net/udp.h>
#include <net/tcp.h>
#include "tcp.h"
#include "IPSec.h"

void ginit(int argc, char** argv) {
}

void init(int argc, char** argv) {
	IPSecModule();
}

static uint32_t address = 0xc0a8640a;	// 192.168.100.10

void process(NetworkInterface* ni) {
	Packet* packet = ni_input(ni);
	if(!packet)
		return;
	Ether* ether = (Ether*)(packet->buffer + packet->start);
	
	if(endian16(ether->type) == ETHER_TYPE_ARP) {
		ARP* arp = (ARP*)ether->payload;
		if(endian16(arp->operation) == 1 && endian32(arp->tpa) == address) {
			ether->dmac = ether->smac;
			ether->smac = endian48(ni->mac);
			arp->operation = endian16(2);
			arp->tha = arp->sha;
			arp->tpa = arp->spa;
			arp->sha = ether->smac;
			arp->spa = endian32(address);
			
			ni_output(ni, packet);
			packet = NULL;
		}
	} else if(endian16(ether->type) == ETHER_TYPE_IPv4) {
		IP* ip = (IP*)ether->payload;
	//	inbound(ip);	
		if(ip->protocol == IP_PROTOCOL_ICMP && endian32(ip->destination) == address) {
			// Echo reply
			ICMP* icmp = (ICMP*)ip->body;
			
			icmp->type = 0;
			icmp->checksum = 0;
			icmp->checksum = endian16(checksum(icmp, packet->end - packet->start - ETHER_LEN - IP_LEN));
			
			ip->destination = ip->source;
			ip->source = endian32(address);
			ip->ttl = endian8(64);
			ip->checksum = 0;
			ip->checksum = endian16(checksum(ip, ip->ihl * 4));
			
			ether->dmac = ether->smac;
			ether->smac = endian48(ni->mac);
			
			ni_output(ni, packet);
			packet = NULL;
		} else if(ip->protocol == IP_PROTOCOL_UDP) {
			UDP* udp = (UDP*)ip->body;
			
			if(endian16(udp->destination) == 7) {
				uint16_t t = udp->destination;
				udp->destination = udp->source;
				udp->source = t;
				udp->checksum = 0;
				
				uint32_t t2 = ip->destination;
				ip->destination = ip->source;
				ip->source = t2;
				ip->ttl = 0x40;
				ip->checksum = 0;
				ip->checksum = endian16(checksum(ip, ip->ihl * 4));

				uint64_t t3 = ether->dmac;
				ether->dmac = ether->smac;
				ether->smac = t3;
				
				ni_output(ni, packet);
				packet = NULL;
			}
		} else if(ip->protocol == IP_PROTOCOL_TCP) {
			TCP* tcp = (TCP*)ip->body;
			
			printf("source=%u, destination=%u, sequence=%u, acknowledgement=%u\n", 
				endian16(tcp->source), endian16(tcp->destination), endian32(tcp->sequence), endian32(tcp->acknowledgement));
			printf("offset=%d, ns=%d, cwr=%d, ece=%d, urg=%d, ack=%d, psh=%d, rst=%d, syn=%d, fin=%d\n", 
				tcp->offset, tcp->ns, tcp->cwr, tcp->ece, tcp->urg, tcp->ack, tcp->psh, tcp->rst, tcp->syn, tcp->fin);
			printf("window=%d, checksum=%x, urgent=%d\n", endian16(tcp->window), endian16(tcp->checksum), endian16(tcp->urgent));
		}
	}
	
	if(packet)
		ni_free(packet);
}

void destroy() {
}

void gdestroy() {
}

uint64_t num;
int main(int argc, char** argv) {
	printf("Thread %d bootting\n", thread_id());
	if(thread_id() == 0) {
		ginit(argc, argv);
	}
	
	thread_barrior();
	
	init(argc, argv);
	
	thread_barrior();
	
	uint32_t i = 0;
	while(1) {
		uint32_t count = ni_count();
		if(count > 0) {
			i = (i + 1) % count;
			
			NetworkInterface* ni = ni_get(i);
			if(ni_has_input(ni)) {
				process(ni);
			}
		}
	}
	
	thread_barrior();
	
	destroy();
	
	thread_barrior();
	
	if(thread_id() == 0) {
		gdestroy(argc, argv);
	}
	
	return 0;
}
