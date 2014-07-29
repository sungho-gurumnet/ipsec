#include <stdio.h>
#include <thread.h>
#include <net/ni.h>
#include <net/packet.h>
#include <net/ether.h>
#include <net/arp.h>
#include <net/ip.h>
#include <net/icmp.h>
#include <net/checksum.h>
#include <net/udp.h>
#include <net/tcp.h>
#include "ipsec.h"

static NetworkInterface* ni0;
static NetworkInterface* ni1;

void ginit(int argc, char** argv) {
	ni0 = ni_get(0);
	ni0->config = map_create(8, map_string_hash, map_string_equals, malloc, free);
	map_put(ni0->config, "ip", (void*)(uint64_t)0xac100001);	// 172.16.0.1
	map_put(ni0->config, "netmask", (void*)(uint64_t)0xffffff00);
	
	ni1 = ni_get(1);
	ni1->config = map_create(8, map_string_hash, map_string_equals, malloc, free);
	map_put(ni1->config, "ip", (void*)(uint64_t)0xc0a8c80a);	// 192.168.200.10
	map_put(ni1->config, "netmask", (void*)(uint64_t)0xffffff00);
	
	init_list();
}

void init(int argc, char** argv) {
}

//static uint32_t address = 0xac1001fe; // 172.16.1.254
//static uint32_t address = 0xc0a86401;	// 192.168.100.1
#ifdef _GW2_
//static uint32_t address = 0xc0a8640a;	// 192.168.100.10
//static uint32_t address_t = 0xac100001;
#endif
#ifdef _GW1_
//static uint32_t address = 0xc0a8c80a;	// 192.168.200.10
//static uint32_t address_t = 0xac100001;
#endif


void process0(NetworkInterface* ni) {	// Packets from Internet
	Packet* packet = ni_input(ni);
	if(!packet)
		return;
	if(arp_process(packet))
		return;
	Ether* ether = (Ether*)(packet->buffer + packet->start);
	
		IP* ip = (IP*)ether->payload;
		printf("DEBUG : SRC: %x DEST : %x SRC MAC:%012lx DEST MAC :%012lx\n, ETHER TYPE: %x\n",
				endian32(ip->source), endian32(ip->destination), endian48(ether->smac), endian48(ether->dmac), endian16(ether->type));
	
	if(endian16(ether->type) == ETHER_TYPE_IPv4) {
		
		if(ip->protocol == IP_PROTOCOL_ESP){
			
			int orig_len = endian16(ip->length);
		
			if(decrypt(ip) >= 0)
			{
				printf("decrypt in\n");
				
				packet->end += (endian16(ip->length) - orig_len);
				
//				printf("decrypt mac (dmac) :  %012lx , (smac) : %012lx\n",endian48(ether->dmac), endian48(ether->smac));
				ether->dmac = endian48(arp_get_mac(ni1, endian32(ip->destination)));
				ether->smac = endian48(ni1->mac);
				
				ni_output(ni1, packet);
				packet = NULL;
			}
		}
	}
	
	if(packet)
		ni_free(packet);
}

void process1(NetworkInterface* ni) {	// Packets from Intranet
	Packet* packet = ni_input(ni);
	if(!packet)
		return;
	if(arp_process(packet))
		return;
	
	Ether* ether = (Ether*)(packet->buffer + packet->start);
	
		IP* ip = (IP*)ether->payload;
		printf("DEBUG : SRC: %x DEST : %x SRC MAC:%012lx DEST MAC :%012lx\n, ETHER TYPE: %x\n",
				endian32(ip->source), endian32(ip->destination), endian48(ether->smac), endian48(ether->dmac), endian16(ether->type));
	
	if(endian16(ether->type) == ETHER_TYPE_IPv4) {
		
		int orig_len = endian16(ip->length);
		
		if(encrypt(ip) >= 0){
			printf("encrypt in\n");

			packet->end += (endian16(ip->length) - orig_len);
			ether->dmac = endian48(arp_get_mac(ni0, endian32(ip->destination)));
			ether->smac = endian48(ni0->mac);
			
			ni_output(ni0, packet);
			packet = NULL;
		} else if(ip->protocol == IP_PROTOCOL_UDP) {
			UDP* udp = (UDP*)ip->body;
			
			if(endian16(udp->destination) == SETKEY_PORT_NUM) {
					
				int orig_len = endian16(ip->length);

				Parameter* parameter = (Parameter*)udp->body;
				
				int result = parse(parameter);
			
				memcpy(&(udp->body), &result, sizeof(result));
				
				for(int i = 0; i < 64 /* Packet Minimum Size */ - ETHER_LEN /* 14 */ - IP_LEN /* 20 */ - UDP_LEN /* 8 */ - sizeof(result); i++)
					udp->body[i + 4] = i;

				uint16_t t = udp->destination;
				udp->destination = udp->source;
				udp->source = t;
				udp->checksum = 0;
				udp->length = endian16(64 - ETHER_LEN - IP_LEN);

				uint32_t t2 = ip->destination;
				ip->destination = ip->source;
				ip->source = t2;
				ip->ttl = 0x40;
				ip->length = endian16(64 - ETHER_LEN);
				ip->checksum = 0;
				ip->checksum = endian16(checksum(ip, ip->ihl * 4));
				
				uint64_t t3 = ether->dmac;
				ether->dmac = ether->smac;
				ether->smac = t3;
				
				packet->end += (endian16(ip->length) - orig_len);
				
				ni_output(ni, packet);
				packet = NULL;
			}
		}
	}
	
	if(packet)
		ni_free(packet);

	packet = NULL;
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

	while(1){
		uint32_t count = ni_count();
		if(count > 0){
			
			if(ni_has_input(ni0)) {
				process0(ni0);
			}
			
			if(ni_has_input(ni1)) {
				process1(ni1);
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
