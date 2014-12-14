#include <stdio.h>
#include <stdbool.h>
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

NetworkInterface* ni_inbound;
NetworkInterface* ni_outbound;

bool ginit(int argc, char** argv) {
	ni_inbound = ni_get(0);
	ni_config_put(ni_inbound, "ip", (void*)(uint64_t)0xac100001);	// 172.16.0.1
	ni_config_put(ni_inbound, "netmask", (void*)(uint64_t)0xffffff00);	//24

	ni_outbound = ni_get(1);
	ni_config_put(ni_outbound, "ip", (void*)(uint64_t)0xc0a8c80a);	// 192.168.200.10
	ni_config_put(ni_outbound, "netmask", (void*)(uint64_t)0xffffff00);	//24

	if(ipsec_init())
		return false;

	//set SP & SD
	return true;
}

void init(int argc, char** argv) {
}

void process_inbound(NetworkInterface* ni) {	// Packets from Internet
	Packet* packet = ni_input(ni);
	if(!packet)
		return;

	if(arp_process(packet))
		return;

	Ether* ether = (Ether*)(packet->buffer + packet->start);

	IP* ip = (IP*)ether->payload;

	if(endian16(ether->type) == ETHER_TYPE_IPv4) {
		if(ipsec_inbound(packet) == 0) {
			ether->dmac = endian48(arp_get_mac(ni_outbound, endian32(ip->destination)));
			ether->smac = endian48(ni_outbound->mac);
			ni_output(ni_outbound, packet);
			packet = NULL;
		}
	}

	if(packet)
		ni_free(packet);
}

void process_outbound(NetworkInterface* ni) {	// Packets from Intranet
	Packet* packet = ni_input(ni);
	if(!packet)
		return;

	if(arp_process(packet))
		return;

	Ether* ether = (Ether*)(packet->buffer + packet->start);


	if(endian16(ether->type) == ETHER_TYPE_IPv4) {
		IP* ip = (IP*)ether->payload;
		if(ip->protocol == IP_PROTOCOL_UDP) {
			UDP* udp = (UDP*)ip->body;
			if(endian16(udp->destination) == SETKEY_PORT_NUM) {
				/*
				int orig_len = endian16(ip->length);

				Parameter* parameter = (Parameter*)udp->body;

				int result = parse(parameter);

				memcpy(&(udp->body), &result, sizeof(result));

				for(int i = 0; i < 64 - ETHER_LEN 14 - IP_LEN - UDP_LEN - sizeof(result); i++)
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

				return;
				*/
			}
		}

		if(ipsec_outbound(packet) == 0) {
			ether->dmac = endian48(arp_get_mac(ni_inbound, endian32(ip->destination)));
			ether->smac = endian48(ni_inbound->mac);

			ni_output(ni_inbound, packet);
			packet = NULL;
			return;
		}
	}

	if(packet)
		ni_free(packet);
}

void destroy() {
}

void gdestroy() {
}

int main(int argc, char** argv) {
	printf("Thread %d bootting\n", thread_id());
	if(thread_id() == 0) {
		ginit(argc, argv);
	}

	thread_barrior();

	init(argc, argv);

	thread_barrior();

	while(1) {
		uint32_t count = ni_count();
		if(count > 0){
			if(ni_has_input(ni_inbound))
				process_inbound(ni_inbound);
			if(ni_has_input(ni_outbound))
				process_outbound(ni_outbound);
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
