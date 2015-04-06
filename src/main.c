#include <stdio.h>
#include <stdbool.h>
#include <thread.h>
#include <readline.h>
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
	ni_config_put(ni_outbound, "ip", (void*)(uint64_t)0xc0a8640a);	// 192.168.100.10
	ni_config_put(ni_outbound, "netmask", (void*)(uint64_t)0xffffff00);	//24

	return true;
}

void init(int argc, char** argv) {
	if(!ipsec_init()) {
		printf("Thread id %d ipsec init error!\n", thread_id());
	}


	receiver_init();
}

void process_inbound(NetworkInterface* ni) {	// Packets from Internet
	Packet* packet = ni_input(ni);
	if(!packet)
		return;

	if(arp_process(packet))
		return;

	if(icmp_process(packet))
		return;

	Ether* ether = (Ether*)(packet->buffer + packet->start);

	//Only Support IPv4
	if(endian16(ether->type) == ETHER_TYPE_IPv4) {
		IP* ip = (IP*)ether->payload;
		if(ipsec_inbound(packet) == 0) {
			ether->dmac = endian48(arp_get_mac(ni_outbound, endian32(ip->destination)));
			ether->smac = endian48(ni_outbound->mac);
			ni_output(ni_outbound, packet);
			packet = NULL;
		}
	} else {
		ni_output(ni_outbound, packet);
		packet = NULL;
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

	/*TEST
	if(icmp_process(packet))
		return;
	*/

	Ether* ether = (Ether*)(packet->buffer + packet->start);

	//Only Support IPv4
	if(endian16(ether->type) == ETHER_TYPE_IPv4) {
		IP* ip = (IP*)ether->payload;
		if(ipsec_outbound(packet) == 0) {
			ether->dmac = endian48(arp_get_mac(ni_inbound, endian32(ip->destination)));
			ether->smac = endian48(ni_inbound->mac);

			printf("here");
			ni_output(ni_inbound, packet);
			printf("test");
			packet = NULL;
			return;
		}
	} else {
		ni_output(ni_inbound, packet);
		packet = NULL;
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

		char* line = readline();
		if(line != NULL) {
			receiver_parse(line);
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
