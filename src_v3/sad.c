#include "sad.h"

// KEY : Packet's dst_ip, ipsec_protocol, spi   
SA* getSA(IP* packet)
{
	SA* tmp = NULL;
printf("getSA in\n");
	ESP* esp = (ESP*)packet->body;

	list_for_each_entry(tmp, &((sad.sa_list)->list), list)
	{
		printf("esp->spi : %d  sad->spi : %d\n", endian32(esp->spi), tmp->spi);
		if(endian32(esp->spi) == tmp->spi)
		{
			printf("packet->dst : %x sad->dst : %x\n", endian32(packet->destination), tmp->dst_ip);
			if(endian32(packet->destination) == tmp->dst_ip)
			{
				printf("packet->protocol : %d sad->protocol : %d\n", packet->protocol, tmp->protocol);
				if(packet->protocol == tmp->protocol)
				{
					return tmp;
				}
			}
		}
	}

	return NULL;
}
/*
	TODO : Match the packet’s selector fields against those in the SA
	bundles found in (1) to locate the first SA bundle that
	matches. If no SAs were found or none match, create an
	appropriate SA bundle and link the SPD entry to the SAD
	entry. If no key management entity is found, drop the
	packet. 
*/
// KEY : Packet's src_ip, dst_ip, xpt_protocol(upperspec), (src_port), (dst_port) TODO : port
SA* findSA(SA* sa, SP* current_sp, IP* packet)
{
	// TODO : Dynamic SA Addition (IKE) : Just drop the packet now
/*	if(sa == NULL)
		return NULL;

	SA* tmp = NULL;

	list_for_each_entry(tmp, &(sa->bundle_list->list), list)
	{
		printf("packet->source : %x  bundlelist->src_ip : %x\n", endian32(packet->source), tmp->src_ip);
		if(endian32(packet->source) == tmp->src_ip)
		{
		printf("packet->dst : %x  bundlelist->dst_ip : %x\n", endian32(packet->destination), tmp->dst_ip);
			if(endian32(packet->destination) == tmp->dst_ip)
			{
		printf("upperspec : %d  packet->protocol : %d\n", current_sp->upperspec, packet->protocol);
				if(current_sp->upperspec == IP_PROTOCOL_ANY)
				{
					return tmp;
				}
				else if(packet->protocol == current_sp->upperspec)
					return tmp;
			}
		}
	}

	return NULL;*/
	return current_sp->sa_pointer;
}
