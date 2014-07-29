#include "sad.h"

// KEY : Packet's dst_ip, ipsec_protocol, spi   
SA* getSA(IP* packet)
{
	SA* tmp = NULL;
	
	ESP* esp = (ESP*)packet->body;

	list_for_each_entry(tmp, &((sad.sa_list)->list), list)
	{
		if(endian32(esp->spi) == tmp->spi)
		{
			if(endian32(packet->destination) == tmp->dst_ip)
			{
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
		if(endian32(packet->source) == tmp->src_ip)
		{
			if(endian32(packet->destination) == tmp->dst_ip)
			{
				if(current_sp->upperspec == IP_PROTOCOL_ANY)
				{
					return tmp;
				}
				else if(packet->protocol == current_sp->upperspec)
					return tmp;
			}
		}
	}

	return NULL;
 */
	return current_sp->sa_pointer;
}
