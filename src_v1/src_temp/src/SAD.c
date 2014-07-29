#include "SAD.h"

SA* SAD_lookup_in(IP* packet)
{
	// for each SAs in sad
	//KEY1 : source address
	SA_node* tmp;

	list_for_each_entry(tmp, &((sad.sa_list)->list), list)
	{
		if(endian32(packet->source) == (tmp->sa)->source)
		{
			//KEY2 : protocol
			if(endian8(packet->protocol) == (tmp->sa)->protocol)
			{
				ESP* esp = (ESP*)packet->body;

				//KEY3 : SPI
				if(endian32(esp->SPI) == (tmp->sa)->SPI)
				{
					return tmp->sa;
				}
			}
		}	
	}
	return NULL;
}

SA* SAD_lookup_out(IP* packet)
{	
	// for each SAs in sad
	//KEY1 : destination address
	SA_node* tmp1;
	SP_node* tmp2;
	
	switch(current_sp->mode)
	{
		case TRANSPORT :
			list_for_each_entry(tmp1, &((sad.sa_list)->list), list)
			{
				if(endian32(packet->destination) == tmp1->sa->destination)
				{
					list_for_each_entry(tmp2, &((spd.sp_list)->list), list)
					{
						if(tmp2->sp->protocol == tmp1->sa->protocol)
						{
							// Slect SPI function here
							return tmp1->sa;
						}
						else
						{
							// if IKE module exsits 
							// IKE function acts to make new SA here
							// else just Discard packet
						}
					}
				}	
			}
			return NULL;
		
		case TUNNEL :
			list_for_each_entry(tmp1, &((sad.sa_list)->list), list)
			{
				if(current_sp->t_destination == tmp1->sa->destination)
				{
					list_for_each_entry(tmp2, &((spd.sp_list)->list), list)
					{
						if(tmp2->sp->protocol == tmp1->sa->protocol)
						{
							// Slect SPI function here
							return tmp1->sa;
						}
						else
						{
							return NULL;
							// if IKE module exsits 
							// IKE function acts to make new SA here
							// else just Discard packet
						}
					}
				}	
			}
			return NULL;
	}

	return NULL;
}
