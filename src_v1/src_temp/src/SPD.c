#include "SPD.h"

SP* SPD_lookup_in(IP* packet)
{
	// for each SPs in spd
	//KEY : destination address
	SP_node* tmp = 0; 
	
	list_for_each_entry(tmp, &((spd.sp_list)->list), list)
	{
		if(endian32(packet->destination) == (tmp->sp)->destination)
		{
			if((tmp->sp)->direction != IN)
					continue;
			return tmp->sp;
		}	
	}

	return NULL;
}

SP* SPD_lookup_out(IP* packet)
{
	// for each SPs in spd
	//KEY : destination address, source address 
	SP_node* tmp = 0;
	
	list_for_each_entry(tmp, &((spd.sp_list)->list), list)
	{
		if(endian32(packet->destination) == (tmp->sp)->destination &&
		   endian32(packet->source) == (tmp->sp)->source)
		{
			if(tmp->sp->direction != OUT)
					continue;
			return tmp->sp;
		}	
	}
	return NULL;
}
