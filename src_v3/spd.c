#include "spd.h"

// KEY : src_ip arrange, dst_ip arrange, xpt_protocol(upperspec), (src_port), (dst_port) TODO : port
SP* getSP(IP* packet)
{
	SP* tmp = NULL;
	printf("getSP in \n" );

	list_for_each_entry(tmp, &((spd.sp_list)->list), list)
	{
		printf("packet->source : %x spd->source : %x\n", (endian32(packet->source) ), (tmp->src_ip ));
		if((endian32(packet->source) & tmp->src_mask) == (tmp->src_ip & tmp->src_mask))
		{
			printf("packet->dst : %x spd->dst : %x\n", (endian32(packet->destination) & tmp->dst_mask), (tmp->dst_ip & tmp->dst_mask));
			if((endian32(packet->destination) & tmp->dst_mask) == (tmp->dst_ip & tmp->dst_mask))
			{
				printf("spd->upperspec : %d , packet->protocol : %d\n", tmp->upperspec, packet->protocol);
				if(tmp->upperspec == IP_PROTOCOL_ANY)
					return tmp;
				else if(packet->protocol == tmp->upperspec)
					return tmp;
			}
		}
	}

	return NULL;
}

int setSA_pointer(SA* sa)
{
	printf("setSA_pointer in \n");
	SP* tmp = NULL;

	list_for_each_entry(tmp, &((spd.sp_list)->list), list)
	{
		printf("sa->src_ip : %x, spd->src_ip : %x\n", (sa->src_ip & tmp->src_mask), (tmp->src_ip & tmp->src_mask));

		if(tmp->mode == TRANSPORT)
		{
			if((sa->src_ip & tmp->src_mask) == (tmp->src_ip & tmp->src_mask))
			{
				printf("sa->dst_ip : %x, spd->dst_ip : %x\n", (sa->dst_ip & tmp->dst_mask), (tmp->dst_ip & tmp->dst_mask));

				if((sa->dst_ip & tmp->dst_mask) == (tmp->dst_ip & tmp->dst_mask))
				{
					printf("sa->protocol : %d, spd->protocol : %d\n", sa->protocol, tmp->protocol);
					if(sa->protocol == tmp->protocol)
					{
						printf("spd->sa_pointer : %x\n", tmp->sa_pointer);

						if(tmp->sa_pointer == NULL)
						{
							sa->bundle_list = sa;

							INIT_LIST_HEAD(&((sa->bundle_list)->list));
							tmp->sa_pointer = sa;
							printf("new sa\n");
							return 0;
						}
						else
						{
							list_add_head(&(sa->list), &(tmp->sa_pointer->bundle_list->list));
							printf("list in\n");
							return 0;
						}
					}
				}
			}
		}
		else if(tmp->mode == TUNNEL)
		{
			if(sa->src_ip == tmp->t_src_ip)
			{
				printf("T : sa->dst_ip : %x, spd->dst_ip : %x\n", sa->dst_ip, tmp->t_dst_ip);

				if(sa->dst_ip == tmp->t_dst_ip)
				{
					printf("T : sa->protocol : %d, spd->protocol : %d\n", sa->protocol, tmp->protocol);
					if(sa->protocol == tmp->protocol)
					{
						printf("T : spd->sa_pointer : %x\n", tmp->sa_pointer);

						if(tmp->sa_pointer == NULL)
						{
							//sa->bundle_list = sa;
							//INIT_LIST_HEAD(&((sa->bundle_list)->list));
							tmp->sa_pointer = sa;
							printf("T : new sa\n");
							return 0;
						}
						else
						{
							//list_add_head(&(sa->list), &(tmp->sa_pointer->bundle_list->list));
							printf("T : list in\n");
							return 0;
						}

					}
				}
			}
		}
	}

	return -1;		
}

