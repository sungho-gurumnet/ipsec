#ifndef __SAD_H__
#define __SAD_H__

#include <stdio.h>
#include <stdint.h>
#include <net/ip.h>
#include <net/ether.h>
#include "esp.h"
#include "sa.h"
#include "sp.h"

#define true 	1
#define false 	0

typedef struct
{
	SA* sa_list;
	size_t max_size;
	size_t size;
}SAD;

SAD sad;

SA* getSA(IP* packet);
SA* findSA(SA* current_sa, SP* current_sp, IP* packet);
#endif
