#ifndef __SAD_H__
#define __SAD_H__

#include "SA.h"
#include "ip.h"
#include "esp.h"
#include "SPD.h"
#include "list.h"
#include <stdio.h>

#define TDES_CBC 0x01

typedef struct
{
	struct list_head list;
	SA* sa;
}SA_node;

typedef struct
{
	SA_node* sa_list;
}SAD;

SA* SAD_lookup_in(IP* packet);
SA* SAD_lookup_out(IP* packet);

extern SAD sad;
extern SPD spd;
extern SP* current_sp;
#endif
