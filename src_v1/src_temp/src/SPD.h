#ifndef __SPD_H__
#define __SPD_H__

#include "SP.h"
#include "SA.h"
#include "ip.h"
#include "list.h"
#include <stdio.h>

typedef struct
{
	struct list_head list;
	SP* sp;
}SP_node;

typedef struct
{
	SP_node* sp_list;
}SPD;

SP* SPD_lookup_in(IP* packet);
SP* SPD_lookup_out(IP* packet);

extern SPD spd;
extern SA* current_sa;
#endif
