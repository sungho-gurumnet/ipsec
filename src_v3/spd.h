#ifndef __SPD_H__
#define __SPD_H__

#include <stdio.h>
#include <stdint.h>
#include <net/ip.h>
#include <net/ether.h>
#include "sp.h"
#include "sa.h"

typedef struct
{
	SP* sp_list;
	size_t max_size;
	size_t size;
}SPD;

SPD spd;

SP* getSP(IP* packet);
int setSA_pointer(SA* sa);
#endif
