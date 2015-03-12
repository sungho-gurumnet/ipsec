#ifndef __RECEIVER_H__
#define __RECEIVER_H__

#include <util/cmd.h>
#include <util/types.h>
/*
extern SPD spd;
extern SAD sad;
*/

int receiver_init();
int receiver_parse(char* line);
#endif /* __RECEIVER_H_ */
