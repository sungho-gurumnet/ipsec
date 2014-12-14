#ifndef __SOCKET_H__
#define __SOCKET_H__
#include <util/map.h>
#include <malloc.h>
#include "sp.h"
#include "sa.h"

Map* map_socket;

typedef struct socket{
	SP* sp;
	SA* sa;
}socket;

bool socket_init();
socket* socket_create(SP* sp, SA* sa);
bool socket_add(uint32_t ip, uint16_t port, socket* data);
socket* socket_get(uint32_t src_ip, uint16_t src_port);
bool socket_delete(uint32_t ip, uint16_t port);
bool socket_exist(uint32_t ip, uint16_t port);

#endif /*__SOCKET_H__*/
