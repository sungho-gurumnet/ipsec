#include <net/ni.h>
#include <util/map.h>
#include <malloc.h>
#define DONT_MAKE_WRAPPER
#include <_malloc.h>
#undef DONT_MAKE_WRAPPER

#include "sp.h"
#include "sa.h"
#include "socket.h"

Socket* socket_create(NetworkInterface* ni, SP* sp, SA* sa) {
	Socket* socket = __malloc(sizeof(socket), ni->pool);
	if(!socket)
		return NULL;

	socket->sp = sp;
	socket->sa = sa;
	socket->fin = false;

	return socket;
}

void socket_delete(NetworkInterface* ni, Socket* socket) {
	__free(socket, ni->pool);
}

bool socket_add(NetworkInterface* ni, uint32_t ip, uint16_t port, Socket* socket) {
	Map* sockets = ni_config_get(ni, SOCKETS);
	if(!sockets) {
		sockets = map_create(16, NULL, NULL, ni->pool);
		if(!sockets) {
			printf("Can'nt create socket table\n");
			return false;
		}

		if(!ni_config_put(ni, SOCKETS, sockets)) {
			map_destroy(sockets);
			return false;
		}
	}

	uint64_t key = (uint64_t)ip << 32 | (uint64_t)port;
	if(!map_put(sockets, (void*)key, socket)) {
		if(map_is_empty(sockets)) {
			map_destroy(sockets);
			ni_config_remove(ni, SOCKETS);
		}
		return false;
	}

	return true;
}

bool socket_remove(NetworkInterface* ni, uint32_t ip, uint16_t port) {
	Map* sockets = ni_config_get(ni, SOCKETS);
	if(!sockets)
		return false;

	uint64_t key = (uint64_t)ip << 32 | (uint64_t)port;
	Socket* socket = map_remove(sockets, (void*)key);
	if(!socket)
		return false;

	socket_delete(ni, socket);

	if(map_is_empty(sockets)) {
		map_destroy(sockets);
		ni_config_remove(ni, SOCKETS);
	}

	return true;
}

Socket* socket_get(NetworkInterface* ni, uint32_t ip, uint16_t port) {
	Map* sockets = ni_config_get(ni, SOCKETS);
	if(!sockets)
		return NULL;

	uint64_t key = (uint64_t)ip << 32 | (uint64_t)port;

	return map_get(sockets, (void*)key);
}
