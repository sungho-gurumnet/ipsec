#include "socket.h"

bool socket_init() {
	map_socket = map_create(4096, NULL, NULL, NULL);
	if(map_socket == NULL)
		return false;
	return true;
}

socket* socket_create(SP* sp, SA* sa) {

	socket* socket = malloc(sizeof(socket));
	socket->sp = sp;
	socket->sa = sa;

	return socket;
}

bool socket_add(uint32_t ip, uint16_t port, socket* socket) {
	uint64_t key = ip;
	key <<= 32;
	key += port;

	return map_put(map_socket, (void*)key, socket);
}

socket* socket_get(uint32_t ip, uint16_t port) {
	uint64_t key = ip;
	key <<= 32;
	key += port;

	return (socket*)map_get(map_socket, (void*)key);
}

bool socket_delete(uint32_t ip, uint16_t port) {
	uint64_t key = ip;
	key <<= 32;
	key += port;
	socket* socket = map_remove(map_socket, (void*)key);
	if(socket != NULL) {
		free(socket);
		return true;
	} else
		return false;
}

bool socket_exist(uint32_t ip, uint16_t port) {
	uint64_t key = ip;
	key <<= 32;
	key += port;
	return map_contains(map_socket, (void*)key);
}
