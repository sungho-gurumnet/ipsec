#include <malloc.h>
#define DONT_MAKE_WRAPPER
#include <_malloc.h>
#undef DONT_MAKE_WRAPPER
#include <net/ni.h>

#include "sa.h"
#include "auth.h"
#include "crypto.h"

SA* sa_alloc(NetworkInterface* ni, uint64_t* attrs) {
	bool has_key(uint64_t key) {
		int i = 0;
		while(attrs[i * 2] != NI_NONE) {
			if(attrs[i * 2] == key)
				return true;

			i++;
		}

		return false;
	}

	uint64_t get_value(uint64_t key) {
		int i = 0;
		while(attrs[i * 2] != NI_NONE) {
			if(attrs[i * 2] == key)
				return attrs[i * 2 + 1];

			i++;
		}

		return (uint64_t)-1;
	}

        SA* sa = NULL;
	if(has_key(SA_PROTOCOL)) {
		uint64_t value = get_value(SA_PROTOCOL);
		switch(value) {
			case IP_PROTOCOL_ESP:
				if(!has_key(SA_CRYPTO_ALGORITHM)) {
					return NULL;
				}
				sa = __malloc(sizeof(SA_ESP), ni->pool);
				sa->protocol = value;
				break;
			case IP_PROTOCOL_AH:
				if(!has_key(SA_AUTH_ALGORITHM)) {
					return NULL;
				}
				sa = __malloc(sizeof(SA_AH), ni->pool);
				sa->protocol = value;
				break;
		}

		if(!sa) {
			printf("Can'nt allocate SA\n");
			return NULL;
		}
		memset(sa, 0, sizeof(SA));
	} else  {
		printf("Can'nt found protocol\n");
		return NULL;
	}

	for(int i = 0; (attrs[i * 2] != SA_NONE); i++) {
		switch(attrs[i * 2]) {
			case SA_SPI:
				break;
			case SA_SOURCE_IP:
				sa->src_ip = attrs[i * 2 + 1];
				break;
			case SA_DESTINATION_IP:
				sa->dest_ip = attrs[i * 2 + 1];
				break;
			case SA_DESTINATION_PORT:
				sa->dest_port = attrs[i * 2 + 1];
				break;
			case SA_CRYPTO_ALGORITHM:
				((SA_ESP*)sa)->crypto_algorithm = attrs[i * 2 + 1];
				((SA_ESP*)sa)->crypto = (void*)get_cryptography(attrs[i * 2 + 1]);
				break;
			case SA_CRYPTO_KEY:
				memcpy(((SA_ESP*)sa)->crypto_key, (uint64_t*)attrs[i * 2 + 1], sizeof(uint64_t) * 3);

				DES_set_odd_parity((DES_cblock*)&(((SA_ESP*)sa)->crypto_key[0]));
				DES_set_odd_parity((DES_cblock*)&(((SA_ESP*)sa)->crypto_key[1]));
				DES_set_odd_parity((DES_cblock*)&(((SA_ESP*)sa)->crypto_key[2]));
				break;
			case SA_IV_SUPPORT:
				((SA_ESP*)sa)->iv = attrs[i * 2 + 1];
				break;
			case SA_AUTH_ALGORITHM:
				switch(sa->protocol) { 
					case IP_PROTOCOL_AH:
						((SA_AH*)sa)->auth_algorithm = attrs[i * 2 + 1];
						((SA_AH*)sa)->auth = (void*)get_authentication(attrs[i * 2 + 1]);
						break;
					case IP_PROTOCOL_ESP:
						((SA_ESP*)sa)->auth_algorithm = attrs[i * 2 + 1];
						((SA_ESP*)sa)->auth = (void*)get_authentication(attrs[i * 2 + 1]);
						break;
				}
				break;
			case SA_AUTH_KEY:
				memcpy(((SA_AH*)sa)->auth_key, (uint64_t*)attrs[i * 2 + 1], sizeof(uint64_t) * 8);
				break;
			case SA_REPLY:
				if(attrs[i * 2 + 1]) {
					sa->window = (Window*)__malloc(sizeof(Window), ni->pool);
					if(!sa->window) {
						printf("Can'nt allocate window\n");
						goto sa_free;
					}
					memset(sa->window, 0x0, sizeof(Window));
				}
				break;
		}
	}

	return sa;

sa_free:
	__free(sa, ni->pool);

	return NULL;
}

bool sa_free(SA* sa) {
	free(sa->window);
	free(sa);

	return true;
}
