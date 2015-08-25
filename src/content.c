#include <malloc.h>
#define DONT_MAKE_WRAPPER
#include <_malloc.h>
#undef DONT_MAKE_WRAPPER
#include <net/ni.h>

#include "content.h"

Content* content_alloc(NetworkInterface* ni, uint64_t* attrs) {
	uint8_t protocol = IP_PROTOCOL_ESP;
	uint8_t mode = CONTENT_MODE_TRANSPORT;
	uint32_t t_src_ip = 0;
	uint32_t t_dest_ip = 0;
	uint8_t crypto_algorithm = 0;
	uint8_t auth_algorithm = 0;

	for(int i = 0 ; attrs[i * 2] != NONE; i++) {
		switch(attrs[i * 2]) {
			case CONTENT_PROTOCOL:
				break;
			case CONTENT_MODE:
				mode = (uint8_t)attrs[i * 2 + 1];
				break;
			case CONTENT_TUNNEL_SOURCE_ADDR:
				t_src_ip = attrs[i * 2 + 1];
				break;
			case CONTENT_TUNNEL_DESTINATION_ADDR:
				t_dest_ip = attrs[i * 2 + 1];
				break;
			case CONTENT_CRYPTO_ALGORITHM:
				crypto_algorithm = attrs[i * 2 + 1];
				break;
			case CONTENT_AUTH_ALGORITHM:
				auth_algorithm = attrs[i * 2 + 1];
				break;
		}
	}
	
	Content* content = NULL;
	switch(protocol) {
		case IP_PROTOCOL_ESP:
			switch(mode) {
				case CONTENT_MODE_TUNNEL:
					content = __malloc(sizeof(Content_ESP_Tunnel), ni->pool);
					break;
				case CONTENT_MODE_TRANSPORT:
					content = __malloc(sizeof(Content_ESP_Transport), ni->pool);
					break;
			}
			break;
		case IP_PROTOCOL_AH:
			switch(mode) {
				case CONTENT_MODE_TUNNEL:
					content = __malloc(sizeof(Content_AH_Tunnel), ni->pool);
					break;
				case CONTENT_MODE_TRANSPORT:
					content = __malloc(sizeof(Content_AH_Transport), ni->pool);
					break;
			}
			break;
	}
	if(!content) {
		printf("Can'nt allocate content\n");
		return NULL;
	}

	content->ni = ni;
	content->protocol = protocol;
	content->mode = mode;
	switch(content->protocol) {
		case IP_PROTOCOL_ESP:
			switch(content->mode) {
				case CONTENT_MODE_TUNNEL:
					((Content_ESP_Tunnel*)content)->crypto_algorithm = crypto_algorithm;
					((Content_ESP_Tunnel*)content)->auth_algorithm = auth_algorithm;
					((Content_ESP_Tunnel*)content)->t_src_ip = t_src_ip;
					((Content_ESP_Tunnel*)content)->t_dest_ip = t_dest_ip;
					break;
				case CONTENT_MODE_TRANSPORT:
					((Content_ESP_Transport*)content)->crypto_algorithm = crypto_algorithm;
					((Content_ESP_Transport*)content)->auth_algorithm = auth_algorithm;
					break;
			}
			break;
		case IP_PROTOCOL_AH:
			switch(content->mode) {
				case CONTENT_MODE_TUNNEL:
					((Content_AH_Tunnel*)content)->auth_algorithm = auth_algorithm;
					((Content_AH_Tunnel*)content)->t_src_ip = t_src_ip;
					((Content_AH_Tunnel*)content)->t_dest_ip = t_dest_ip;
					break;
				case CONTENT_MODE_TRANSPORT:
					((Content_AH_Transport*)content)->auth_algorithm = auth_algorithm;
					break;
			}
			break;
	}

	return content;
}

void content_free(Content* content) {
	__free(content->ni, content);
}
