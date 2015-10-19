#include <malloc.h>
#define DONT_MAKE_WRAPPER
#include <_malloc.h>
#undef DONT_MAKE_WRAPPER
#include <net/ni.h>

#include "ipsec.h"
#include "content.h"

Content* content_alloc(NetworkInterface* ni, uint64_t* attrs) {
	uint64_t get_value(uint64_t key) {
		int i = 0;
		while(attrs[i * 2] != NI_NONE) {
			if(attrs[i * 2] == key)
				return attrs[i * 2 + 1];

			i++;
		}

		return (uint64_t)-1;
	}

	uint8_t mode = IPSEC_MODE_TRANSPORT;
	uint32_t t_src_ip = 0;
	uint32_t t_dest_ip = 0;
	uint8_t crypto_algorithm = 0;
	uint8_t auth_algorithm = 0;

	for(int i = 0 ; attrs[i * 2] != NONE; i++) {
		switch(attrs[i * 2]) {
			case CONTENT_IPSEC_MODE:
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
	
	uint8_t ipsec_protocol = 0;
	if(get_value(CONTENT_CRYPTO_ALGORITHM)) {
		ipsec_protocol = IP_PROTOCOL_ESP;
	} else if(get_value(CONTENT_AUTH_ALGORITHM)){
		ipsec_protocol = IP_PROTOCOL_AH;
	}
	if(!ipsec_protocol) {
		printf("Can'nt found algorihtm\n");
		return NULL;
	}

	Content* content = NULL;
	switch(ipsec_protocol) {
		case IP_PROTOCOL_ESP:
			switch(mode) {
				case IPSEC_MODE_TUNNEL:
					content = __malloc(sizeof(Content_ESP_Tunnel), ni->pool);
					break;
				case IPSEC_MODE_TRANSPORT:
					content = __malloc(sizeof(Content_ESP_Transport), ni->pool);
					break;
			}
			break;
		case IP_PROTOCOL_AH:
			switch(mode) {
				case IPSEC_MODE_TUNNEL:
					content = __malloc(sizeof(Content_AH_Tunnel), ni->pool);
					break;
				case IPSEC_MODE_TRANSPORT:
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
	content->ipsec_protocol = ipsec_protocol;
	content->ipsec_mode = mode;
	switch(content->ipsec_protocol) {
		case IP_PROTOCOL_ESP:
			switch(content->ipsec_mode) {
				case IPSEC_MODE_TUNNEL:
					((Content_ESP_Tunnel*)content)->crypto_algorithm = crypto_algorithm;
					((Content_ESP_Tunnel*)content)->auth_algorithm = auth_algorithm;
					((Content_ESP_Tunnel*)content)->t_src_ip = t_src_ip;
					((Content_ESP_Tunnel*)content)->t_dest_ip = t_dest_ip;
					break;
				case IPSEC_MODE_TRANSPORT:
					((Content_ESP_Transport*)content)->crypto_algorithm = crypto_algorithm;
					((Content_ESP_Transport*)content)->auth_algorithm = auth_algorithm;
					break;
			}
			break;
		case IP_PROTOCOL_AH:
			switch(content->ipsec_mode) {
				case IPSEC_MODE_TUNNEL:
					((Content_AH_Tunnel*)content)->auth_algorithm = auth_algorithm;
					((Content_AH_Tunnel*)content)->t_src_ip = t_src_ip;
					((Content_AH_Tunnel*)content)->t_dest_ip = t_dest_ip;
					break;
				case IPSEC_MODE_TRANSPORT:
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
