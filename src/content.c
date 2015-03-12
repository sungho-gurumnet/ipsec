#include "content.h"

Content* create_content(uint8_t protocol, uint8_t mode, uint32_t t_src_ip, uint32_t t_dst_ip, uint8_t crypto_algorithm, uint8_t auth_algorithm) {
	Content* cont = (Content*)malloc(sizeof(Content));
	if(cont== NULL)
		return NULL;

	cont->protocol = protocol;
	cont->mode = mode;
	if(mode == TUNNEL) {
		cont->t_src_ip = t_src_ip;
		cont->t_dst_ip = t_dst_ip;
	}

	cont->crypto_algorithm = crypto_algorithm;
	cont->auth_algorithm = auth_algorithm;

	return cont;
}
