#include "receiver.h"

int parse(Parameter* parameter) {
	int result;

	switch(parameter->name) {
		case SETKEY_ADD:
			printf("SETKEY_ADD function called\n");
			result = setkey_add(
					parameter->src_ip,
					parameter->dst_ip,
					parameter->protocol,
					parameter->spi,
					parameter->extensions,
					parameter->crypto_algorithm,
					parameter->auth_algorithm,
					parameter->crypto_key,
					parameter->auth_key
					);
			break;
		
		case SETKEY_GET:
			printf("SETKEY_GET function called\n");
			result = setkey_get(
					parameter->src_ip,
					parameter->dst_ip,
					parameter->protocol,
					parameter->spi
					);
			break;
		
		case SETKEY_DELETE:
			printf("SETKEY_DELETE function called\n");
			result = setkey_delete(
					parameter->src_ip,
					parameter->dst_ip,
					parameter->protocol,
					parameter->spi
					);
			break;
		
		case SETKEY_DELETEALL:
			printf("SETKEY_DELETEALL function called\n");
			result = setkey_deleteall(
					parameter->src_ip,
					parameter->dst_ip,
					parameter->protocol
					);
			break;
		
		case SETKEY_FLUSH:
			printf("SETKEY_FLUSH function called\n");
			result = setkey_flush(
					parameter->protocol
					);
			break;
		
		case SETKEY_DUMP:
			printf("SETKEY_DUMP function called\n");
			result = setkey_dump(
					parameter->protocol
					);
			break;

		case SETKEY_SPDADD:
			printf("SETKEY_SPDADD function called\n");
			result = setkey_spdadd(
					parameter->src_ip,
					parameter->dst_ip,
					parameter->src_mask,
					parameter->dst_mask,
					parameter->src_port,
					parameter->dst_port,
					parameter->t_src_ip,
					parameter->t_dst_ip,
					parameter->upperspec,
					parameter->direction,
					parameter->action,
					parameter->protocol,
					parameter->mode,
					parameter->level
					);

			break;
		
		case SETKEY_SPDUPDATE:
			printf("SETKEY_SPDUPDATE function called\n");
			result = setkey_spdupdate(
					parameter->src_ip,
					parameter->dst_ip,
					parameter->src_mask,
					parameter->dst_mask,
					parameter->src_port,
					parameter->dst_port,
					parameter->upperspec,
					parameter->direction,
					parameter->action
					);
			break;
		
		case SETKEY_SPDDELETE:
			printf("SETKEY_SPDDELETE function called\n");
			result = setkey_spddelete(
					parameter->src_ip,
					parameter->dst_ip,
					parameter->src_mask,
					parameter->dst_mask,
					parameter->src_port,
					parameter->dst_port,
					parameter->upperspec,
					parameter->direction,
					parameter->action
					);
			break;
		
		case SETKEY_SPDFLUSH:
			printf("SETKEY_SPDFLUSH function called\n");
			result = setkey_spdflush();
			break;

		case SETKEY_SPDDUMP:
			printf("SETKEY_SPDDUMP function called\n");
			result = setkey_spddump();
			break;

		default:
			printf("No function for parsing\n");
			return -1;
			break;
	}

	return result;
}
