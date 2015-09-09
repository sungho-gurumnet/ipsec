#ifndef __AH_H__
#define __AH_H__

#include <util/types.h>

#define AUTH_DATA_LEN	12
#define AH_HEADER_LEN 	(12 + AUTH_DATA_LEN)
#define AH_LEN		((AH_HEADER_LEN / 4) - 2)

typedef struct _AH{
	uint8_t		next_hdr;
	uint8_t		len;
	uint16_t 	reserved;
	uint32_t 	spi;
	uint32_t 	seq_num;

	uint8_t		auth_data[AUTH_DATA_LEN];
	uint8_t		body[0];
} __attribute__ ((packed)) AH;

#endif 
