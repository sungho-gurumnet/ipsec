#ifndef __ESP_H__
#define __ESP_H__

#include <util/types.h>

#define ESP_HEADER_LEN 	16
#define ESP_TRAILER_LEN	2
#define ICV_LEN			12

typedef struct {
	uint32_t	spi;
	uint32_t	seq_num;
	uint64_t 	iv;

	uint8_t		body[0];
} __attribute__ ((packed)) ESP;

typedef struct {
	uint8_t		pad_len;
	uint8_t		next_hdr;
}__attribute__ ((packed)) ESP_T;

#endif 
