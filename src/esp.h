#ifndef __ESP_H__
#define __ESP_H__

#define ESP_HEADER_LEN 	16
#define ESP_TRAILER_LEN	2
#define ICV_LEN			12

typedef struct 
{
	uint32_t	spi;
	uint32_t	seq_num;
	uint64_t 	iv;

	uint8_t		body[0];
} __attribute__ ((packed)) ESP;

#endif 
