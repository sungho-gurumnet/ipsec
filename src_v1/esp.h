#ifndef __ESP_H__
#define __ESP_H__

typedef struct 
{
	uint32_t	SPI;
	uint32_t	seq_num;
	uint64_t 	IV;

	uint8_t		body[0];
} __attribute__ ((packed)) ESP;

#endif 
