#ifndef __AH_H__
#define __AH_H__

#define AH_HEADER_LEN 	12

typedef struct {
	uint8_t		next_hdr;
	uint8_t		len;
	uint16_t 	reserved;
	uint32_t 	spi;
	uint32_t 	seq_num;
	uint8_t		auth_data[12];

	uint8_t		payload[0];
} __attribute__ ((packed)) AH;

#endif 
