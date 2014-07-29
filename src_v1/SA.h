#ifndef __SA_H__
#define __SA_H__

#include <stdint.h>

//Mode
#define TRANSPORT 	0x01
#define TUNNEL 		0x02

typedef struct
{
	uint8_t algorithm;
	uint64_t esp_key[3];
	uint64_t iv;
	uint64_t ah_key[2];
} ESP_algo;

typedef struct
{
	uint8_t alogrithm;
	uint64_t key[2];
} AH_algo;

typedef struct
{
	unsigned long bitmap;
	unsigned long lastSeq;
}s_window;

typedef struct
{
	uint32_t SPI;
	uint32_t source;
	uint32_t destination;
	uint8_t seq_counter;
	uint8_t seq_counter_of;
	uint8_t protocol;
	uint8_t mode;
	AH_algo* ah_algo;
	ESP_algo* esp_algo;
	uint8_t ttl;
	s_window s_win;
}__attribute__((packed)) SA;

int seq_validate(SA* current_sa, uint32_t seq_num);
#endif
