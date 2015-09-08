#ifndef __WINDOW_H__
#define __WINDOW_H__

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#define ReplayWindowSize 32

typedef struct _Window {
	uint32_t bitmap;
	uint32_t lastSeq;
	uint32_t seq_counter;
	uint8_t volatile seq_counter_lock;
	uint8_t seq_counter_of;
} Window;

int checkWindow(Window* window, uint32_t seq);
uint8_t window_get_seq_counter(Window* window);
#endif /* __WINDOW_H__ */
