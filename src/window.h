#ifndef __WINDOW_H__
#define __WINDOW_H__

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#define ReplayWindowSize 32

typedef struct {
	uint32_t bitmap;
	uint32_t lastSeq;
	uint8_t seq_counter;
	uint8_t seq_counter_of;
} Window;

int checkWindow(Window* window, uint32_t seq);
#endif /* __WINDOW_H__ */
