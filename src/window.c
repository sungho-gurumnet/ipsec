#include <lock.h>

#include "window.h"

int checkWindow(Window* window, uint32_t seq) {
	uint32_t diff;

	if(seq == 0) 
		return -1; /* first == 0 or wrapped */

	if(seq > window->lastSeq) { /* new larger sequence number */
		diff = seq - window->lastSeq;
		if(diff < ReplayWindowSize) { /* In window */
			window->bitmap <<= diff;
			window->bitmap |= 1; /* set bit for this packet */
		} else 
			window->bitmap = 1; /* This packet has a "way larger" */
		window->lastSeq = seq;

		return 0; /* larger is good */
	}

	diff = window->lastSeq - seq;

	if(diff >= ReplayWindowSize) 
		return -1; /* too old or wrapped */

	if(window->bitmap & ((uint32_t)1 << diff)) 
		return -1; /* already seen */

	window->bitmap |= ((uint32_t)1 << diff); /* mark as seen */
		return 0; /* out of order but good */
}

uint8_t window_get_seq_counter(Window* window) {
	uint8_t seq_counter;
	lock_lock(&window->seq_counter_lock);
	seq_counter = ++window->seq_counter;
	lock_unlock(&window->seq_counter_lock);

	return seq_counter;
}
