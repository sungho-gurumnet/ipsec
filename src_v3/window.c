#include "window.h"

int checkWindow(Window* window, uint32_t seq) {
	uint32_t diff;
	if (seq == 0) return 0; /* first == 0 or wrapped */
	if (seq > window->lastSeq) { /* new larger sequence number */
		diff = seq - window->lastSeq;
		if (diff < ReplayWindowSize) { /* In window */
			window->bitmap <<= diff;
			window->bitmap |= 1; /* set bit for this packet */
		} else window->bitmap = 1; /* This packet has a "way larger" */
		window->lastSeq = seq;
		return 1; /* larger is good */
	}
	diff = window->lastSeq - seq;
	if (diff >= ReplayWindowSize) return 0; /* too old or wrapped */
	if (window->bitmap & ((uint32_t)1 << diff)) return 0; /* already seen */
	window->bitmap |= ((uint32_t)1 << diff); /* mark as seen */
	return 1; /* out of order but good */
}
