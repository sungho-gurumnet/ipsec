#include "s_window.h"

int checkSeq_num(SA* current_sa, unsigned long seq) 
{
	unsigned long diff;
    unsigned long lastSeq = current_sa->s_win.lastSeq;
	unsigned long bitmap = current_sa->s_win.bitmap;

	if (seq == 0) return 0; /* first == 0 or wrapped */
	if (seq > lastSeq) { /* new larger sequence number */
		diff = seq - lastSeq;
		if (diff < ReplayWindowSize) { /* In window */
			bitmap <<= diff;
			bitmap |= 1; /* set bit for this packet */
		} else bitmap = 1; /* This packet has a "way larger" */
		lastSeq = seq;
		return 1; /* larger is good */
	}
	diff = lastSeq - seq;
	if (diff >= ReplayWindowSize) return 0; /* too old or wrapped */
	if (bitmap & ((unsigned long)1 << diff)) return 0; /* already seen */
	bitmap |= ((unsigned long)1 << diff); /* mark as seen */
	return 1; /* out of order but good */
}

int initiateWindow(s_window s)
{
	s.bitmap = 0;
	s.lastSeq = 0;

	return 0;
}

void printWindow(s_window s)
{
	printf("bits:%08lx last:%lu\n", s.bitmap, s.lastSeq);
}
