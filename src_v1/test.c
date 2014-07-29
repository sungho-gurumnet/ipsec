#include <stdio.h>
#include <stdlib.h>
typedef unsigned long u_long;
enum {
	ReplayWindowSize = 32
};
u_long bitmap = 0; /* session state - must be 32 bits */
u_long lastSeq = 0; /* session state */
/* Returns 0 if packet disallowed, 1 if packet permitted */
int ChkReplayWindow(u_long seq);
int ChkReplayWindow(u_long seq) {
	u_long diff;
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
	if (bitmap & ((u_long)1 << diff)) return 0; /* already seen */
	bitmap |= ((u_long)1 << diff); /* mark as seen */
	return 1; /* out of order but good */
}
char string_buffer[512];

#define STRING_BUFFER_SIZE sizeof(string_buffer)
int main() {
	int result;
	u_long last, current, bits;
	printf("Input initial state (bits in hex, last msgnum):\n");
	if (!fgets(string_buffer, STRING_BUFFER_SIZE, stdin)) exit(0);
	sscanf(string_buffer, "%lx %lu", &bits, &last);
	if (last != 0)
		bits |= 1;
	bitmap = bits;
	lastSeq = last;
	printf("bits:%08lx last:%lu\n", bitmap, lastSeq);
	printf("Input value to test (current):\n");
	while (1) {
		if (!fgets(string_buffer, STRING_BUFFER_SIZE, stdin)) break;
		sscanf(string_buffer, "%lu", &current);
		result = ChkReplayWindow(current);
		printf("%-3s", result ? "OK" : "BAD");
		printf(" bits:%08lx last:%lu\n", bitmap, lastSeq);
	}
	return 0;
}
