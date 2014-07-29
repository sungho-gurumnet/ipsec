#ifndef __NET_MD5_H__
#define __NET_MD5_H__

#include <stdint.h>

void md5(uint8_t* message, uint32_t len, uint32_t* hash);
// Block size must 64 bytes aligned
void md5_blocks(void** blocks, uint32_t block_count, uint32_t block_size, uint64_t len, uint32_t* hash);

#endif /* __NET_MD5_H__ */
