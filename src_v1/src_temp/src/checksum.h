#ifndef __NET_CHECKSUM_H__
#define __NET_CHECKSUM_H__

#include <stdint.h>

uint16_t checksum(void* data, uint32_t size);

#endif /* __NET_CHECKSUM_H__ */
