#ifndef __SETKEY_H__
#define __SETKEY_H__

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "spd.h"
#include "sad.h"

extern SPD spd;
extern SAD sad;

int setkey_add(uint32_t src_ip, uint32_t dst_ip, uint8_t protocol, uint32_t spi, uint8_t extensions, uint8_t crypto_algorithm, uint8_t auth_algorithm, uint64_t crypto_key[], uint64_t auth_key[]);
int setkey_get(uint32_t src_ip, uint32_t dst_ip, uint8_t protocol, uint32_t spi);
int setkey_delete(uint32_t src_ip, uint32_t dst_ip, uint8_t protocol, uint32_t spi);
int setkey_deleteall(uint32_t src_ip, uint32_t dst_ip, uint8_t protocol);
int setkey_flush(uint8_t protocol);
int setkey_dump(uint8_t protocol);
int setkey_spdadd(uint32_t src_ip, uint32_t dst_ip, uint32_t src_mask, uint32_t dst_mask, uint16_t src_port, uint16_t dst_port, uint8_t upperspec, uint8_t direction, uint8_t action, uint8_t protocol, uint8_t mode, uint32_t t_src_ip, uint32_t t_dst_ip, uint8_t level);
int setkey_spdupdate(uint32_t src_ip, uint32_t dst_ip, uint32_t src_mask, uint32_t dst_mask, uint16_t src_port, uint16_t dst_port, uint8_t upperspec, uint8_t direction, uint8_t action);
int setkey_spddelete(uint32_t src_ip, uint32_t dst_ip, uint32_t src_mask, uint32_t dst_mask, uint16_t src_port, uint16_t dst_port, uint8_t upperspec, uint8_t direction, uint8_t action);
int setkey_spdflush();
int setkey_spddump();

#endif /* __SETKEY_H__ */
