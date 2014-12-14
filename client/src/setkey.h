#ifndef __SETKEY_H__
#define __SETKEY_H__

#include <stdio.h>
#include <stdint.h>
#include "sender.h"

extern Parameter paramter;

void setkey_add(uint32_t src_ip, uint32_t dst_ip, uint8_t protocol, uint32_t spi, uint8_t extensions, uint8_t crypto_algorithm, uint8_t auth_algorithm, uint64_t crypto_key[], uint64_t auth_key[]);
void setkey_get(uint32_t src_ip, uint32_t dst_ip, uint8_t protocol, uint32_t spi);
void setkey_delete(uint32_t src_ip, uint32_t dst_ip, uint8_t protocol, uint32_t spi);
void setkey_deleteall(uint32_t src_ip, uint32_t dst_ip, uint8_t protocol);
void setkey_flush(uint8_t protocol);
void setkey_dump(uint8_t protocol);
void setkey_spdadd(uint32_t src_ip, uint32_t dst_ip, uint32_t src_mask, uint32_t dst_mask, uint16_t src_port, uint16_t dst_port, uint8_t upperspec, uint8_t direction, uint8_t action, uint8_t protocol, uint8_t mode, uint32_t t_src_ip, uint32_t t_dst_ip, uint8_t level);
void setkey_spdupdate(uint32_t src_ip, uint32_t dst_ip, uint32_t src_mask, uint32_t dst_mask, uint16_t src_port, uint16_t dst_port, uint8_t upperspec, uint8_t direction, uint8_t action);
void setkey_spddelete(uint32_t src_ip, uint32_t dst_ip, uint32_t src_mask, uint32_t dst_mask, uint16_t src_port, uint16_t dst_port, uint8_t upperspec, uint8_t direction, uint8_t action);
void setkey_spdflush();
void setkey_spddump();

#endif /* __SETKEY_H__ */
