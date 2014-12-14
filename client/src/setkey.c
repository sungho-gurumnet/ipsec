#include "setkey.h"

// TODO : Extensions addition, Duplciation check
void setkey_add(uint32_t src_ip, uint32_t dst_ip, uint8_t protocol, uint32_t spi, uint8_t extensions, uint8_t crypto_algorithm, uint8_t auth_algorithm, uint64_t crypto_key[], uint64_t auth_key[])
{
	parameter.name = SETKEY_ADD;	
	parameter.src_ip = src_ip;
	parameter.dst_ip = dst_ip;
	parameter.protocol = protocol;
    parameter.spi = spi;
	parameter.extensions = extensions;
	parameter.crypto_algorithm = crypto_algorithm;
	parameter.auth_algorithm = auth_algorithm;
	parameter.crypto_key[0] = crypto_key[0];
	parameter.crypto_key[1] = crypto_key[1];
	parameter.crypto_key[2] = crypto_key[2];
	if(auth_algorithm != 0)
	{
		parameter.auth_key[0] = auth_key[0];
		parameter.auth_key[1] = auth_key[1];
		parameter.auth_key[2] = auth_key[2];
		parameter.auth_key[3] = auth_key[3];
		parameter.auth_key[4] = auth_key[4];
		parameter.auth_key[5] = auth_key[5];
		parameter.auth_key[6] = auth_key[6];
		parameter.auth_key[7] = auth_key[7];
	}

	if(setkey_send() < 0)
		printf("Setkey_send() error\n");
}

void setkey_get(uint32_t src_ip, uint32_t dst_ip, uint8_t protocol, uint32_t spi)
{
	parameter.name = SETKEY_GET;	
	parameter.src_ip = src_ip;
	parameter.dst_ip = dst_ip;
	parameter.protocol = protocol;
	parameter.spi = spi;

	if(setkey_send() < 0)
		printf("Setkey_send() error\n");
}

void setkey_delete(uint32_t src_ip, uint32_t dst_ip, uint8_t protocol, uint32_t spi)
{
	parameter.name = SETKEY_DELETE;	
	parameter.src_ip = src_ip;
	parameter.dst_ip = dst_ip;
	parameter.protocol = protocol;
	parameter.spi = spi;

	if(setkey_send() < 0)
		printf("Setkey_send() error\n");
}

void setkey_deleteall(uint32_t src_ip, uint32_t dst_ip, uint8_t protocol)
{
	parameter.name = SETKEY_DELETEALL;	
	parameter.src_ip = src_ip;
	parameter.dst_ip = dst_ip;
	parameter.protocol = protocol;

	if(setkey_send() < 0)
		printf("Setkey_send() error\n");
}

void setkey_flush(uint8_t protocol)
{
	parameter.name = SETKEY_FLUSH;
	parameter.protocol = protocol;

	if(setkey_send() < 0)
		printf("Setkey_send() error\n");
}

void setkey_dump(uint8_t protocol)
{
	parameter.name = SETKEY_DUMP;
	parameter.protocol = protocol;

	if(setkey_send() < 0)
		printf("Setkey_send() error\n");
}

// TODO : Duplication check
void setkey_spdadd(uint32_t src_ip, uint32_t dst_ip, uint32_t src_mask, uint32_t dst_mask, uint16_t src_port, uint16_t dst_port, uint8_t upperspec, uint8_t direction, uint8_t action, uint8_t protocol, uint8_t mode, uint32_t t_src_ip, uint32_t t_dst_ip, uint8_t level)
{
	parameter.name = SETKEY_SPDADD;	
	parameter.src_ip = src_ip;
	parameter.dst_ip = dst_ip;
	parameter.src_mask = src_mask;
	parameter.dst_mask = dst_mask;
	parameter.src_port = src_port;
	parameter.dst_port = dst_port;
	parameter.upperspec = upperspec;
	parameter.direction = direction;
	parameter.action = action;
	parameter.protocol = protocol;
	parameter.mode = mode;
	parameter.t_src_ip = t_src_ip;
	parameter.t_dst_ip = t_dst_ip;
	parameter.level = level;

	if(setkey_send() < 0)
		printf("Setkey_send() error\n");
}

void setkey_spdupdate(uint32_t src_ip, uint32_t dst_ip, uint32_t src_mask, uint32_t dst_mask, uint16_t src_port, uint16_t dst_port, uint8_t upperspec, uint8_t direction, uint8_t action)
{
	parameter.name = SETKEY_SPDUPDATE;	
	parameter.src_ip = src_ip;
	parameter.dst_ip = dst_ip;
	parameter.src_mask = src_mask;
	parameter.dst_mask = dst_mask;
	parameter.src_port = src_port;
	parameter.dst_port = dst_port;
	parameter.upperspec = upperspec;
	parameter.direction = direction;
	parameter.action = action;

	if(setkey_send() < 0)
		printf("Setkey_send() error\n");
	// Range ?
}

void setkey_spddelete(uint32_t src_ip, uint32_t dst_ip, uint32_t src_mask, uint32_t dst_mask, uint16_t src_port, uint16_t dst_port, uint8_t upperspec, uint8_t direction, uint8_t action)
{
	parameter.name = SETKEY_SPDDELETE;	
	parameter.src_ip = src_ip;
	parameter.dst_ip = dst_ip;
	parameter.src_mask = src_mask;
	parameter.dst_mask = dst_mask;
	parameter.src_port = src_port;
	parameter.dst_port = dst_port;
	parameter.upperspec = upperspec;
	parameter.direction = direction;
	parameter.action = action;

	if(setkey_send() < 0)
		printf("Setkey_send() error\n");
	// Range ?
}

void setkey_spdflush()
{
	parameter.name = SETKEY_SPDFLUSH;

	if(setkey_send() < 0)
		printf("Setkey_send() error\n");
}

void setkey_spddump()
{
	parameter.name = SETKEY_SPDDUMP;

	if(setkey_send() < 0)
		printf("Setkey_send() error\n");
}

