#ifndef __CLIENT_H__
#define __CLIENT_H__

#include <stdio.h>
#include <net/ip.h>
#include "setkey.h"

// CRYPTO_ALGORITHM
#define CRYPTO_DES_CBC			0x01
#define CRYPTO_3DES_CBC			0x02
#define CRYPTO_BLOWFISH_CBC		0x03
#define CRYPTO_CAST128_CBC		0x04
#define CRYPTO_DES_DERIV		0x05
#define CRYPTO_3DES_DERIV		0x06
#define CRYPTO_RIJNDAEL_CBC		0x07
#define CRYPTO_TWOFISH_CBC		0x08
#define CRYPTO_AES_CTR			0x09
#define CRYPTO_CAMELLIA_CBC		0x10

// AUTH_ALGORITHM
#define AUTH_HMAC_MD5			0x01
#define AUTH_HMAC_SHA1			0x02
#define AUTH_KEYED_MD5			0x03
#define AUTH_KEYED_SHA1			0x04
#define AUTH_HMAC_SHA256		0x05
#define AUTH_HMAC_SHA384		0x06
#define AUTH_HMAC_SHA512		0x07
#define AUTH_HMAC_RIPEMD160		0x08
#define AUTH_AES_XCBC_MAC		0x09
#define AUTH_TCP_MD5			0x10

// PROTOCOL 
#define IP_PROTOCOL_ICMP	0x01
#define IP_PROTOCOL_UDP		0x11
#define IP_PROTOCOL_TCP		0x06
#define IP_PROTOCOL_ESP 	0x32
#define IP_PROTOCOL_AH 		0x33
#define IP_PROTOCOL_COMP	0x6c

// Action
#define IPSEC 		0x01

// Mode
#define TRANSPORT 	0x01
#define TUNNEL 		0x02

// Upperspec
#define ICMP6		0x01
#define IP4			0x02
#define GRE			0x03
#define ANY			0x04

// Direction
#define IN			0x01
#define OUT			0x02

// Level
#define DEFAULT 	0x01	
#define USE			0x02
#define REQUIRE		0x03
#define UNIQUE 		0x04

#endif /* __CLIENT_H__ */
