#include <stdio.h>
#include <stdbool.h>
#include <thread.h>
#include <readline.h>
#include <net/ni.h>
#include <net/packet.h>
#include <net/ether.h>
#include <net/arp.h>
#include <net/ip.h>
#include <net/icmp.h>
#include <net/checksum.h>
#include <net/udp.h>
#include <net/tcp.h>

#include <util/cmd.h>
#include <util/types.h>

#include "sp.h"

#include "crypto.h"
#include "auth.h"
#include "sad.h"
#include "spd.h"

#include "ipsec.h"

static bool is_continue;

bool ginit(int argc, char** argv) {
	if(!ipsec_init()) {
		return -1;
	}
	return true;
}

void init(int argc, char** argv) {
	is_continue  = true;

	cmd_init();
}

void destroy() {
}

void gdestroy() {
}

static uint32_t str_to_addr(char* argv) {
	char* str = argv;
	uint32_t address = (strtol(str, &str, 0) & 0xff) << 24; str++;
	address |= (strtol(str, &str, 0) & 0xff) << 16; str++;
	address |= (strtol(str, &str, 0) & 0xff) << 8; str++;
	address |= strtol(str, NULL, 0) & 0xff;

	return address;
}

static bool parse_key(char* argv, uint64_t** key) {
	if(strncmp("0x", argv, 2)) {
		return false;
	}

	ssize_t length = strlen(argv) - 2;
	*key = malloc(length);

	return true;
}

static NetworkInterface* parse_ni(char* argv) {
	if(!strncmp(argv, "eth", 3))
		return NULL;

	char* next;
	uint16_t index = strtol(argv + 3, &next, 0);
	if(next == argv + 3)
		return NULL;

	if(*next != '\0' && *next != '@')
		return NULL;

	if(index >= ni_count())
		return NULL;

	return ni_get(index);
}

static bool parse_addr_mask_port(char* argv, uint32_t* addr, uint32_t* mask, uint16_t* port) {
	*addr = 0;
	*mask = 0xffffffff;
	*port = 0;

	char* next = argv;
	*addr = (strtol(next, &next, 0) & 0xff) << 24; next++;
	*addr |= (strtol(next, &next, 0) & 0xff) << 16; next++;
	*addr |= (strtol(next, &next, 0) & 0xff) << 8; next++;
	*addr |= strtol(next, &next, 0) & 0xff;
	if(*next == '/') {
		next++;
		uint8_t _mask = strtol(next, &next, 0);
		if(_mask > 32)
			return false;

		*mask = *mask << (32 - _mask);
	}
	if(*next == ':') {
		next++;
		*port = strtol(next, &next, 0);
	}

	if(*next != '\0') {
		return false;
	}

	return true;
}

static int cmd_ip(int argc, char** argv, void(*callback)(char* result, int exit_status)) {
	if(argc == 1) {
		//dump
	}

	if(!strcmp("add", argv[1])) {
		NetworkInterface* ni = parse_ni(argv[2]);
		if(!ni) {
			printf("Netowrk Interface number wrong\n");
			return -2;
		}

		uint32_t addr = str_to_addr(argv[3]);
		if(!ni_ip_add(ni, addr))
			return -3;
	} else if(!strcmp("remove", argv[1])) {
		NetworkInterface* ni = parse_ni(argv[2]);
		if(!ni) {
			printf("Netowrk Interface number wrong\n");
			return -2;
		}

		uint32_t addr = str_to_addr(argv[3]);
		if(!ni_ip_remove(ni, addr)) {
			printf("Can'nt found address\n");
			return -3;
		}

	} else
		return -1;

	return 0;
}
	
static int cmd_sa(int argc, char** argv, void(*callback)(char* result, int exit_status)) {
	for(int i = 1; i < argc; i++) {
		if(!strcmp(argv[i], "add")) {
			i++;
			NetworkInterface* ni = parse_ni(argv[i]);
			if(!ni) {
				printf("Can'nt found Network Interface\n");
			}

			uint8_t ipsec_protocol = IP_PROTOCOL_ESP;
			uint32_t protocol = IP_PROTOCOL_ANY;
			uint32_t src_ip = 0;
			uint32_t src_mask = 0xffffffff;
			uint16_t src_port = 0;
			uint32_t dest_ip = 0;
			uint32_t dest_mask = 0xffffffff;
			uint16_t dest_port = 0;
			uint32_t spi = 0;
			//uint8_t extensions = 0;
			uint8_t crypto_algorithm = 0;
			uint8_t auth_algorithm = 0;
			uint64_t* crypto_key;
			uint64_t* auth_key;

			for(; i < argc; i++) {
				if(!strcmp(argv[i], "-p")) {
					i++;
					if(!strcmp(argv[i], "esp")) {
						protocol = IP_PROTOCOL_ESP;
					} else if(!strcmp(argv[i], "ah")) {
						protocol = IP_PROTOCOL_AH;
					} else {
						printf("Invalid protocol\n");
						return i;
					}
				} else if(!strcmp(argv[i], "-s")) {
					i++;
					if(!parse_addr_mask_port(argv[i], &src_ip, &src_mask, &src_port)) {
						printf("Wrong source parameter\n");
						return false;
					}
				} else if(!strcmp(argv[i], "-d")) {
					i++;
					if(!parse_addr_mask_port(argv[i], &dest_ip, &dest_mask, &dest_port)) {
						printf("Wrong destination parameter\n");
						return false;
					}
				} else if(!strcmp(argv[i], "-E")) {
					i++;

					if(!strcmp(argv[i], "des_cbc")) {
						crypto_algorithm = CRYPTO_DES_CBC;
					} else if(!strcmp(argv[i], "3des_cbc")) {
						crypto_algorithm = CRYPTO_3DES_CBC;
					} else if(!strcmp(argv[i], "blowfish_cbc")) {
						crypto_algorithm = CRYPTO_BLOWFISH_CBC;
					} else if(!strcmp(argv[i], "cast128_cbc")) {
						crypto_algorithm = CRYPTO_CAST128_CBC;
					} else if(!strcmp(argv[i], "rijndael_cbc")) {
						crypto_algorithm = CRYPTO_RIJNDAEL_CBC;
					} else if(!strcmp(argv[i], "aes_ctr")) {
						crypto_algorithm = CRYPTO_AES_CTR;
					} else if(!strcmp(argv[i], "camellia_cbc")) {
						crypto_algorithm = CRYPTO_CAMELLIA_CBC;
					} else if(!strcmp(argv[i], "twofish_cbc")) {
						//crypto_algorithm = CRYPTO_TWOFISH_CBC;
						printf("Not yet support\n");
						return -i;
					} else if(!strcmp(argv[i], "des_deriv")) {
						//crypto_algorithm = CRYPTO_DES_DERIV;
						printf("Not yet support\n");
						return -i;
					} else if(!strcmp(argv[i], "3des_deriv")) {
						//crypto_algorithm = CRYPTO_3DES_DERIV;
						printf("Not yet support\n");
						return -i;
					} else {
						printf("Invalid crypto algorithm");
						return i;
					}

					i++;
					if(!parse_key(argv[i], &crypto_key)) {
						printf("Wrong key\n");
						return i;
					}

					i++;
					if(!is_uint32(argv[i])) {
						printf("Wrong spi\n");
						return i;
					}
					spi = parse_uint32(argv[i]);
				} else if(!strcmp(argv[i], "-A")) {
					i++;

					if(!strcmp(argv[i], "hmac_md5")) {
						auth_algorithm = AUTH_HMAC_MD5;
					} else if(!strcmp(argv[i], "hmac_sha1")) {
						auth_algorithm = AUTH_HMAC_SHA1;
					} else if(!strcmp(argv[i], "hmac_sha256")) {
						auth_algorithm = AUTH_HMAC_SHA256;
					} else if(!strcmp(argv[i], "hmac_sha384")) {
						auth_algorithm = AUTH_HMAC_SHA384;
					} else if(!strcmp(argv[i], "hmac_sha512")) {
						auth_algorithm = AUTH_HMAC_SHA512;
					} else if(!strcmp(argv[i], "hmac_ripemd160")) {
						auth_algorithm = AUTH_HMAC_RIPEMD160;
					} else if(!strcmp(argv[i], "keyed_md5")) {
						//auth_algorithm = AUTH_KEYED_MD5;
						printf("Not yet support\n");
						return -i;
					} else if(!strcmp(argv[i], "keyed_sha1")) {
						//auth_algorithm = AUTH_KEYED_SHA1;
						printf("Not yet support\n");
						return -i;
					} else if(!strcmp(argv[i], "aes_xcbc_mac")) {
						//auth_algorithm = AUTH_AES_XCBC_MAC;
						printf("Not yet support\n");
						return -i;
					} else if(!strcmp(argv[i], "tcp_md5")) {
						//auth_algorithm = AUTH_TCP_MD5;
						printf("Not yet support\n");
						return -i;
					} else {
						printf("Invalid auth algorithm");
						return i;
					}

					i++;
					if(!parse_key(argv[i], &auth_key)) {
						printf("Wrong key\n");
						return i;
					}

					i++;
					if(!is_uint32(argv[i])) {
						printf("Wrong spi\n");
						return i;
					}
					spi = parse_uint32(argv[i]);
				} else {
					printf("Invalid Value\n");
					return i;
				}
			}

			
			uint64_t attrs[] = {
				SA_IPSEC_PROTOCOL, ipsec_protocol,
				SA_PROTOCOL, protocol,
				SA_SPI, spi,
				SA_SOURCE_IP, src_ip,
				SA_SOURCE_MASK, src_mask,
				SA_DESTINATION_IP, dest_ip,
				SA_DESTINATION_MASK, dest_mask,
				SA_SOURCE_PORT, src_port,
				SA_DESTINATION_PORT, dest_port,

				SA_CRYPTO_ALGORITHM, crypto_algorithm,
				SA_CRYPTO_KEY, (uint64_t)crypto_key,
				//SA_IV_SUPPORT, iv,
				SA_AUTH_ALGORITHM, auth_algorithm,
				SA_AUTH_KEY, (uint64_t)auth_key,

				//SA_REPLY,
				SA_NONE,
			};

			SA* sa = sa_alloc(ni, attrs);
			if(sa == NULL) {
				printf("can't create SA\n");
				return -1;
			}

 //			if(sad_add_sa(ni, sa)) {
 //				SP* sp = spd_get_index(ni, 0);
 //				sp_sa_add(sp, sa, OUT);
 //				return 0;
 //			} else {
 //				printf("can't add to SAD\n");
 //				return -1;
 //			}

			return 0;
		} else if(!strcmp(argv[i], "remove")) {
 //			i++;
 //
 //			uint32_t dest_ip = 0;
 //			uint8_t protocol = 0;
 //			uint32_t spi = 0;
 //
 //			for(; i < argc; i++) {
 //				if(!strcmp(argv[i], "dest_ip:")) {
 //					i++;
 //					if(!is_uint32(argv[i])) {
 //						printf("dest_ip is must be uint32\n");
 //						return i;
 //					}
 //
 //					dest_ip = parse_uint32(argv[i]);
 //				} else if(!strcmp(argv[i], "protocol:")) {
 //					i++;
 //					if(!is_uint8(argv[i])) {
 //						printf("protocol is must be uint32\n");
 //						return i;
 //					}
 //
 //					protocol = parse_uint8(argv[i]);
 //				} else if(!strcmp(argv[i], "spi:")) {
 //					i++;
 //					if(!is_uint32(argv[i])) {
 //						printf("spi is must be uint32\n");
 //						return i;
 //					}
 //
 //					spi = parse_uint32(argv[i]);
 //				} else {
 //					printf("Invalid Value\n");
 //					return i;
 //				}
 //			}
 //
 //			SA* sa = sad_sa_get(spi, dest_ip, protocol);
 //			if(sa == NULL)
 //				return -1;
 //
 //			sad_sa_remove(sa);
 //
			return 0;
		} else if(!strcmp(argv[i], "list")) {
			i++;
			NetworkInterface* ni = parse_ni(argv[i]);
			if(!ni) {
				printf("Can'nt found Network Interface\n");
			}

			Map* sad = sad_get(ni);
			MapIterator iter;
			map_iterator_init(&iter, sad);
			int index = 0;
			printf("Index\tSA");
			while(map_iterator_has_next(&iter)) {
				MapEntry* entry = map_iterator_next(&iter);
				SA* sa = entry->data;
				printf("%d\t%p\n", index++, sa);
			}
			return 0;
		} else {
			printf("Invalid Command\n");
			return -i;
		}
	}
	
	return 0;
}

static int cmd_sp(int argc, char** argv, void(*callback)(char* result, int exit_status)) {
	for(int i = 1; i < argc; i++) {
		if(!strcmp(argv[1], "add")) {
			i++;
			NetworkInterface* ni = parse_ni(argv[i]);
			if(!ni) {
				printf("Can'nt found Network Interface\n");
			}

			uint8_t protocol = IP_PROTOCOL_ANY;
			bool is_protocol_sa_share = true;
			uint32_t src_ip = 0;
			bool is_src_ip_sa_share = true;
			uint32_t src_mask = 0xffffffff;
			uint32_t dest_ip = 0;
			bool is_dest_ip_sa_share = true;
			uint32_t dest_mask = 0xffffffff;
			uint16_t src_port = 0;
			bool is_src_port_sa_share = true;
			uint16_t dest_port = 0;
			bool is_dest_port_sa_share = true;

			uint8_t direction = DIRECTION_IN;
			uint8_t action = ACTION_BYPASS;
			uint8_t index = 0;

			i++;
			for(; i < argc; i++) {
				if(!strcmp(argv[i], "-p")) { //protocol
					i++;
					if(!strcmp(argv[i], "any")) {
						protocol = IP_PROTOCOL_ANY;
					} else if(!strcmp(argv[i], "tcp")) {
						protocol = IP_PROTOCOL_TCP;
					} else if(!strcmp(argv[i], "udp")) {
						protocol = IP_PROTOCOL_UDP;
					} else {
						printf("Wrong protocol parameter\n");
						return i;
					}
				} else if(!strcmp(argv[i], "-s")) {
					i++;
					if(!parse_addr_mask_port(argv[i], &src_ip, &src_mask, &src_port)) {
						printf("Wrong source parameter\n");
						return false;
					}
				} else if(!strcmp(argv[i], "-d")) {
					i++;
					if(!parse_addr_mask_port(argv[i], &dest_ip, &dest_mask, &dest_port)) {
						printf("Wrong destination parameter\n");
						return false;
					}
				} else if(!strcmp(argv[i], "-a")) {
					i++;
					if(!strcmp(argv[i], "ipsec")) {
						action = ACTION_IPSEC;
					} else if(!strcmp(argv[i], "bypass")) {
						action = ACTION_BYPASS;
					} else {
						printf("Invalid action\n");
						return i;
					}
					i++;

					if(!strcmp(argv[i], "in")) {
						direction = DIRECTION_IN;
					} else if(!strcmp(argv[i], "out")) {
						direction = DIRECTION_OUT;
					} else {
						printf("Invalid direction\n");
						return i;
					}
				} else if(!strcmp(argv[i], "-i")) {
					i++;
					if(!is_uint8(argv[i])) {
						printf("index is must be uint8\n");
						return i;
					}

					index = parse_uint8(argv[i]);
				} else if(!strcmp(argv[i], "-o")) {
				} else {
					printf("Invalid Value\n");
					return i;
				}
			}

			uint64_t attrs[] = {
				SP_PROTOCOL, protocol,
				SP_IS_PROTOCOL_SA_SHARE, is_protocol_sa_share,

				SP_SOURCE_IP, src_ip,
				SP_IS_SOURCE_IP_SA_SHARE, is_src_ip_sa_share,
				SP_SOURCE_NET_MASK, src_mask,
				SP_SOURCE_PORT, src_port,
				SP_IS_SOURCE_PORT_SA_SHARE, is_src_port_sa_share,

				SP_OUT_NI, 
				SP_DESTINATION_IP, dest_ip,
				SP_IS_DESTINATION_IP_SA_SHARE, is_dest_ip_sa_share,
				SP_DESTINATION_NET_MASK, dest_mask,
				SP_DESTINATION_PORT, dest_port,
				SP_IS_DESTINATION_PORT_SHARE, is_dest_port_sa_share,

				SP_ACTION, action,
				SP_DIRECTION, direction,

				SP_NONE,
			};

			SP* sp = sp_alloc(ni, attrs);
			if(sp == NULL)
				return -1;

			if(!spd_add_sp(ni, sp, index)) {
				printf("Can'nt add sp\n");
				sp_free(sp);
				return -1;
			}

			return 0;
		} else if(!strcmp(argv[1], "remove")) {
 //			i++;
 //			NetworkInterface* ni = parse_ni(argv[i]);
 //			if(!ni) {
 //				printf("Netowrk Interface number wrong\n");
 //				return -2;
 //			}
 //
 //			i++;
 //			for(; i < argc; i++) {
 //				if(!strcmp(argv[i], "index:")) {
 //					i++;
 //					if(!is_uint8(argv[i])) {
 //						printf("index is must be uint8\n");
 //						return i;
 //					}
 //
 //					index = parse_uint32(argv[i]);
 //				} else {
 //					printf("Invalid Value\n");
 //					return i;
 //				}
 //			}
 //
 //			if(!spd_sp_delete(index))
 //				return -1;
 //
			return 0;
		} else if(!strcmp(argv[1], "list")) {
			i++;
			NetworkInterface* ni = parse_ni(argv[i]);
			if(!ni) {
				printf("Netowrk Interface number wrong\n");
				return -2;
			}

			List* spd = spd_get(ni);
			if(!spd) {
				printf("SPD not exist\n");
				return i;
			}

			printf("Index\tProtocol\tSource\tDestination\t");
			int index = 0;
			ListIterator iter;
			list_iterator_init(&iter, spd);
			while(list_iterator_has_next(&iter)) {
				SP* sp = list_iterator_next(&iter);
				void protocol_dump(uint8_t protocol) {
					switch(protocol) {
						case IP_PROTOCOL_ANY:
							printf("any");
							break;
						case IP_PROTOCOL_ICMP:
							printf("icmp");
							break;
						case IP_PROTOCOL_IP:
							printf("ip");
							break;
						case IP_PROTOCOL_TCP:
							printf("tcp");
							break;
						case IP_PROTOCOL_UDP:
							printf("udp");
							break;
					}
				}
				printf("%d\t", index++);
				protocol_dump(sp->protocol);
				printf("\t");
				printf("%x/%x:%d", sp->src_ip, sp->src_mask, sp->src_port);
				printf("%x/%x:%d", sp->dest_ip, sp->dest_mask, sp->dest_port);
				printf("\n");
			}
			return 0;
		} else {
			printf("Invalid Command\n");
			return -1;
		}
	}
	return 0;
}

static int cmd_content(int argc, char** argv, void(*callback)(char* result, int exit_status)) {
	for(int i = 1; i < argc; i++) {
		if(!strcmp(argv[i], "add")) {
			i++;
			NetworkInterface* ni = parse_ni(argv[i]);
			if(!ni) {
				printf("Can'nt found Network Interface\n");
			}
			i++;
			uint8_t sp_index = parse_uint8(argv[i]);
			
			SP* sp = spd_get_sp_index(ni, sp_index);
			if(!sp) {
				printf("Can'nt found Security Policy\n");
				return i;
			}
			i++;
			uint8_t protocol = 0;
			uint8_t mode = 0;
			uint32_t src_ip = 0;
			uint32_t dest_ip = 0;
			uint8_t crypto_algorithm = 0;
			uint8_t auth_algorithm = 0;
			uint8_t priority = 0;
			
			for(; i < argc; i++) {
				if(!strcmp(argv[i], "-p")) {
					i++;

					if(!strcmp(argv[i], "esp")) {
						protocol = IP_PROTOCOL_ESP;
					} else if(!strcmp(argv[i], "ah")) {
						protocol = IP_PROTOCOL_AH;
					} else {
						printf("Invalid protocol\n");
						return i;
					}
				} else if(!strcmp(argv[i], "-m")) {
					i++;

					if(!strcmp(argv[i], "transport")) {
						mode = CONTENT_MODE_TRANSPORT;

					} else if(!strcmp(argv[i], "tunnel")) {
						mode = CONTENT_MODE_TUNNEL;
						i++;

						char* next = argv[i];
						src_ip = (strtol(next, &next, 0) & 0xff) << 24; next++;
						src_ip |= (strtol(next, &next, 0) & 0xff) << 16; next++;
						src_ip |= (strtol(next, &next, 0) & 0xff) << 8; next++;
						src_ip |= strtol(next, &next, 0) & 0xff;

						if(*next != '-') {
							printf("Wrong parameter\n");
							return i;
						}
						next++;
						dest_ip = (strtol(next, &next, 0) & 0xff) << 24; next++;
						dest_ip |= (strtol(next, &next, 0) & 0xff) << 16; next++;
						dest_ip |= (strtol(next, &next, 0) & 0xff) << 8; next++;
						dest_ip |= strtol(next, &next, 0) & 0xff;
					} else {
						printf("Invalid mode\n");
						return i;
					}
				} else if(!strcmp(argv[i], "crypto:")) {
					i++;

					for(; i < argc; i++) {
						if(!strcmp(argv[i], "algorithm:")) {
							i++;
							if(!strcmp(argv[i], "DES_CBC")) {
								crypto_algorithm = CRYPTO_DES_CBC;
							} else if(!strcmp(argv[i], "3DES_CBC")) {
								crypto_algorithm = CRYPTO_3DES_CBC;
							} else if(!strcmp(argv[i], "BLOWFISH_CBC")) {
								crypto_algorithm = CRYPTO_BLOWFISH_CBC;
							} else if(!strcmp(argv[i], "CAST128_CBC")) {
								crypto_algorithm = CRYPTO_CAST128_CBC;
							} else if(!strcmp(argv[i], "DES_DERIV")) {
								crypto_algorithm = CRYPTO_DES_DERIV;
							} else if(!strcmp(argv[i], "3DES_DERIV")) {
								crypto_algorithm = CRYPTO_3DES_DERIV;
							} else if(!strcmp(argv[i], "RIJNDAEL_CBC")) {
								crypto_algorithm = CRYPTO_RIJNDAEL_CBC;
							} else if(!strcmp(argv[i], "TWOFISH_CBC")) {
								crypto_algorithm = CRYPTO_TWOFISH_CBC;
							} else if(!strcmp(argv[i], "AES_CTR")) {
								crypto_algorithm = CRYPTO_AES_CTR;
							} else if(!strcmp(argv[i], "CAMELLIA_CBC")) {
								crypto_algorithm = CRYPTO_CAMELLIA_CBC;
							} else {
								printf("Invalid crypto algorithm");
								return i;
							}
						} else {
							i--;
							break;
						}
					}
				} else if(!strcmp(argv[i], "auth:")) {
					i++;

					for(; i < argc; i++) {
						if(!strcmp(argv[i], "algorithm:")) {
							i++;
							if(!strcmp(argv[i], "HMAC_MD5")) {
								auth_algorithm = AUTH_HMAC_MD5;
							} else if(!strcmp(argv[i], "HMAC_SHA1")) {
								auth_algorithm = AUTH_HMAC_SHA1;
							} else if(!strcmp(argv[i], "KEYED_MD5")) {
								auth_algorithm = AUTH_KEYED_MD5;
							} else if(!strcmp(argv[i], "KEYED_SHA1")) {
								auth_algorithm = AUTH_KEYED_SHA1;
							} else if(!strcmp(argv[i], "HMAC_SHA256")) {
								auth_algorithm = AUTH_HMAC_SHA256;
							} else if(!strcmp(argv[i], "HMAC_SHA384")) {
								auth_algorithm = AUTH_HMAC_SHA384;
							} else if(!strcmp(argv[i], "HMAC_SHA512")) {
								auth_algorithm = AUTH_HMAC_SHA512;
							} else if(!strcmp(argv[i], "HMAC_SHA384")) {
								auth_algorithm = AUTH_HMAC_SHA384;
							} else if(!strcmp(argv[i], "AES_XCBC_MAC")) {
								auth_algorithm = AUTH_AES_XCBC_MAC;
							} else if(!strcmp(argv[i], "TCP_MD5")) {
								auth_algorithm = AUTH_TCP_MD5;
							} else {
								printf("Invalid auth algorithm");
								return i;
							}
						} else {
							i--;
							break;
						}
					}
				} else if(!strcmp(argv[i], "priority:")) {
					i++;

					if(!is_uint8(argv[i])) {
						printf("priority must be uint8_t\n");
						return i;
					}

					priority = parse_uint8(argv[i]);
				} else {
					printf("%s: ", argv[i]);
					printf("Invalid Value\n");
					return i;
				}
			}

			uint64_t attrs[] = {
				CONTENT_PROTOCOL, protocol,
				CONTENT_MODE, mode,
				CONTENT_TUNNEL_SOURCE_ADDR, src_ip,
				CONTENT_TUNNEL_DESTINATION_ADDR, dest_ip,
				CONTENT_CRYPTO_ALGORITHM, crypto_algorithm,
				CONTENT_AUTH_ALGORITHM, auth_algorithm,
				NONE,
			};
			Content* content = content_alloc(ni, attrs);
			if(content == NULL) {
				printf("Can't Create Content\n");
				return -1;
			}

			if(!sp_add_content(sp, content, priority)) {
				printf("Can't add content to SP\n");
				return -1;
			}

			return 0;
			//get sp
		} else if(!strcmp(argv[i], "delete")) {
			return 0;
		} else {
			printf("Invalid Option %s\n", argv[i]);
			return -1;
		}
	}
	return 0;
}

static int cmd_start(int argc, char** argv, void(*callback)(char* result, int exit_status)) {
	return 0;
}

static int cmd_stop(int argc, char** argv, void(*callback)(char* result, int exit_status)) {
	return 0;
}

static int cmd_exit(int argc, char** argv, void(*callback)(char* result, int exit_status)) {
	return 0;
}


Command commands[] = {
	{
		.name = "help",
		.desc = "Show This Message",
		.func = cmd_help
	},
	{
		.name = "ip",
		.desc = "add or remove IP",
		.func = cmd_ip
	},
	{
		.name = "sa",
		.desc = "Manage IPSec Security Association Database\nadd get delete flush dump",
		.func = cmd_sa
	},
	{
		.name = "sp",
		.desc = "Manage IPSec Security Policy Database\nadd update delete flush dump",
		.func = cmd_sp
	},
	{
		.name = "content",
		.desc = "Manage IPSec Contents\nadd update delete flush dump",
		.func = cmd_content
	},
	{
		.name = "start",
		.desc = "Start IPSec Application",
		.func = cmd_start
	},
	{
		.name = "stop",
		.desc = "Stop IPSec Application",
		.func = cmd_stop
	},
	{
		.name = "exit",
		.desc = "Exit IPSec Application",
		.func = cmd_exit
	},
	{
		.name = NULL,
		.desc = NULL,
		.func = NULL
	}
};

int main(int argc, char** argv) {
	printf("Thread %d bootting\n", thread_id());
	if(thread_id() == 0) {
		ginit(argc, argv);
	}

	thread_barrior();

	init(argc, argv);

	thread_barrior();

	uint32_t count = ni_count();
	while(is_continue) {
		for(int i = 0; i < count; i++) {
			NetworkInterface* ni = ni_get(i);
			if(ni_has_input(ni)) {
				Packet* packet = ni_input(ni);
				if(!packet)
					continue;

				if(!ipsec_process(packet))
					ni_free(packet);
			}
		}

		char* line = readline();
		if(line != NULL) {
			cmd_exec(line, NULL);
		}
	}

	thread_barrior();

	destroy();

	thread_barrior();

	if(thread_id() == 0) {
		gdestroy(argc, argv);
	}

	return 0;
}
