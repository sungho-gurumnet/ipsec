#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <malloc.h>
#define DONT_MAKE_WRAPPER
#include <_malloc.h>
#undef DONT_MAKE_WRAPPER
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

static bool parse_key(NetworkInterface* ni, char* argv, uint64_t** key, uint16_t key_length) {
	if(strncmp("0x", argv, 2)) {
		return false;
	}

	ssize_t length = strlen(argv) - 2;
	length /= 2;
	//check keylength
	if(length > key_length)
		return false;

	*key = __malloc(key_length, ni->pool);
	if(!(*key)) {
		printf("Can'nt allocate key\n");
		return false;
	}
	memset(*key, 0, key_length);

	uint8_t* _key = (uint8_t*)*key;

	char buf[5];
	strcpy(buf, "0x00");
	for(int  i = 0; i < length; i++) {
		memcpy(buf + 2, argv + strlen(argv) - (2 * (i + 1)), 2);
		uint8_t value = parse_uint8(buf);
		*_key = value;
		_key++;
	}

	if(!!((strlen(argv) - 2) % 2)) {
		strcpy(buf, "0x0");
		memcpy(buf + 2, argv + 2, 1);
		uint8_t value = parse_uint8(buf);
		*_key = value;
	}

	return true;
}

static NetworkInterface* parse_ni(char* argv) {
	if(strncmp(argv, "eth", 3)) {
		return NULL;
	}

	char* next;
	uint16_t index = strtol(argv + 3, &next, 0);
	if(next == argv + 3) {
		return NULL;
	}

	if(*next != '\0' && *next != '@') {
		return NULL;
	}

	if(index >= ni_count()) {
		return NULL;
	}

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

			uint8_t protocol = IP_PROTOCOL_ANY;
			uint32_t src_ip = 0;
			uint32_t src_mask = 0xffffffff;
			uint16_t src_port = 0;
			uint32_t dest_ip = 0;
			uint32_t dest_mask = 0xffffffff;
			uint16_t dest_port = 0;
			uint32_t spi = 0;

			uint8_t crypto_algorithm = 0;
			uint64_t* crypto_key = NULL;
			uint16_t crypto_key_length = 0;
			uint8_t auth_algorithm = 0;
			uint64_t* auth_key = NULL;
			uint16_t auth_key_length = 0;

			i++;
			for(; i < argc; i++) {
				if(!strcmp(argv[i], "-p")) {
					i++;
					if(!strcmp(argv[i], "tcp")) {
						protocol = IP_PROTOCOL_TCP;
					} else if(!strcmp(argv[i], "udp")) {
						protocol = IP_PROTOCOL_UDP;
					} else if(!strcmp(argv[i], "any")){
						protocol = IP_PROTOCOL_ANY;
					} else 
						return i;
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
						crypto_key_length = 8;	//8bytes;
						i++;
						if(!parse_key(ni, argv[i], &crypto_key, 8)) {
							printf("Wrong crypto key\n");
							return i;
						}
					} else if(!strcmp(argv[i], "3des_cbc")) {
						crypto_algorithm = CRYPTO_3DES_CBC;
						crypto_key_length = 24;
						i++;
						if(!parse_key(ni, argv[i], &crypto_key, 24)) {
							printf("Wrong crypto key\n");
							return i;
						}
					} else if(!strcmp(argv[i], "blowfish_cbc")) {
						/* blow fish key length 5~ 56 bytes */
						crypto_algorithm = CRYPTO_BLOWFISH_CBC;
						i++;
						if(strncmp("0x", argv[i], 2)) {
							printf("Wrong key length\n");
							return i;
						}

						crypto_key_length = strlen(argv[i]) - 2;
						crypto_key_length = crypto_key_length / 2 + !!(crypto_key_length % 2);
						if(crypto_key_length > 56) {
							printf("Wrong key length\n");
							return i;
						}

						uint16_t key_length = crypto_key_length;
						if(key_length % 8) {
							key_length -= key_length % 8;
							key_length += 8;
						}
						if(!parse_key(ni, argv[i], &crypto_key, key_length)) {
							printf("Wrong crypto key\n");
							return i;
						}
					} else if(!strcmp(argv[i], "cast128_cbc")) {
						/* cast128 key length 5 ~56 bytes */
						crypto_algorithm = CRYPTO_CAST128_CBC;
						i++;
						if(strncmp("0x", argv[i], 2)) {
							printf("Wrong key length\n");
							return i;
						}

						crypto_key_length = strlen(argv[i]) - 2;
						crypto_key_length = crypto_key_length / 2 + !!(crypto_key_length % 2);
						if(crypto_key_length > 56) {
							printf("Wrong key length\n");
							return i;
						}

						uint16_t key_length = crypto_key_length;
						if(key_length % 8) {
							key_length -= key_length % 8;
							key_length += 8;
						}
						if(!parse_key(ni, argv[i], &crypto_key, key_length)) {
							printf("Wrong crypto key\n");
							return i;
						}
					} else if(!strcmp(argv[i], "rijndael_cbc")) {
						crypto_algorithm = CRYPTO_RIJNDAEL_CBC;
						i++;
						if(strncmp("0x", argv[i], 2)) {
							printf("Wrong key length\n");
							return i;
						}

						crypto_key_length = strlen(argv[i]) - 2;
						crypto_key_length = crypto_key_length / 2 + !!(crypto_key_length % 2);
						if(crypto_key_length > 32) {
							printf("Wrong key length\n");
							return i;
						}
						if(crypto_key_length > 24)
							crypto_key_length = 32;
						else if(crypto_key_length > 16)
							crypto_key_length = 24;
						else
							crypto_key_length = 16;

						if(!parse_key(ni, argv[i], &crypto_key, crypto_key_length)) {
							printf("Wrong crypto key\n");
							return i;
						}
					} else if(!strcmp(argv[i], "camellia_cbc")) {
						crypto_algorithm = CRYPTO_CAMELLIA_CBC;
						i++;
						if(strncmp("0x", argv[i], 2)) {
							printf("Wrong key length\n");
							return i;
						}

						crypto_key_length = strlen(argv[i]) - 2;
						crypto_key_length = crypto_key_length / 2 + !!(crypto_key_length % 2);
						if(crypto_key_length > 32) {
							printf("Wrong key length\n");
							return i;
						}
						if(crypto_key_length > 24)
							crypto_key_length = 32;
						else if(crypto_key_length > 16)
							crypto_key_length = 24;
						else
							crypto_key_length = 16;

						if(!parse_key(ni, argv[i], &crypto_key, crypto_key_length)) {
							printf("Wrong crypto key\n");
							return i;
						}
					} else if(!strcmp(argv[i], "aes_ctr")) {
						crypto_algorithm = CRYPTO_AES_CTR;
						crypto_key_length = 16;
						i++;
						if(!parse_key(ni, argv[i], &crypto_key, 16)) {
							printf("Wrong crypto key\n");
							return i;
						}
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
					if(!is_uint32(argv[i])) {
						printf("Wrong spi\n");
						return i;
					}
					spi = parse_uint32(argv[i]);
				} else if(!strcmp(argv[i], "-A")) {
					i++;

					if(!strcmp(argv[i], "hmac_md5")) {
						auth_algorithm = AUTH_HMAC_MD5;
						i++;
						auth_key_length = 16;
						if(!parse_key(ni, argv[i], &auth_key, 16)) {
							printf("AH key  wrong\n");
							return i;
						}
					} else if(!strcmp(argv[i], "hmac_sha1")) {
						auth_algorithm = AUTH_HMAC_SHA1;
						auth_key_length = 20;
						if(!parse_key(ni, argv[i], &auth_key, 20)) {
							printf("AH key  wrong\n");
							return i;
						}
					} else if(!strcmp(argv[i], "hmac_sha256")) {
						auth_algorithm = AUTH_HMAC_SHA256;
						auth_key_length = 32;
						if(!parse_key(ni, argv[i], &auth_key, 32)) {
							printf("AH key  wrong\n");
							return i;
						}
					} else if(!strcmp(argv[i], "hmac_sha384")) {
						auth_algorithm = AUTH_HMAC_SHA384;
						auth_key_length = 48;
						if(!parse_key(ni, argv[i], &auth_key, 48)) {
							printf("AH key  wrong\n");
							return i;
						}
					} else if(!strcmp(argv[i], "hmac_sha512")) {
						auth_algorithm = AUTH_HMAC_SHA512;
						auth_key_length = 64;
						if(!parse_key(ni, argv[i], &auth_key, 64)) {
							printf("AH key  wrong\n");
							return i;
						}
					} else if(!strcmp(argv[i], "hmac_ripemd160")) {
						auth_algorithm = AUTH_HMAC_RIPEMD160;
						auth_key_length = 20;
						if(!parse_key(ni, argv[i], &auth_key, 20)) {
							printf("AH key  wrong\n");
							return i;
						}
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

					//TODO: case not esp
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

			if(!(crypto_algorithm || auth_algorithm)) {
				printf("Algorithm not setted\n");
				return i;
			}
			uint64_t attrs[] = {
				SA_SPI, spi,
				SA_PROTOCOL, protocol,
				SA_SOURCE_IP, src_ip,
				SA_SOURCE_MASK, src_mask,
				SA_DESTINATION_IP, dest_ip,
				SA_DESTINATION_MASK, dest_mask,
				SA_SOURCE_PORT, src_port,
				SA_DESTINATION_PORT, dest_port,

				SA_CRYPTO_ALGORITHM, crypto_algorithm,
				SA_CRYPTO_KEY, (uint64_t)crypto_key,
				SA_CRYPTO_KEY_LENGTH, crypto_key_length,
				//SA_IV_SUPPORT, iv,
				SA_AUTH_ALGORITHM, auth_algorithm,
				SA_AUTH_KEY, (uint64_t)auth_key,
				SA_AUTH_KEY_LENGTH, auth_key_length,

				SA_REPLY, true,
				SA_NONE,
			};

			SA* sa = sa_alloc(ni, attrs);
			if(sa == NULL) {
				printf("can't create SA\n");
				return -1;
			}

			if(!sad_add_sa(ni, sa)) {
				printf("Can'nt add SA\n");
				return -1;
			}
			printf("Security Association added\n");

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
			printf("NI\tProtocol\tAlgorithm:Key\n");
			void dump_sad(uint16_t ni_index) {
				void crypto_algorithm_dump(uint8_t crypto_algorithm) {
					switch(crypto_algorithm) {
						case CRYPTO_NONE:
							printf("none:");
							break;
						case CRYPTO_DES_CBC:
							printf("des_cbc:");
							break;
						case CRYPTO_3DES_CBC:
							printf("3des_cbc:");
							break;
						case CRYPTO_BLOWFISH_CBC:
							printf("blowfish_cbc:");
							break;
						case CRYPTO_CAST128_CBC:
							printf("cast128_cbc:");
							break;
						case CRYPTO_DES_DERIV:
							printf("des_deriv:");
							break;
						case CRYPTO_3DES_DERIV:
							printf("3des_deriv:");
							break;
						case CRYPTO_RIJNDAEL_CBC:
							printf("rinjndael_cbc:");
							break;
						case CRYPTO_TWOFISH_CBC:
							printf("twofish_cbc:");
							break;
						case CRYPTO_AES_CTR:
							printf("aes_ctr:");
							break;
						case CRYPTO_CAMELLIA_CBC:
							printf("camellia_cbc:");
							break;
					}
				}
				void auth_algorithm_dump(uint8_t auth_algorithm) {
					switch(auth_algorithm) {
						case AUTH_NONE:
							printf("none:");
							break;
						case AUTH_HMAC_MD5:
							printf("hmac_md5:");
							break;
						case AUTH_HMAC_SHA1:
							printf("hmac_sha1:");
							break;
						case AUTH_KEYED_MD5:
							printf("keyed_md5:");
							break;
						case AUTH_KEYED_SHA1:
							printf("keyed_sha1:");
							break;
						case AUTH_HMAC_SHA256:
							printf("hmac_sha256:");
							break;
						case AUTH_HMAC_SHA384:
							printf("hmac_sha384:");
							break;
						case AUTH_HMAC_SHA512:
							printf("hmac_sha512:");
							break;
						case AUTH_HMAC_RIPEMD160:
							printf("hmac_ripemd160:");
							break;
						case AUTH_AES_XCBC_MAC:
							printf("aes_xcbc_mac:");
							break;
						case AUTH_TCP_MD5:
							printf("tcp_md5:");
							break;
					}
				}
				void key_dump(uint64_t* key, uint16_t key_length) {
					int index = key_length;
					uint8_t* _key = (uint8_t*)key;
					index--;
					for(; index >= 0; index--) {
						if(*(_key + index) != 0)
							break;
					}

					printf("0x");

					for(; index >= 0; index--) {
						printf("%02x", *(_key + index));
					}
				}
				void protocol_dump(uint8_t protocol) {
					switch(protocol) {
						case IP_PROTOCOL_ESP:
							printf("esp\t");
							break;
						case IP_PROTOCOL_AH:
							printf("ah\t");
							break;
					}
				}

				NetworkInterface* ni = ni_get(ni_index);
				if(!ni)
					return;

				Map* sad = sad_get(ni);
				if(!sad)
					return;

				MapIterator iter;
				map_iterator_init(&iter, sad);
				while(map_iterator_has_next(&iter)) {
					MapEntry* entry = map_iterator_next(&iter);
					List* dest_list = entry->data;
					ListIterator _iter;
					list_iterator_init(&_iter, dest_list);
					while(list_iterator_has_next(&_iter)) {
						SA* sa = list_iterator_next(&_iter);
						printf("eth%d\t", ni_index);
						protocol_dump(sa->ipsec_protocol);
						printf("\t");
						if(sa->ipsec_protocol == IP_PROTOCOL_ESP) {
							crypto_algorithm_dump(((SA_ESP*)sa)->crypto_algorithm);
							key_dump(((SA_ESP*)sa)->crypto_key, ((SA_ESP*)sa)->crypto_key_length);
							printf("\t");
							auth_algorithm_dump(((SA_ESP*)sa)->auth_algorithm);
							key_dump(((SA_ESP*)sa)->auth_key, ((SA_ESP*)sa)->auth_key_length);
							printf("\t");
						} else {
							auth_algorithm_dump(((SA_AH*)sa)->auth_algorithm);
							key_dump(((SA_AH*)sa)->auth_key, ((SA_AH*)sa)->auth_key_length);
							printf("\t");
						}
						printf("\n");
					}
				}
			}

			i++;
			if(argc == 2) {
				uint16_t count = ni_count();
				for(int i = 0; i < count; i++) {
					dump_sad(i);
				}
			} else {
				if(strncmp(argv[i], "eth", 3)) {
					printf("Netowrk Interface number wrong\n");
					return -2;
				}
				if(!is_uint16(argv[i] + 3)) {
					printf("Netowrk Interface number wrong\n");
					return -2;
				}

				uint16_t ni_index = parse_uint16(argv[i] + 3);
				dump_sad(ni_index);
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

			NetworkInterface* out_ni = NULL;

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
						return i;
					}
				} else if(!strcmp(argv[i], "-d")) {
					i++;
					if(!parse_addr_mask_port(argv[i], &dest_ip, &dest_mask, &dest_port)) {
						printf("Wrong destination parameter\n");
						return i;
					}
				} else if(!strcmp(argv[i], "-a")) {
					i++;
					char* _argv = argv[i];
					if(!strncmp(_argv, "ipsec", 5)) {
						_argv += 5;
						action = ACTION_IPSEC;
					} else if(!strncmp(_argv, "bypass", 6)) {
						_argv += 6;
						action = ACTION_BYPASS;
					} else {
						printf("Invalid action\n");
						return i;
					}

					if(*_argv != '/' && *_argv != '\0') {
						printf("Invalid direction\n");
						return i;
					}

					if(*_argv == '/') {
						_argv++;
						if(!strcmp(_argv, "in")) {
							direction = DIRECTION_IN;
						} else if(!strcmp(_argv, "out")) {
							direction = DIRECTION_OUT;
						} else {
							printf("Invalid direction\n");
							return i;
						}
					}
				} else if(!strcmp(argv[i], "-i")) {
					i++;
					if(!is_uint8(argv[i])) {
						printf("index is must be uint8\n");
						return i;
					}

					index = parse_uint8(argv[i]);
				} else if(!strcmp(argv[i], "-o")) {
					i++;
					out_ni = parse_ni(argv[i]);
					if(!out_ni) {
						printf("Can'nt found Out Network Interface\n");
						return i;
					}
				} else {
					printf("Invalid Value\n");
					return i;
				}
			}

			//check null
			uint64_t attrs[] = {
				SP_PROTOCOL, protocol,
				SP_IS_PROTOCOL_SA_SHARE, is_protocol_sa_share,

				SP_SOURCE_IP, src_ip,
				SP_IS_SOURCE_IP_SA_SHARE, is_src_ip_sa_share,
				SP_SOURCE_NET_MASK, src_mask,
				SP_SOURCE_PORT, src_port,
				SP_IS_SOURCE_PORT_SA_SHARE, is_src_port_sa_share,

				SP_OUT_NI, (uint64_t)out_ni,
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

			printf("Security Policy added\n");
			return 0;
		} else if(!strcmp(argv[1], "remove")) {
			//Not yet
			return 0;
		} else if(!strcmp(argv[1], "list")) {
			printf("NI\tProtocol\tSource/Mask:Port\tDestination/Mask:Port\n");
			int parse_mask(uint32_t mask) {
				int i = 0;
				int bit = 0;
				while(mask ^ bit) {
					i++;
					if(bit == 0)
						bit = 1 << 31;
					else
						bit = bit >> 1;
				}

				return i;
			}

			void dump_spd(uint16_t ni_index) {
				NetworkInterface* ni = ni_get(ni_index);
				if(!ni)
					return;

				List* spd = spd_get(ni);
				if(!spd) {
					return;
				}

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
					printf("eth%d\t", ni_index);
					protocol_dump(sp->protocol);
					printf("\t\t");
					printf("%x/%d:%d\t", sp->src_ip, parse_mask(sp->src_mask), sp->src_port);
					printf("%x/%d:%d", sp->dest_ip, parse_mask(sp->dest_mask), sp->dest_port);
					printf("\n");
				}
			}
			i++;
			uint16_t count = ni_count();
			if(argc == 2) {
				for(int i = 0; i < count; i++) {
					dump_spd(i);
				}
			} else {
				if(strncmp(argv[i], "eth", 3)) {
					printf("Netowrk Interface number wrong\n");
					return -2;
				}
				if(!is_uint16(argv[i] + 3)) {
					printf("Netowrk Interface number wrong\n");
					return -2;
				}

				uint16_t ni_index = parse_uint16(argv[i] + 3);
				dump_spd(ni_index);
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
				} else if(!strcmp(argv[i], "-E")) {
					i++;

					protocol = IP_PROTOCOL_ESP;
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
				} else if(!strcmp(argv[i], "-A")) {
					i++;

					protocol = IP_PROTOCOL_AH;
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
				} else if(!strcmp(argv[i], "-i")) {
					i++;

					if(!is_uint8(argv[i])) {
						printf("priority must be uint8_t\n");
						return i;
					}

					priority = parse_uint8(argv[i]);
				} else {
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
