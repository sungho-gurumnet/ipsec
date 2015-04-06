#include <net/ip.h>
#include "receiver.h"
#include "sp.h"
#include "spd.h"
#include "sa.h"
#include "sad.h"
#include "auth.h"
#include "crypto.h"

static int cmd_sad(int argc, char** argv, void(*callback)(char* result, int exit_status)) {
	for(int i = 1; i < argc; i++) {
		if(!strcmp(argv[i], "add")) {
			i++;

			uint32_t src_ip = 0;
			uint32_t dst_ip = 0;
			uint8_t protocol = 0;
			uint32_t spi = 0;
			uint8_t extensions = 0;
			uint8_t crypto_algorithm = 0;
			uint8_t auth_algorithm = 0;
			uint64_t crypto_key[32] = {0, };
			uint64_t auth_key[32] = {0, };

			for(; i < argc; i++) {
				if(!strcmp(argv[i], "src_ip:")) {
					i++;
					if(!is_uint32(argv[i])) {
						printf("src_ip is must be uint32\n");
						return i;
					}

					src_ip = parse_uint32(argv[i]);
				} else if(!strcmp(argv[i], "dst_ip:")) {
					i++;
					if(!is_uint32(argv[i])) {
						printf("dst_ip is must be uint32\n");
						return i;
					}

					dst_ip = parse_uint32(argv[i]);
				} else if(!strcmp(argv[i], "protocol:")) {
					i++;
					if(!strcmp(argv[i], "ESP")) {
						protocol = IP_PROTOCOL_ESP;
					} else if(!strcmp(argv[i], "AH")) {
						protocol = IP_PROTOCOL_AH;
					} else {
						printf("Invalid protocol\n");
						return i;
					}
				} else if(!strcmp(argv[i], "spi:")) {
					i++;
					if(!is_uint32(argv[i])) {
						printf("spi is must be uint32\n");
						return i;
					}

					spi = parse_uint32(argv[i]);
				} else if(!strcmp(argv[i], "extensions:")) {
					i++;
					if(!is_uint8(argv[i])) {
						printf("extensions is must be uint32\n");
						return i;
					}

					extensions = parse_uint8(argv[i]);
				} else if(!strcmp(argv[i], "crypto:")) {
					i++;

					int key_index = 0;
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
						} else if(!strcmp(argv[i], "key:")) {
							if(key_index == 32) {
								printf("crypto key's maximum count is 3\n");
								return i;
							}
							i++;
							if(!is_uint64(argv[i]))	{
								printf("crypto key is must be uint64\n");
								return i;
							}
							crypto_key[key_index++] = parse_uint64(argv[i]);

						} else {
							i--;
							break;
						}
					}
				} else if(!strcmp(argv[i], "auth:")) {
					i++;

					int key_index = 0;
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
						} else if(!strcmp(argv[i], "key:")) {
							if(key_index == 32) {
								printf("auth key's maximum count is 8\n");
								return i;
							}
							i++;
							if(!is_uint64(argv[i]))	{
								printf("auth key is must be uint64\n");
								return i;
							}
							auth_key[key_index++] = parse_uint64(argv[i]);

						} else {
							i--;
							break;
						}
					}
				} else {
					printf("Invalid Value\n");
					return i;
				}
			}

			SA* sa = sa_create(src_ip, dst_ip, protocol, spi, extensions, crypto_algorithm, auth_algorithm, crypto_key, auth_key);
			if(sa == NULL) {
				printf("can't create SA\n");
				return -1;
			}

			if(sad_sa_add(sa)) {
				SP* sp = spd_get_index(0);
				sp_sa_add(sp, sa, OUT);
				return 0;
			} else {
				printf("can't add to SAD\n");
				return -1;
			}
		} else if(!strcmp(argv[i], "get")) {
			i++;

			uint32_t spi = 0;
			uint32_t dst_ip = 0;
			uint8_t protocol = 0;

			for(; i < argc; i++) {
				if(!strcmp(argv[i], "dst_ip:")) {
					i++;
					if(!is_uint32(argv[i])) {
						printf("dst_ip is must be uint32\n");
						return i;
					}

					dst_ip = parse_uint32(argv[i]);
				} else if(!strcmp(argv[i], "protocol:")) {
					i++;
					if(!is_uint8(argv[i])) {
						printf("protocol is must be uint32\n");
						return i;
					}

					protocol = parse_uint8(argv[i]);
				} else if(!strcmp(argv[i], "spi:")) {
					i++;
					if(!is_uint32(argv[i])) {
						printf("spi is must be uint32\n");
						return i;
					}

					spi = parse_uint32(argv[i]);
				} else {
					printf("Invalid Value\n");
					return i;
				}
			}

			SA* sa = sad_get(spi, dst_ip, protocol);
			if(sa == NULL)
				return -1;

			printf("SA src_ip : %x dst_ip: %x protoco: %d\n", sa->src_ip, sa->dst_ip, sa->protocol);
			printf("spi: %x mode: %d crypto_algorithm: %d auth_algorithm %d\n", sa->spi, sa->mode, sa->esp_crypto_algorithm, sa->esp_auth_algorithm);

			return 0;
		} else if(!strcmp(argv[i], "delete")) {
			i++;

			uint32_t dst_ip = 0;
			uint8_t protocol = 0;
			uint32_t spi = 0;

			for(; i < argc; i++) {
				if(!strcmp(argv[i], "dst_ip:")) {
					i++;
					if(!is_uint32(argv[i])) {
						printf("dst_ip is must be uint32\n");
						return i;
					}

					dst_ip = parse_uint32(argv[i]);
				} else if(!strcmp(argv[i], "protocol:")) {
					i++;
					if(!is_uint8(argv[i])) {
						printf("protocol is must be uint32\n");
						return i;
					}

					protocol = parse_uint8(argv[i]);
				} else if(!strcmp(argv[i], "spi:")) {
					i++;
					if(!is_uint32(argv[i])) {
						printf("spi is must be uint32\n");
						return i;
					}

					spi = parse_uint32(argv[i]);
				} else {
					printf("Invalid Value\n");
					return i;
				}
			}

			SA* sa = sad_get(spi, dst_ip, protocol);
			if(sa == NULL)
				return -1;

			sad_delete(sa);

			return 0;
		} else if(!strcmp(argv[i], "deleteall")) {
			/*
			i++;

			uint32_t src_ip;
			uint32_t dst_ip;
			uint8_t protocol;

			for(; i < argc; i++) {
				if(!strcmp(argv[i], "src_ip:")) {
					i++;
					if(!is_uint32(argv[i])) {
						printf("src_ip is must be uint32\n");
						return i;
					}

					src_ip = parse_uint32(argv[i]);
				} else if(!strcmp(argv[i], "dst_ip:")) {
					i++;
					if(!is_uint32(argv[i])) {
						printf("dst_ip is must be uint32\n");
						return i;
					}

					dst_ip = parse_uint32(argv[i]);
				} else if(!strcmp(argv[i], "protocol:")) {
					i++;
					if(!is_uint8(argv[i])) {
						printf("protocol is must be uint32\n");
						return i;
					}

					protocol = parse_uint8(argv[i]);
				} else {
					printf("Invalid Value\n");
					return i;
				}
			}

			return setkey_deleteall(src_ip, dst_ip, protocol);
			*/
			return 0;
		} else if(!strcmp(argv[i], "flush")) {

			return 0;
		} else if(!strcmp(argv[i], "dump")) {
			sad_dump();
			return 0;
		} else {
			printf("Invalid Option %s\n", argv[1]);
			return -1;
		}
	}
	
	return 0;
}

static int cmd_spd(int argc, char** argv, void(*callback)(char* result, int exit_status)) {
	for(int i = 1; i < argc; i++) {
		if(!strcmp(argv[1], "add")) {
			i++;

			uint32_t src_ip = 0;
			uint32_t src_mask = 0xffffff00;
			uint32_t dst_ip = 0;
			uint32_t dst_mask = 0xffffff00;
			uint16_t src_port = 0;
			uint16_t dst_port = 0;
			uint8_t protocol = IP_PROTOCOL_ESP;
			uint8_t direction = INOUT;
			uint8_t action = IPSEC;
			uint8_t priority = 0;

			for(; i < argc; i++) {
				if(!strcmp(argv[i], "src:")) {
					i++;
					for(; i < argc; i++) {
						if(!strcmp(argv[i], "ip:")) {
							i++;
							if(!is_uint32(argv[i])) {
								if(!strcmp(argv[i], "IP_ANY")) {
									src_ip = IP_ANY;
								} else {
									printf("ip is must be uint32\n");
									return i;
								}
							} else
								src_ip = parse_uint32(argv[i]);
						} else if(!strcmp(argv[i], "mask:")) {
							i++;
							if(!is_uint32(argv[i])) {
								printf("mask is must be uint32\n");
								return i;
							}

							src_mask = parse_uint32(argv[i]);

						} else if(!strcmp(argv[i], "port:")) {
							i++;
							if(!is_uint16(argv[i])) {
								if(!strcmp(argv[i], "PORT_ANY")) {
									src_port = PORT_ANY;
								} else {
									printf("port is must be uint16\n");
									return i;
								}
							} else
								src_port = parse_uint16(argv[i]);
						} else {
							i--;
							break;
						}
					}
				} else if(!strcmp(argv[i], "dst:")) {
					i++;
					for(; i < argc; i++) {
						if(!strcmp(argv[i], "ip:")) {
							i++;
							if(!is_uint32(argv[i])) {
								if(!strcmp(argv[i], "IP_ANY")) {
									dst_ip = IP_ANY;
								} else {
									printf("ip is must be uint32\n");
									return i;
								}
							} else
								dst_ip = parse_uint32(argv[i]);

						} else if(!strcmp(argv[i], "mask:")) {
							i++;
							if(!is_uint32(argv[i])) {
								printf("mask is must be uint32\n");
								return i;
							}

							dst_mask = parse_uint32(argv[i]);

						} else if(!strcmp(argv[i], "port:")) {
							i++;
							if(!is_uint16(argv[i])) {
								if(!strcmp(argv[i], "PORT_ANY")) {
									dst_port = PORT_ANY;
								} else {
									printf("port is must be uint16\n");
									return i;
								}
							} else
								dst_port = parse_uint16(argv[i]);
						} else {
							i--;
							break;
						}
					}
				} else if(!strcmp(argv[i], "direction:")) {
					i++;

					if(!strcmp(argv[i], "IN")) {
						direction = IN;
					} else if(!strcmp(argv[i], "OUT")) {
						direction = OUT;
					} else if(!strcmp(argv[i], "INOUT")) {
						direction = INOUT;
					} else {
						printf("Invalid direction\n");
						return i;
					}
				} else if(!strcmp(argv[i], "action:")) {
					i++;

					if(!strcmp(argv[i], "IPSEC")) {
						action = IPSEC;
					} else if(!strcmp(argv[i], "BYPASS")) {
						action = BYPASS;
					} else {
						printf("Invalid action\n");
						return i;
					}
				} else if(!strcmp(argv[i], "protocol:")) {
					i++;

					if(!strcmp(argv[i], "IP_PROTOCOL_ANY")) {
						protocol = IP_PROTOCOL_ANY;
					} else if(!strcmp(argv[i], "ICMP6")) {
						protocol = ICMP6;
					} else if(!strcmp(argv[i], "IP4")) {
						protocol = IP4;
					} else if(!strcmp(argv[i], "GRE")) {
						protocol = GRE;
					} else {
						printf("Invalid protocol\n");
						return i;
					}
				} else if(!strcmp(argv[i], "priority:")) {
					i++;
					if(!is_uint8(argv[i])) {
						printf("priority is must be uint8\n");
						return i;
					}

					priority = parse_uint8(argv[i]);
				} else {
					printf("Invalid Value\n");
					return i;
				}
			}

			SP* sp = sp_create(direction, src_ip, src_mask, dst_ip, dst_mask, src_port, dst_port, action, protocol);

			if(sp == NULL)
				return -1;

			if(spd_sp_add(sp, priority))
				return 0;
		} else if(!strcmp(argv[1], "update")) {
			printf("update not yet support\n");
			/*
			i++;

			if(argc != 10)	
				return -1;

			uint32_t src_ip;
			uint32_t src_mask;
			uint32_t dst_ip;
			uint32_t dst_mask;
			uint16_t src_port;
			uint16_t dst_port;
			uint8_t upperspec;
			uint8_t direction;
			uint8_t action;

			for(; i < argc; i++) {
				if(!strcmp(argv[i], "src:")) {
					i++;
					for(; i < argc; i++) {
						if(!strcmp(argv[i], "ip:")) {
							if(!is_uint32(argv[i])) {
								printf("mask is must be uint32\n");
								return i;
							}

							src_ip = parse_uint32(argv[i]);
						} else if(!strcmp(argv[i], "mask:")) {
							if(!is_uint32(argv[i])) {
								printf("mask is must be uint32\n");
								return i;
							}

							src_mask = parse_uint32(argv[i]);

						} else if(!strcmp(argv[i], "port:")) {
							if(!is_uint16(argv[i])) {
								printf("port is must be uint16\n");
								return i;
							}

							src_port = parse_uint16(argv[i]);
						} else {
							i--;
							break;
						}
					}
				} else if(!strcmp(argv[i], "dst:")) {
					i++;
					for(; i < argc; i++) {
						if(!strcmp(argv[i], "ip:")) {
							if(!is_uint32(argv[i])) {
								printf("mask is must be uint32\n");
								return i;
							}

							dst_ip = parse_uint32(argv[i]);
						} else if(!strcmp(argv[i], "mask:")) {
							if(!is_uint32(argv[i])) {
								printf("mask is must be uint32\n");
								return i;
							}

							dst_mask = parse_uint32(argv[i]);
						} else if(!strcmp(argv[i], "port:")) {
							if(!is_uint16(argv[i])) {
								printf("port is must be uint16\n");
								return i;
							}

							dst_port = parse_uint16(argv[i]);
						} else {
							i--;
							break;
						}
					}
				} else if(!strcmp(argv[i], "upperspec:")) {
					i++;
					if(!is_uint8(argv[i])) {
						printf("upperspec is must be uint8\n");
						return i;
					}

					upperspec = parse_uint8(argv[i]);
				} else if(!strcmp(argv[i], "direction:")) {
					i++;
					if(!is_uint8(argv[i])) {
						printf("direction is must be uint8\n");
						return i;
					}

					direction = parse_uint8(argv[i]);
				} else if(!strcmp(argv[i], "action:")) {
					i++;
					if(!is_uint8(argv[i])) {
						printf("action is must be uint8\n");
						return i;
					}

					action = parse_uint8(argv[i]);
				} else {
					printf("Invalid Value\n");
					return i;
				}
			}
			*/

			return 0;
			//return setkey_spdupdate(src_ip, dst_ip, src_mask, dst_mask, src_port, dst_port, upperspec, direction, action);
		} else if(!strcmp(argv[1], "delete")) {
			i++;

			if(argc != 10)	
				return -1;

			uint32_t index = 0;

			for(; i < argc; i++) {
				if(!strcmp(argv[i], "index:")) {
					i++;
					if(!is_uint8(argv[i])) {
						printf("index is must be uint8\n");
						return i;
					}

					index = parse_uint32(argv[i]);
				} else {
					printf("Invalid Value\n");
					return i;
				}
			}

			if(spd_sp_delete(index))
				return 0;
			else return -1;
		} else if(!strcmp(argv[1], "flush")) {
			spd_all_delete();

			return 0;
		} else if(!strcmp(argv[1], "dump")) {
			int j = 0;
			while(true) {
				SP* sp = spd_get_index(j);
				if(sp == NULL)
					break;

				void protocol_dump(uint8_t protocol) {
					switch(protocol) {
						case IP_PROTOCOL_ANY:
							printf("IP_PROTOCOL_ANY");
							break;
						case ICMP6:
							printf("ICMP6");
							break;
						case IP4:
							printf("IP4");
							break;
						case GRE:
							printf("GRE");
							break;
					}
				}
				printf("[INDEX: %d] Protocol ", j++);
				protocol_dump(sp->protocol);
				printf("\n");
				printf("Source ip %x mask %x port %d\n", sp->src_ip, sp->src_mask, sp->src_port);
				printf("Destination ip %x mask %x port %d\n", sp->dst_ip, sp->dst_mask, sp->dst_port);
			}

			return 0;
		} else {
			printf("Invalid Option %s\n", argv[1]);
			return -1;
		}
	}
	return 0;
}

static int cmd_content(int argc, char** argv, void(*callback)(char* result, int exit_status)) {
	for(int i = 1; i < argc; i++) {
		if(!strcmp(argv[i], "add")) {
			i++;
			
			SP* sp = NULL;
			uint8_t protocol = 0;
			uint8_t mode = 0;
			uint32_t t_src_ip = 0;
			uint32_t t_dst_ip = 0;
			uint8_t crypto_algorithm = 0;
			uint8_t auth_algorithm = 0;
			uint8_t priority = 0;
			
			for(; i < argc; i++) {
				if(!strcmp(argv[i], "index:")) {
					i++;

					if(!is_uint8(argv[i])) {
						printf("index is must be uint8\n");
						return i;
					}

					sp = spd_get_index((int)parse_uint8(argv[i]));
				} else if(!strcmp(argv[i], "protocol:")) {
					i++;

					if(!strcmp(argv[i], "ESP")) {
						protocol = IP_PROTOCOL_ESP;
					} else if(!strcmp(argv[i], "AH")) {
						protocol = IP_PROTOCOL_AH;
					} else {
						printf("Invalid protocol\n");
						return i;
					}

				} else if(!strcmp(argv[i], "mode:")) {
					i++;

					if(!strcmp(argv[i], "TRANSPORT")) {
						mode = TRANSPORT;

					} else if(!strcmp(argv[i], "TUNNEL")) {
						mode = TUNNEL;
						i++;

						for(; i < argc; i++) {
							if(!strcmp(argv[i], "src_ip:")) {
								i++;

								if(!is_uint32(argv[i])) {
									printf("src_ip is must be uint32\n");
									return i;
								}

								t_src_ip = parse_uint32(argv[i]);
							} else if(!strcmp(argv[i], "dst_ip:")) {
								i++;

								if(!is_uint32(argv[i])) {
									printf("dst_ip is must be uint32\n");
									return i;
								}

								t_dst_ip = parse_uint32(argv[i]);

							} else {
								i--;
								break;
							}
						}
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

			if(sp == NULL) {
				printf("Can't Found SP\n");
				return -1;
			}

			Content* cont = create_content(protocol, mode, t_src_ip, t_dst_ip, crypto_algorithm, auth_algorithm);
			if(cont == NULL) {
				printf("Can't Create Content\n");
				return -1;
			}

			if(!sp_content_add(sp, cont, priority)) {
				printf("Can't add content to SP\n");
				return -1;
			}
			printf("sp contents size: %d\n",list_size(sp->contents));

			return 0;
			//get sp
		} else if(!strcmp(argv[i], "delete")) {
			return 0;
		} else if(!strcmp(argv[i], "flush")) {
			return 0;
		} else if(!strcmp(argv[i], "dump")) {
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
		.name = "sad",
		.desc = "Manage IPSec Security Association Database\nadd get delete flush dump",
		.func = cmd_sad
	},
	{
		.name = "spd",
		.desc = "Manage IPSec Security Policy Database\nadd update delete flush dump",
		.func = cmd_spd
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

int receiver_init() {
	cmd_init();
	printf("IPSec Configuration Receiver Initialized\n");

	return 0;
}

int receiver_parse(char* line) {
	void cmd_callback(char* result, int exit_status) {
		if(result)
			printf("%s\n", result);
	}

	int exit_status = cmd_exec(line, cmd_callback);

	return exit_status;
}
