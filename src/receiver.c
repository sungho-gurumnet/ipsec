#include "receiver.h"
#include "sp.h"
#include "spd.h"
#include "sa.h"
#include "sad.h"

static int cmd_sad(int argc, char** argv, void(*callback)(char* result, int exit_status)) {
	for(int i = 1; i < argc; i++) {
		if(!strcmp(argv[1], "add")) {
			i++;

			if(argc != 10)	
				return -1;

			uint32_t src_ip = 0;
			uint32_t dst_ip = 0;
			uint8_t protocol = 0;
			uint32_t spi = 0;
			uint8_t extensions = 0;
			uint8_t crypto_algorithm = 0;
			uint8_t auth_algorithm = 0;
			uint64_t crypto_key[3] = {0, };
			uint64_t auth_key[8] = {0, };

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
				} else if(!strcmp(argv[i], "crypto_algorithm:")) {
					i++;
					if(!is_uint8(argv[i])) {
						printf("crypto_algorithm is must be uint32\n");
						return i;
					}
					crypto_algorithm = parse_uint8(argv[i]);

					i++;
					
					for(int j = 0; j < 3; j++) {
						if(!is_uint64(argv[i]))	{
							i--;
							break;
						}
						crypto_key[j] = parse_uint64(argv[i]);
						i++;
					}
				} else if(!strcmp(argv[i], "auth_algorithm:")) {
					i++;
					if(!is_uint8(argv[i])) {
						printf("crypto_algorithm is must be uint32\n");
						return i;
					}
					auth_algorithm = parse_uint8(argv[i]);

					i++;

					for(int j = 0; j < 8; j++) {
						if(!is_uint64(argv[i]))	{
							i--;
							break;
						}
						auth_key[j] = parse_uint64(argv[i]);
						i++;
					}
				} else {
					printf("Invalid Value\n");
					return i;
				}
			}

			SA* sa = sa_create(src_ip, dst_ip, protocol, spi, extensions, crypto_algorithm, auth_algorithm, crypto_key, auth_key);
			if(sa == NULL)
				return -1;

			if(sad_sa_add(sa))
				return 0;
			else
				return -1;
		} else if(!strcmp(argv[1], "get")) {
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
		} else if(!strcmp(argv[1], "delete")) {
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
		} else if(!strcmp(argv[1], "deleteall")) {
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
		} else if(!strcmp(argv[1], "flush")) {
			/*
			i++;
			
			uint8_t protocol;
			if(!strcmp(argv[i], "protocol:")) {
				if(!is_uint8(argv[i])) {
					return i;
				}

				protocol = parse_uint8(argv[i]);
			}

			return setkey_flush(protocol);
			*/
			return 0;
		} else if(!strcmp(argv[1], "dump")) {
			/*
			i++;
			
			uint8_t protocol;
			if(!strcmp(argv[i], "protocol:")) {
				if(!is_uint8(argv[i])) {
					return i;
				}

				protocol = parse_uint8(argv[i]);
			}

			return setkey_dump(protocol);
			*/
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

			if(argc != 16)	
				return -1;

			uint32_t src_ip = 0;
			uint32_t src_mask = 0;
			uint32_t dst_ip = 0;
			uint32_t dst_mask = 0;
			uint16_t src_port = 0;
			uint16_t dst_port = 0;
			uint8_t protocol = 0;
			uint8_t direction = 0;
			uint8_t action = 0;
			uint8_t priority = 0;

			/*
			uint8_t protocol;
			uint8_t mode;
			uint32_t t_src_ip;
			uint32_t t_dst_ip;
			uint32_t level;
			*/

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
							/*
						} else if(!strcmp(argv[i], "tunnel:")) {
							if(!is_uint32(argv[i])) {
								printf("mask is must be uint32\n");
								return i;
							}

							t_src_ip = parse_uint32(argv[i]);
							*/
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
							/*
						} else if(!strcmp(argv[i], "tunnel:")) {
							if(!is_uint32(argv[i])) {
								printf("mask is must be uint32\n");
								return i;
							}

							t_dst_ip = parse_uint32(argv[i]);
							*/
						} else {
							i--;
							break;
						}
					}
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
				} else if(!strcmp(argv[i], "protocol:")) {
					i++;
					if(!is_uint8(argv[i])) {
						printf("protocol is must be uint8\n");
						return i;
					}

					protocol = parse_uint8(argv[i]);
					/*
				} else if(!strcmp(argv[i], "mode:")) {
					i++;
					if(!is_uint8(argv[i])) {
						printf("mode is must be uint8\n");
						return i;
					}

					mode = parse_uint8(argv[i]);
					*/
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

			uint32_t index;

			for(; i < argc; i++) {
				if(!strcmp(argv[i], "index:")) {
					i++;
					if(!is_uint8(argv[i])) {
						printf("upperspec is must be uint8\n");
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

				printf("index : %d\n", j);
			}

			return 0;
		} else {
			printf("Invalid Option %s\n", argv[1]);
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
		.desc = "Manage IPSec Security Association Database",
		.func = cmd_sad
	},
	{
		.name = "spd",
		.desc = "Manage IPSec Security Policy Database",
		.func = cmd_spd
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
	printf("receiver initialized\n");

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
