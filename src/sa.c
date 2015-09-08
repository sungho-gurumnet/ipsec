#include <malloc.h>
#define DONT_MAKE_WRAPPER
#include <_malloc.h>
#undef DONT_MAKE_WRAPPER
#include <net/ni.h>
#include <lock.h>

#include "sa.h"
#include "auth.h"
#include "crypto.h"

SA* sa_alloc(NetworkInterface* ni, uint64_t* attrs) {
	bool has_key(uint64_t key) {
		int i = 0;
		while(attrs[i * 2] != NI_NONE) {
			if(attrs[i * 2] == key)
				return true;

			i++;
		}

		return false;
	}

	uint64_t get_value(uint64_t key) {
		int i = 0;
		while(attrs[i * 2] != NI_NONE) {
			if(attrs[i * 2] == key)
				return attrs[i * 2 + 1];

			i++;
		}

		return (uint64_t)-1;
	}

        SA* sa = NULL;
	uint64_t value = get_value(SA_CRYPTO_ALGORITHM);
	if(value) {
		//case esp
		if(!has_key(SA_CRYPTO_KEY)) {
			return NULL;
		}
		sa = __malloc(sizeof(SA_ESP), ni->pool);
		if(!sa) {
			printf("Can'nt allocate SA\n");
			return NULL;
		}
		memset(sa, 0, sizeof(SA_ESP));
		sa->ni = ni;
		sa->ipsec_protocol = IP_PROTOCOL_ESP;
	} else {
		if(!has_key(SA_AUTH_KEY)) {
			return NULL;
		}
		sa = __malloc(sizeof(SA_AH), ni->pool);
		if(!sa) {
			printf("Can'nt allocate SA\n");
			return NULL;
		}
		memset(sa, 0, sizeof(SA_AH));
		sa->ni = ni;
		sa->ipsec_protocol = IP_PROTOCOL_AH;
	}

	sa->src_mask = 0xffffffff;
	sa->dest_mask = 0xffffffff;

	for(int i = 0; attrs[i * 2] != SA_NONE; i++) {
		switch(attrs[i * 2]) {
			case SA_IPSEC_MODE:
				sa->ipsec_mode = (uint8_t)attrs[i * 2 + 1];
				break;
			case SA_TUNNEL_SOURCE_IP:
				sa->t_src_ip = (uint32_t)attrs[i * 2 + 1];
				break;
			case SA_TUNNEL_DESTINATION_IP:
				sa->t_dest_ip = (uint32_t)attrs[i * 2 + 1];
				break;
			case SA_SPI:
				sa->spi = (uint32_t)attrs[i * 2 + 1];
				break;
			case SA_PROTOCOL:
				sa->protocol = (uint8_t)attrs[i * 2 + 1];
				break;
			case SA_SOURCE_IP:
				sa->src_ip = (uint32_t)attrs[i * 2 + 1];
				break;
			case SA_SOURCE_MASK:
				sa->src_mask = (uint32_t)attrs[i * 2 + 1];
				break;
			case SA_DESTINATION_IP:
				sa->dest_ip = (uint32_t)attrs[i * 2 + 1];
				break;
			case SA_DESTINATION_MASK:
				sa->dest_mask = (uint32_t)attrs[i * 2 + 1];
				break;
			case SA_SOURCE_PORT:
				sa->src_port = (uint16_t)attrs[i * 2 + 1];
				break;
			case SA_DESTINATION_PORT:
				sa->dest_port = (uint16_t)attrs[i * 2 + 1];
				break;
			case SA_CRYPTO_ALGORITHM:
				if(sa->ipsec_protocol == IP_PROTOCOL_ESP) {
					((SA_ESP*)sa)->crypto_algorithm = (uint8_t)attrs[i * 2 + 1];
					((SA_ESP*)sa)->crypto = (void*)get_cryptography(attrs[i * 2 + 1]);
				}
				break;
			case SA_CRYPTO_KEY:
				((SA_ESP*)sa)->crypto_key = (uint64_t*)attrs[i * 2 + 1];

				uint16_t crypto_key_length = get_value(SA_CRYPTO_KEY_LENGTH);
				uint8_t algorithm = get_value(SA_CRYPTO_ALGORITHM);
				switch(algorithm) {
					case CRYPTO_DES_DERIV:
					case CRYPTO_3DES_DERIV:
						break;
					case CRYPTO_DES_CBC:
						;
						/*Des*/
						DES_cblock des_key;
						uint64_t key = *(uint64_t*)(((SA_ESP*)sa)->crypto_key);
						//key = endian64(key);
						printf("key: %lx\n", key);
						memcpy(des_key, &key, sizeof(DES_cblock));
						DES_set_odd_parity(&des_key);

						DES_key_schedule* ks = __malloc(sizeof(DES_key_schedule), ni->pool);
						if(!ks) {
							printf("Can'nt allocate key\n");
							goto fail_key_alloc;
						}
						if(DES_set_key_checked(&des_key, ks)) {
							printf("Encrypt key is weak key\n");
							__free(ks, ni->pool);
							goto error_set_key;
						}

						((SA_ESP*)sa)->encrypt_key = ks;
						((SA_ESP*)sa)->decrypt_key = ks;
						break;
					case CRYPTO_3DES_CBC:
						/*Des*/
						;
						DES_cblock des_key_3[3];
						memcpy(des_key_3, ((SA_ESP*)sa)->crypto_key, sizeof(DES_cblock) * 3);
						for(int i = 0; i < 3; i++)
							DES_set_odd_parity(&des_key_3[i]);

						DES_key_schedule* ks_3 = __malloc(sizeof(DES_key_schedule) * 3, ni->pool);
						if(!ks_3) {
							printf("Can'nt allocate key\n");
							goto fail_key_alloc;
						}
						if(DES_set_key_checked(&des_key_3[0], &ks_3[0]) || DES_set_key_checked(&des_key_3[1], &ks_3[1]) || DES_set_key_checked(&des_key_3[2], &ks_3[2])) {
							printf("Encrypt key is weak key\n");
							__free(ks_3, ni->pool);
							goto error_set_key;
						}

						((SA_ESP*)sa)->encrypt_key = ks_3;
						((SA_ESP*)sa)->decrypt_key = ks_3;
						break;
					case CRYPTO_BLOWFISH_CBC:
						;
						/*BF*/
						BF_KEY* bf_key = __malloc(sizeof(BF_KEY), ni->pool);
						if(!bf_key) {
							printf("Can'nt allocate key\n");
							goto fail_key_alloc;
						}
						BF_set_key(bf_key, crypto_key_length * 8, (const unsigned char*)((SA_ESP*)sa)->crypto_key);
						((SA_ESP*)sa)->encrypt_key = bf_key;
						((SA_ESP*)sa)->decrypt_key = bf_key;
						break;
					case CRYPTO_CAST128_CBC:
						;
						/*Cast*/
						CAST_KEY* cast_key = __malloc(sizeof(CAST_KEY), ni->pool);
						if(!cast_key) {
							printf("Can'nt allocate key\n");
							goto fail_key_alloc;
						}
						CAST_set_key(cast_key, crypto_key_length * 8, (const unsigned char*)((SA_ESP*)sa)->crypto_key);
						((SA_ESP*)sa)->encrypt_key = cast_key;
						((SA_ESP*)sa)->decrypt_key = cast_key;
						break;
					case CRYPTO_RIJNDAEL_CBC:
					case CRYPTO_AES_CTR:
						;
						/*AES*/
						AES_KEY* encrypt_key = __malloc(sizeof(AES_KEY), ni->pool);
						if(!encrypt_key) {
							printf("Can'nt allocate key\n");
							goto fail_key_alloc;
						}
						AES_KEY* decrypt_key = __malloc(sizeof(AES_KEY), ni->pool);
						if(!decrypt_key) {
							printf("Can'nt allocate key\n");
							__free(encrypt_key, ni->pool);
							goto fail_key_alloc;
						}
						/*AES has diffrent key for encrypt and decrypt*/
						AES_set_encrypt_key((const unsigned char*)((SA_ESP*)sa)->crypto_key, crypto_key_length * 8, encrypt_key);
						AES_set_decrypt_key((const unsigned char*)((SA_ESP*)sa)->crypto_key, crypto_key_length * 8, decrypt_key);
						((SA_ESP*)sa)->encrypt_key = encrypt_key;
						((SA_ESP*)sa)->decrypt_key = decrypt_key;
					case CRYPTO_CAMELLIA_CBC:
						;
						/*Camellia*/
						CAMELLIA_KEY* camellia_key = __malloc(sizeof(CAMELLIA_KEY), ni->pool);
						if(!camellia_key) {
							printf("Can'nt allocate key\n");
							__free(camellia_key, ni->pool);
							goto fail_key_alloc;
						}
						Camellia_set_key((const unsigned char*)((SA_ESP*)sa)->crypto_key, crypto_key_length * 8, camellia_key);
						((SA_ESP*)sa)->encrypt_key = camellia_key;
						((SA_ESP*)sa)->decrypt_key = camellia_key;
					case CRYPTO_TWOFISH_CBC:
						break;
				}
				break;
			case SA_CRYPTO_KEY_LENGTH:
				((SA_ESP*)sa)->crypto_key_length = (uint16_t)attrs[i * 2 + 1];
				break;
			case SA_IV_SUPPORT:
				((SA_ESP*)sa)->iv = (bool)attrs[i * 2 + 1];
				break;
			case SA_AUTH_ALGORITHM:
				if(sa->ipsec_protocol == IP_PROTOCOL_AH) { 
						((SA_AH*)sa)->auth_algorithm = (uint8_t)attrs[i * 2 + 1];
						((SA_AH*)sa)->auth = (void*)get_authentication(attrs[i * 2 + 1]);
				} else {
						if(!attrs[i * 2 + 1]) {
							break;
						}
						((SA_ESP*)sa)->auth_algorithm = (uint8_t)attrs[i * 2 + 1];
						((SA_ESP*)sa)->auth = (void*)get_authentication(attrs[i * 2 + 1]);
				}
				break;
			case SA_AUTH_KEY:
				if(sa->ipsec_protocol == IP_PROTOCOL_AH) {  
						((SA_AH*)sa)->auth_key = (uint64_t*)attrs[i * 2 + 1];
				} else {
						((SA_ESP*)sa)->auth_key = (uint64_t*)attrs[i * 2 + 1];
				}
				break;
			case SA_AUTH_KEY_LENGTH:
				if(sa->ipsec_protocol == IP_PROTOCOL_AH) {   
						((SA_AH*)sa)->auth_key_length = (uint32_t)attrs[i * 2 + 1];
				} else {
						((SA_ESP*)sa)->auth_key_length = (uint32_t)attrs[i * 2 + 1];
				}
				break;
			case SA_REPLY:
				if(attrs[i * 2 + 1]) {
					sa->window = (Window*)__malloc(sizeof(Window), ni->pool);
					if(!sa->window) {
						printf("Can'nt allocate window\n");
						goto sa_free;
					}
					memset(sa->window, 0x0, sizeof(Window));
				}
				break;
		}
	}

	return sa;

fail_key_alloc:
error_set_key:
sa_free:
	if(sa->ipsec_protocol == IP_PROTOCOL_ESP) {
		if(((SA_ESP*)sa)->encrypt_key) {
			if(((SA_ESP*)sa)->encrypt_key == ((SA_ESP*)sa)->decrypt_key) {
				__free(((SA_ESP*)sa)->encrypt_key, ni->pool);
			} else {
				//AES key
				__free(((SA_ESP*)sa)->encrypt_key, ni->pool);
				__free(((SA_ESP*)sa)->decrypt_key, ni->pool);
			}
		}
	} else if(sa->ipsec_protocol == IP_PROTOCOL_AH) {
	}
	if(sa->window) {
		__free(sa->window, ni->pool);
	}
	__free(sa, ni->pool);

	return NULL;
}

bool sa_free(SA* sa) {
	if(sa->ipsec_protocol == IP_PROTOCOL_ESP) {
		if(((SA_ESP*)sa)->encrypt_key) {
			if(((SA_ESP*)sa)->encrypt_key == ((SA_ESP*)sa)->decrypt_key) {
				__free(((SA_ESP*)sa)->encrypt_key, sa->ni->pool);
			} else {
				//AES key
				__free(((SA_ESP*)sa)->encrypt_key, sa->ni->pool);
				__free(((SA_ESP*)sa)->decrypt_key, sa->ni->pool);
			}
		}
		if(((SA_ESP*)sa)->auth_key) {
			__free(((SA_ESP*)sa)->auth_key, sa->ni->pool);
		}
	} else if(sa->ipsec_protocol == IP_PROTOCOL_AH) {
		if(((SA_AH*)sa)->auth_key) {
			__free(((SA_ESP*)sa)->auth_key, sa->ni->pool);
		}
	}
	free(sa->window);
	free(sa);

	return true;
}
