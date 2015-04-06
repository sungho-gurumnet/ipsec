#include "sa.h"
#include "auth.h"
#include "crypto.h"

SA* sa_create(uint32_t src_ip, uint32_t dst_ip, uint8_t protocol, uint32_t spi, uint8_t extensions, uint8_t crypto_algorithm, uint8_t auth_algorithm, uint64_t crypto_key[], uint64_t auth_key[]) {
        SA* sa = (SA*)malloc(sizeof(SA));
	if(sa == NULL)
		return NULL;

        sa->src_ip = src_ip;
        sa->dst_ip = dst_ip;
        sa->protocol = protocol;
        sa->spi = spi;
        sa->mode = extensions; // TODO Here
        sa->esp_crypto_algorithm = crypto_algorithm;
        sa->esp_auth_algorithm = auth_algorithm;

	sa->crypto = (void*)get_cryptography(crypto_algorithm);
	sa->auth = (void*)get_authentication(auth_algorithm);

        switch(protocol) {
                case IP_PROTOCOL_ESP : 
                        if(crypto_algorithm != 0) {
                                sa->esp_crypto_key[0] = crypto_key[0];
                                sa->esp_crypto_key[1] = crypto_key[1];
                                sa->esp_crypto_key[2] = crypto_key[2];
				
				DES_set_odd_parity((DES_cblock*)&(sa->esp_crypto_key[0]));
				DES_set_odd_parity((DES_cblock*)&(sa->esp_crypto_key[1]));
				DES_set_odd_parity((DES_cblock*)&(sa->esp_crypto_key[2]));
                        }
                        if(auth_algorithm != 0) {
                                sa->iv_mode = true;
                                sa->esp_auth_key[0] = auth_key[0];
                                sa->esp_auth_key[1] = auth_key[1];
                                sa->esp_auth_key[2] = auth_key[2];
                                sa->esp_auth_key[3] = auth_key[3];
                                sa->esp_auth_key[4] = auth_key[4];
                                sa->esp_auth_key[5] = auth_key[5];
                                sa->esp_auth_key[6] = auth_key[6];
                                sa->esp_auth_key[7] = auth_key[7];
                        }
                        break;
                        
                case IP_PROTOCOL_AH :
                                sa->ah_key[0] = auth_key[0];
                                sa->ah_key[1] = auth_key[1];
                                sa->ah_key[2] = auth_key[2];
                        break;
                
                default : 
                        break;
        }

        sa->window = (Window*)malloc(sizeof(Window));
        memset(sa->window, 0x0, sizeof(Window));

        return sa;
}

bool sa_delete(SA* sa) {
	free(sa->window);
	free(sa);

	return true;
}
