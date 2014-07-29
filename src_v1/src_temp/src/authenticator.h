#ifndef __AUTHENTICATOR_H__
#define __AUTHENTICATOR_H__

#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <string.h>
#include <openssl/engine.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "ip.h"
#include "SA.h"

int hmac_md5_icv_check(IP* packet, SA* current_sa);
int hmac_md5_icv_calc(IP* packet, SA* current_sa);
#endif
