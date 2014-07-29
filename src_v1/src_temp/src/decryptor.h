#ifndef __DECRYPTOR_H__
#define __DECRYPTOR_H__

#include <openssl/des.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "esp.h"
#include "SA.h"
#include "ip.h"

int des3_cbc_decrypt(IP* packet, SA* current_sa);

#endif
