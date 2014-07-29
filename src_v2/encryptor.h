#ifndef __ENCRYPTOR_H__
#define __ENCRYPTOR_H__

#include <openssl/des.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "esp.h"
#include "SA.h"
#include "ip.h"
#include "SPD.h"

#define PRINT printf
int des3_cbc_encrypt(IP* packet, SA* current_sa);

extern SP* current_sp;
#endif
