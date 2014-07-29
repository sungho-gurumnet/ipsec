#ifndef __COMMON_H__
#define __COMMON_H__

#include "SPD.h"
#include "SP.h"
#include "SAD.h"
#include "SA.h"

#include "ip.h"
#include "esp.h"
#include "checksum.h"

#include "encryptor.h"
#include "decryptor.h"
#include "authenticator.h"

#include <string.h>
#include <malloc.h>

#define _INPUT_
#define _DEBUG_

int outbound(IP* packet);
int inbound(IP* packet);

#endif
