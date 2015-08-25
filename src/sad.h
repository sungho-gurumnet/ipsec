#ifndef __sad_H__
#define __sad_H__

#include <stdbool.h>

#include "sa.h"

#define	SAD	"net.ipsec.sad"

Map* sad_get(NetworkInterface* ni);
void sad_remove_all(NetworkInterface* ni);
SA* sad_get_sa(NetworkInterface* ni, uint32_t spi, uint32_t dst_ip, uint8_t protocol);
bool sad_add_sa(NetworkInterface* ni, SA* sa);
SA* sad_remove_sa(NetworkInterface* ni, uint32_t spi, uint32_t dest_ip, uint8_t protocol);
#endif
