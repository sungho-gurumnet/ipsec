bool tunnel_set(Packet* packet, uint16_t header_len, uint16_t tail_len);
bool transport_set(Packet* packet, uint16_t header_len, uint16_t tail_len);
bool tunnel_unset(Packet* packet, uint16_t header_len, uint16_t tail_len);
bool transport_unset(Packet* packet, uint16_t header_len, uint16_t tail_len);
