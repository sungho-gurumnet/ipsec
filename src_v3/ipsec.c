#include "ipsec.h"

// Setkey
#ifdef _TRANSPORT_

unsigned char in_packet[] = 
{
	0x45, 0x00, 0x00, 0x6c, 0x00, 0x00, 0x40, 0x00,
	0x40, 0x32, 0xb6, 0x10, 0xc0, 0xa8, 0x01, 0x01, 
	0xc0, 0xa8, 0x01, 0xfe, 0x00, 0x00, 0x02, 0x01,
	0x00, 0x00, 0x00, 0x01, 0xeb, 0x2e, 0xfb, 0x3c, 
	0x28, 0x18, 0x70, 0xc3, 0xe1, 0xff, 0x13, 0xa4, 
	0xf7, 0x37, 0x56, 0x34, 0x00, 0x63, 0x56, 0x9b, 
	0xd6, 0x10, 0xfc, 0x41, 0xe0, 0xc7, 0xe9, 0x55, 
	0x4d, 0xd3, 0xf9, 0xe3, 0xfa, 0xf1, 0x56, 0xb6, 
	0x3a, 0x19, 0x80, 0x06, 0x39, 0x26,	0xa3, 0xbe, 
	0x4d, 0xff, 0xbf, 0x9d, 0x89, 0xab, 0x36, 0xbe, 
	0x8f, 0x1b, 0xc1, 0xbf, 0x1e, 0xf2, 0x6d, 0xac, 
	0xb1, 0x4e, 0xba, 0x81, 0x07, 0x6b, 0xf0, 0x2a, 
	0xa4, 0x66, 0x42, 0xd0,	0x4c, 0xc2, 0x89, 0xfc, 
	0x67, 0xc8, 0x76, 0xd6
};

unsigned char out_packet[] = 
{
	0x45, 0x00, 0x00, 0x54, 0x00, 0x00, 0x40, 0x00,
	0x40, 0x01, 0xb6, 0x59, 0xc0, 0xa8, 0x01, 0x01,
	0xc0, 0xa8, 0x01, 0xfe, 0x08, 0x00, 0x26, 0x26,
	0x11, 0xaf, 0x00, 0x01, 0x0a, 0xff, 0x3b, 0x53,
	0x00, 0x00, 0x00, 0x00, 0xb4, 0x04, 0x07, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x10, 0x11, 0x12, 0x13,
	0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
	0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 
	0x24, 0x25,	0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b,
	0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33,
	0x34, 0x35, 0x36, 0x37
};

SP sp = 
{
	.src_ip 	  =	0xc0a864c8, //0xc0a80101, 192.168.100.200
	.dst_ip		  = 0xc0a8640a, //0xc0a801fe, 192.168.100.10
	.action       = IPSEC,
	.protocol 	  = IP_PROTOCOL_ESP,
	.mode		  = TRANSPORT,
	.direction    = IN,
	.upperspec	  = IP_PROTOCOL_ANY
};

SP sp2 = 
{
	.src_ip 	  = 0xc0a8640a,
	.dst_ip       = 0xc0a864c8, 
	.action	 	  = IPSEC,
	.protocol	  = IP_PROTOCOL_ESP,
	.mode 		  = TRANSPORT,
	.direction	  = OUT,
	.upperspec    = IP_PROTOCOL_ANY
};

SA sa = 
{
	.spi		 	   	  = 0x201,
	.protocol	 	  	  = IP_PROTOCOL_ESP,
	.src_ip   	   	   	  = 0xc0a864c8, //0xc0a80101, 192.168.100.200
	.dst_ip			      = 0xc0a8640a, //0xc0a801fe, 192.168.100.10
	.seq_counter 	   	  = 0,
	.mode 			  	  = TRANSPORT,
	.esp_crypto_algorithm = CRYPTO_3DES_CBC,
	.esp_crypto_key[0]	  = 0xaeaeaeaeaeaeaeae,
	.esp_crypto_key[1]	  = 0xaeaeaeaeaeaeaeae,
	.esp_crypto_key[2]	  = 0xaeaeaeaeaeaeaeae,
	.iv_mode 		      = 0, 
	.window 		      = &window,
	.direction 			  = IN,
};

SA sa2 = 
{
	.spi		 	      = 0x301,
	.protocol	 	      = IP_PROTOCOL_ESP,
	.src_ip   	   	      = 0xc0a8640a, //0xc0a80101,
	.dst_ip			      = 0xc0a864c8, //0xc0a801fe,
	.seq_counter 	      = 0,
	.mode 			      = TRANSPORT,
	.esp_crypto_algorithm = CRYPTO_3DES_CBC,
	.esp_crypto_key[0]    = 0xaeaeaeaeaeaeaeae,
	.esp_crypto_key[1]    = 0xaeaeaeaeaeaeaeae,
	.esp_crypto_key[2]    = 0xaeaeaeaeaeaeaeae,
	.iv_mode 		      = 0,
	.window 		      = &window,
	.direction		      = OUT,
};
#endif

// Tunnel Setting
#ifndef _TRANSPORT_

unsigned char out_packet[] = 
{
	0x45, 0x00,	0x00, 0x54, 0x00, 0x00, 0x40, 0x00, 
	0x40, 0x01,	0xdf, 0x88, 0xac, 0x10, 0x01, 0x00, 
	0xac, 0x10,	0x02, 0x00, 0x08, 0x00, 0x05, 0x59, 
	0x13, 0x6a,	0x00, 0x01, 0xb0, 0xe7, 0x70, 0x53, 
	0x00, 0x00,	0x00, 0x00, 0xf7, 0x2d, 0x08, 0x00, 
	0x00, 0x00,	0x00, 0x00, 0x10, 0x11, 0x12, 0x13, 
	0x14, 0x15,	0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 
	0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 
	0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 
	0x2c, 0x2d,	0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 
	0x34, 0x35, 0x36, 0x37
};

unsigned char in_packet[] = 
{
	0x45, 0x00, 0x00, 0x88, 0xf4, 0x94, 0x00, 0x00,
	0x40, 0x32, 0x00, 0x97, 0xc0, 0xa8, 0x02, 0x64,
	0xc0, 0xa8, 0x01, 0x64, 0x00, 0x00, 0x03, 0x01,
	0x00, 0x00, 0x00, 0x05, 0xad, 0xa5, 0x55, 0xa4,
	0xd6, 0x61, 0xe2, 0x96, 0x73, 0x5c, 0xe0, 0x66,
	0x06, 0x75, 0x2e, 0x5b, 0x33, 0xbe, 0x7d, 0xf2,
	0x19, 0x24, 0xd8, 0x4a, 0x1e, 0xd0, 0x21, 0xbd,
	0x16, 0x5d, 0x48, 0x03, 0xc1, 0xe4, 0xe1, 0x0e,
	0xb5, 0xf1, 0xc4, 0x4a, 0xa6, 0x3d, 0x6a, 0xef,
	0x6b, 0xdf, 0x0e, 0x46, 0x01, 0x22, 0x7d, 0xdd,
	0x37, 0x66, 0x4a, 0xd8, 0x94, 0xe1, 0x58, 0x40,
	0x1e, 0xe0, 0x9d, 0x0f, 0x9e, 0xeb, 0x2e, 0xf6,
	0x62, 0x31, 0xf4, 0xee, 0x4e, 0x7d, 0xfa, 0x85,
	0xdf, 0x23, 0x01, 0x2e, 0x1b, 0x27, 0x56, 0xb3,
	0x4a, 0x73, 0x89, 0x7c, 0x4d, 0x0b, 0xa7, 0xef,
	0xfe, 0x8a, 0x3f, 0x84, 0xc3, 0xf9, 0xb1, 0x37,
	0x86, 0xe9, 0x9e, 0x9c, 0x6d, 0xe4, 0x4c, 0xbe
};
#ifdef _GW2_
// For GW2
SP sp = 
{
	.src_ip 		 = 0xc0a86401, // 192.168.100.1
	.dst_ip			 = 0xc0a8c801, // 192.168.200.1
	.t_src_ip        = 0xac100001, // 172.16.0.1
	.t_dst_ip 		 = 0xac100002, // 172.16.0.2
	.action     	 = IPSEC,
	.protocol   	 = IP_PROTOCOL_ESP,
	.mode			 = TUNNEL,
	.direction  	 = OUT,
	.upperspec	     = IP_PROTOCOL_ANY
};

SP sp2 = 
{
	.src_ip 	 	= 0xc0a8c801, // 192.168.200.1
	.dst_ip 		= 0xc0a86401, // 192.168.100.1
	.t_src_ip       = 0xac100002, // 172.16.0.2
	.t_dst_ip	 	= 0xac100001, // 172.16.0.1
	.action	 		= IPSEC,
	.protocol		= IP_PROTOCOL_ESP,
	.mode 			= TUNNEL,
	.direction		= IN
	.upperspec	     = IP_PROTOCOL_ANY
};

SA sa = 
{
	.spi		 		    = 0x201,
	.protocol   		    = IP_PROTOCOL_ESP,
	.mode 				    = TUNNEL,
	.src_ip  			    = 0xac100001, // 172.16.0.1
	.dst_ip 	  		    = 0xac100002, // 172.16.0.2
	.seq_counter 		    = 0,
	.esp_crypto_algorithm   = CRYPTO_3DES_CBC,
	.esp_crypto_key[0]	    = 0xaeaeaeaeaeaeaeae,
	.esp_crypto_key[1] 	    = 0xaeaeaeaeaeaeaeae,
	.esp_crypto_key[2]	    = 0xaeaeaeaeaeaeaeae,
	.esp_auth_key[0] 	    = 0xc0291ff014dccdd0,
	.esp_auth_key[1] 	    = 0x3874d9e8e4cdf3e6,
	.iv_mode			    = 0,
	.direction			    = IN
};

SA sa2 = 
{
	.spi				    = 0x301,
	.protocol			    = IP_PROTOCOL_ESP,
	.mode				    = TUNNEL,
	.src_ip				    = 0xac100002, // 172.16.0.2
	.dst_ip				    = 0xac100001, // 172.16.0.1
	.seq_counter		    = 0,
	.esp_crypto_algorithm   = CRYPTO_3DES_CBC,
	.esp_crypto_key[0]	    = 0xaeaeaeaeaeaeaeae,
	.esp_crypto_key[1]		= 0xaeaeaeaeaeaeaeae,
	.esp_crypto_key[2]		= 0xaeaeaeaeaeaeaeae,
	.ah_key[0]				= 0x96358c90783bbfa3,
	.ah_key[1]				= 0xd7b196ceabe0536b,
	.iv_mode				= 0,
	.direction				= OUT 
};
#endif

#ifdef _GW1_
// For GW1
Window window;

SP sp = 
{
	.src_ip 		 = 0xc0a8c801, // 192.168.200.1
	.dst_ip			 = 0xc0a86401, // 192.168.100.1
	.t_src_ip        = 0xac100001, // 172.16.0.1
	.t_dst_ip 		 = 0xac100002, // 172.16.0.2
	.src_mask 		 = 0xffffff00,
	.dst_mask        = 0xffffff00,
	.action     	 = IPSEC,
	.protocol   	 = IP_PROTOCOL_ESP,
	.mode			 = TUNNEL,
	.direction  	 = OUT,
	.upperspec   	 = IP_PROTOCOL_ANY
};

SP sp2 = 
{
	.src_ip 	 	= 0xc0a86401, // 192.168.100.1
	.dst_ip 		= 0xc0a8c801, // 192.168.200.1
	.t_src_ip       = 0xac100002, // 172.16.0.2
	.t_dst_ip	 	= 0xac100001, // 172.16.0.1
	.src_mask 		= 0xffffff00,
	.dst_mask       = 0xffffff00,
	.action	 		= IPSEC,
	.protocol		= IP_PROTOCOL_ESP,
	.mode 			= TUNNEL,
	.direction		= IN,
	.upperspec 		= IP_PROTOCOL_ANY
};

SA sa = 
{
	.spi		 		    = 0x201,
	.protocol   		    = IP_PROTOCOL_ESP,
	.mode 				    = TUNNEL,
	.src_ip  			    = 0xac100001, // 172.16.0.1
	.dst_ip 	  		    = 0xac100002, // 172.16.0.2
	.esp_crypto_algorithm   = CRYPTO_3DES_CBC,
	.esp_crypto_key[0]	    = 0xaeaeaeaeaeaeaeae,
	.esp_crypto_key[1] 	    = 0xaeaeaeaeaeaeaeae,
	.esp_crypto_key[2]	    = 0xaeaeaeaeaeaeaeae, 
	.esp_auth_key[0] 	    = 0xaeaeaeaeaeaeaeae,
	.esp_auth_key[1] 	    = 0xaeaeaeaeaeaeaeae,
	.iv_mode			    = 0,
	.window 				= &window
};

SA sa2 = 
{
	.spi				    = 0x301,
	.protocol			    = IP_PROTOCOL_ESP,
	.mode				    = TUNNEL,
	.src_ip				    = 0xac100002, // 172.16.0.2
	.dst_ip				    = 0xac100001, // 172.16.0.1
	.esp_crypto_algorithm   = CRYPTO_3DES_CBC,
	.esp_crypto_key[0]	    = 0xaeaeaeaeaeaeaeae,
	.esp_crypto_key[1]		= 0xaeaeaeaeaeaeaeae,
	.esp_crypto_key[2]		= 0xaeaeaeaeaeaeaeae,
	.ah_key[0]				= 0x96358c90783bbfa3,
	.ah_key[1]				= 0xd7b196ceabe0536b,
	.iv_mode				= 0,
	.window					= &window
};
#endif /* __GW1__ */
#endif /* __TRANPORT__ */

void init_list()
{
	SP* sp_header_node = (SP*)malloc(sizeof(SP));
	SA* sa_header_node = (SA*)malloc(sizeof(SA));

	spd.sp_list = sp_header_node;
	sad.sa_list = sa_header_node;
	
	INIT_LIST_HEAD(&((spd.sp_list)->list));
	INIT_LIST_HEAD(&((sad.sa_list)->list));

	sa.bundle_list = &sa;
	sa2.bundle_list = &sa2;

	INIT_LIST_HEAD(&((sa.bundle_list)->list));
	INIT_LIST_HEAD(&((sa2.bundle_list)->list));

	sp.sa_pointer = &sa;
	sp2.sa_pointer = &sa2;

	list_add_head(&sp.list, &((spd.sp_list)->list));
	list_add_head(&sp2.list, &((spd.sp_list)->list));
	list_add_head(&sa.list, &((sad.sa_list)->list));
	list_add_head(&sa2.list, &((sad.sa_list)->list));

}

int decrypt(IP* packet)
{
	int size; 
	current_sa = NULL;
	current_sp = NULL;
	ESP* esp;
	IP* ip;

	printf("Decrypt Processing : \n");

	// 1. SAD Lookup
	if((current_sa = getSA(packet)) == NULL)
	{
		printf(" 1. SAD Lookup : Discard packet \n");
	
		return -1;
	}
	
	current_sa->crypto = get_cryptography(current_sa->esp_crypto_algorithm);
	current_sa->auth = get_authentication(current_sa->esp_auth_algorithm);

	// 2. Seq# Validation
	esp = (ESP*)packet->body;

	if(checkWindow(current_sa->window, esp->seq_num) < 0)
	{
		printf(" 2. Seq# Validation : Dicard Packet \n");

		return -1;
	}

	// 3. ICV Validation
	if(current_sa->iv_mode == true)
	{
		size = endian16(packet->length) - (packet->ihl * 4) - ICV_LEN; 

		unsigned char* result = &(packet->body[size]);
		
		((Authentication*)(current_sa->auth))->authenticate(packet, size, result);
	
		if(memcmp(result, &(packet->body[size]), 12) != 0)
		{
			printf(" 3. ICV Validation : Discard Packet \n");
			
			return -1;
		}
	}

	switch(current_sa->protocol)
	{
		case IP_PROTOCOL_ESP :
			// 4. Decrypt
			size = endian16(packet->length) - (packet->ihl * 4) - ESP_HEADER_LEN; 
			
			if(current_sa->iv_mode == true)
				size -= ICV_LEN;
			
			((Cryptography*)(current_sa->crypto))->decrypt(esp, size); 
			
			// 5. ESP Header & Trailer Deletion
			int packet_protocol;
			int packet_len = endian16(packet->length) - ESP_HEADER_LEN - esp->body[size - 2] /* Padding */ - ESP_TRAILER_LEN;
			
			if(current_sa->mode == TRANSPORT)
			{
				packet_protocol = esp->body[size - 1];
				memmove(packet->body, esp->body, size);
			}
			else if(current_sa->mode == TUNNEL)
			{
				ip = (IP*)esp->body;
				packet_protocol = ip->protocol;
				packet_len -= (packet->ihl * 4);
				memmove(packet, esp->body, size);
			}
			
			packet->protocol = packet_protocol;
			packet->length = endian16(packet_len);
			
			if(current_sa->iv_mode == true) 
				packet->length += endian16(ICV_LEN);
			
			break;
		
		case IP_PROTOCOL_AH : 	
			break;
		default : break;
	}
	
	// 6. SPD Lookup 
	if((current_sp = getSP(packet)) == NULL)
	{
		printf(" 6. SPD Lookup : Discard packet \n");

		return -1;
	}


	Ether* ether1 = (Ether*)malloc(250);
	memmove(ether1->payload, packet, 250) ; 
	int i;
	// Print protected Packet 	
	printf("Decrypted Packet : \n");
	for(i = 1; i < 1 + endian16(packet->length); i++)
	{
		printf("%02x ", ether1->payload[i - 1]); // Packet - IP Header 
		if( i % 16 == 0 )
			printf("\n");
	}
	printf("\n");

	free(ether1);
	
	return 0;
}

int encrypt(IP* packet)
{
	int size, body_len, padding_len, i;
	unsigned char* padding = NULL;
	current_sp = NULL;
	current_sa = NULL;

	printf("Encrypt Processing : \n");
	
	// 1. SPD Lookup
	if((current_sp = getSP(packet)) == NULL)
	{
		printf(" 1. SPD Lookup : Bypass packet\n");
		
		return -1;
	}

	// 2. SAD Lookup
	if((current_sa = findSA(current_sp->sa_pointer, current_sp, packet)) == NULL)
	{
		printf(" 2. SAD check : Discard packet\n");
		
		return -1;
	}
	current_sa->crypto = get_cryptography(current_sa->esp_crypto_algorithm);
	current_sa->auth = get_authentication(current_sa->esp_auth_algorithm);

	switch(current_sa->protocol)
	{
		case IP_PROTOCOL_ESP :
			// 3. ESP Trailer Addition & Encrypt
			body_len = endian16(packet->length) - (packet->ihl * 4);
		
			if(current_sa->mode == TRANSPORT)
			{
				padding_len = (ESP_HEADER_LEN + body_len + 2) % 8;
				if(padding_len != 0)
					padding_len = 8 - (ESP_HEADER_LEN + body_len + 2) % 8;
			}
			else if(current_sa->mode == TUNNEL)
			{
				padding_len = (packet->ihl * 4 + ESP_HEADER_LEN + body_len + 2) % 8;
				if(padding_len != 0)
					padding_len = 8 - (packet->ihl * 4 + ESP_HEADER_LEN + body_len + 2) % 8;
			}

			padding = packet->body + body_len;
			
			for(i = 0; i < padding_len; i++)
				padding[i] = i + 1;
			
			packet->body[body_len + padding_len + 1] = packet->protocol;
			packet->body[body_len + padding_len] = padding_len;

			size = body_len + padding_len + 2;
			
			if(current_sa->mode == TUNNEL)
			{
				//  3.1 Inner IP Addition
				packet->ttl--;
				packet->checksum = 0;
				packet->checksum = endian16(checksum(packet, packet->ihl * 4));

				packet->body[body_len + padding_len + 1] = IP_PROTOCOL_IPV4;

				memmove(packet->body, packet, endian16(packet->length) + padding_len + ESP_TRAILER_LEN);
				// TODO : Hop Limit Check

				size += packet->ihl * 4;
			}
	
			((Cryptography*)(current_sa->crypto))->encrypt(packet->body, size);		
	
			// 4. IP Header Change & ESP Header Addition
			packet->protocol = IP_PROTOCOL_ESP;
			packet->length = endian16(endian16(packet->length) + ESP_HEADER_LEN + ESP_TRAILER_LEN + padding_len);
			
			//  4.1 IP Header Change
			if(current_sa->mode == TRANSPORT)
			{
				packet->source = endian32(packet->destination);
				packet->destination = endian32(packet->source);
			}
			else if(current_sa->mode == TUNNEL)
			{
				packet->length = endian16(endian16(packet->length) + packet->ihl * 4);
				packet->source = endian32(current_sp->t_src_ip);
				packet->destination = endian32(current_sp->t_dst_ip);
			}

			if(current_sa->iv_mode == true) 
				packet->length += endian16(ICV_LEN);
			
			packet->ttl = endian8(64);
			packet->checksum = 0;
			packet->checksum = endian16(checksum(packet, packet->ihl * 4));
			
			// 4.2 ESP Header Addition
			memmove(packet->body + ESP_HEADER_LEN, packet->body, endian16(packet->length));
			
			ESP* esp = (ESP*)packet->body;
			esp->spi = endian32(current_sa->spi);
			esp->iv = current_sa->iv;	
			
			// 5. Seq# Validation 
			esp->seq_num = endian32(++current_sa->window->seq_counter);
			// TODO : Seq# Overflow Check
			
			// 6. ICV Calculation
			if(current_sa->iv_mode == true)
			{
				size = endian16(packet->length) - (packet->ihl * 4) - ICV_LEN; 
				unsigned char* result = &(packet->body[size]);
				
				((Authentication*)(current_sa->auth))->authenticate(packet, size, result);
			}
			break;
		case IP_PROTOCOL_AH :
			break;
		default : 
			break;
	}
	
	// Print protected IP 
	printf("Encrypted Packet : \n");

	Ether* ether = (Ether*)malloc(250);
	memmove(ether->payload, packet, 250) ; 
	
	for(i = 1; i < 1 + endian16(packet->length); i++) 
		// (ESP) + (Inner IP)(optional) + (ICV)
	{
		printf("%02x ", ether->payload[i - 1]); // Packet - IP Header 
		if( i % 16 == 0 )
			printf("\n");
	}
	printf("\n");
	free(ether);

	return 0;
}

