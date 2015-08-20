# PacketNgin IPSec

## CLI

###COMMANDS

####Manage network interface ip
	ip -- Manage ip of network interface interface.
######SUB COMMANDS
	add [interface][address]-- Allocate ip to network interface.
	remove -- Free ip from network interface.

####Manage SP
	sp -- Manages SPD(Security Policy Database) entries in interface.
######SUB COMMANDS
	add [protocol][source][destination][action][index] -- Add security policy database entry.
	remove [interface][index] -- Remove SPD entry.
	list [interface] -- Print list of SPD entry.
######PARAMETERS
	-p Protocols
		Protocol specification.
		any -- TCP & UDP
		tcp -- TCP
		udp -- UDP

	-s [interface][@address][/mask][:port]
		Source specification.
		defalut address = any
		default mask = 24
		default port = any

	-d [interface][@address][/mask][:port]
		Destination specificiation.
		defalut address = any
		default mask = 24
		default port = any

	-a actions[/direction]
		ipsec -- IPSec action
		bypass -- Bypass action
		default action = bypass
		in -- in direction
		out -- out direction
		bi -- bidirectional
		default direction = bi

	-i index
		Index of entry.
		default index = 0

####Manages contents
	content -- Manages contents in SP.
######SUB COMMANDS
	add [interface][SP index]-- Add content to SP.
	remove [interface][SP index]-- Remove content from SP.
	list [interface][SP index]-- Print list of contents in SP.
######PARAMETERS
	-m mode
		tunnel -- tunnel mode
		transport -- transport mode

####Manage security association
	sa -- Manage SA(Security Association) entries.
######SUB COMMANDS
	add -- Add security association entry
	remove -- Remove security association entry
	list --List security association entry

######PARAMETERS
	-A authentication method[key: HEX][spi: HEX]
		hmac_md5
		hmac_sha1
		hmac_sha256
		hmac_sha384
		hmac_sha512
		hmac_sha384
		keyed_md5
		keyed_sha1
		aes_xcbc_mac
		tcp_md5

	-E encapsulating security payload method[key: HEX][spi: HEX]
		des_cbc
		3des_cbc
		blowfish_cbc
		cast128_cbc
		des_deriv
		3des_deriv
		rijndael_cbc
		twofish_cbc
		aes_ctr
		camellia_cbc

###EXAMPLES
	ip add eth0 192.168.10.254
	ip add eth1 192.168.11.254

	spd add -p tcp -s eth0 192.168.10.0/24 -d eth1 192.168.100.0/24 -a ipsec/bi
	spd add -p any -a bypass -i 1

	content add eth0
	sad add

# License

PacketNgin IPsec is distributed under GPL2 license.
