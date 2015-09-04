# PacketNgin IPSec

## CLI

###COMMANDS

####Manage network interface ip
	ip -- Manage ip of network interface interface.
######SUB COMMANDS
	add [interface][address]-- Allocate ip to network interface.
	remove -- Free ip from network interface.

####Manage network interface ip
	route -- Manage ip of network interface interface.
######SUB COMMANDS
	add [interface][address]-- Allocate ip to network interface.
	remove [interface][address]-- Free ip from network interface.
######PARAMETERS
	-g gateway
	-m mask
		Mas specification.
		default 24

####Manage Security policy
	sp -- Manages SPD(Security Policy Database) entries in interface.
######SUB COMMANDS
	add [interface][protocol][source][destination][action][index] -- Add SP.
	remove [interface][index] -- Remove SP.
	list [interface] -- Print list of SP.
######PARAMETERS
	-p Protocols
		Protocol specification.
		any -- TCP & UDP
		tcp -- TCP
		udp -- UDP
		default protocol = any

	-s [address][/mask][:port]
		Source specification.
		defalut address = any
		default mask = 32
		default port = any

	-d [address][/mask][:port]
		Destination specificiation.
		defalut address = any
		default mask = 24
		default port = any

	-a actions[/direction]
		ipsec -- IPSec action
		bypass -- Bypass action
		default action = bypass
		out -- out bound
		in -- in bound
		default direction = out

	-i index
		Index of entry.
		default index = 0

	-o out network interface

####Manages contents
	content -- Manages contents in SP.
######SUB COMMANDS
	add [interface][SP index]-- Add content to SP.
	remove [interface][SP index]-- Remove content from SP.
	list [interface][SP index]-- Print list of contents in SP.
######PARAMETERS
	-m mode
		tunnel[source address-destination address] -- tunnel mode
		transport -- transport mode

	-E encapsulating security payload method[key: HEX][spi: HEX]
		des_cbc -- key length: 8 Bytes
		3des_cbc -- key length: 24 Bytes
		blowfish_cbc -- key length: 5 ~ 56 Bytes
		cast128_cbc -- key length: 5 ~ 56 Bytes
		rijndael_cbc -- key length: 16, 24, 32 Bytes
		camellia_cbc -- key length: 16, 24, 32 Bytes
		aes_ctr -- key length: 16
		twofish_cbc -- not yet support
		des_deriv -- not yet support
		3des_deriv -- not yet support

	-A authentication method[key: HEX][spi: HEX]
		hmac_md5 -- key length: 16 Bytes
		hmac_sha1 -- key length: 20 Bytes
		hmac_sha256 -- key length: 32 Bytes
		hmac_sha384 -- key length: 48 Bytes
		hmac_sha512 -- key length: 64 Bytes
		hmac_ripemd160 -- key length: 20 Bytes
		keyed_md5 -- not yet support
		keyed_sha1 -- not yet support
		aes_xcbc_mac -- not yet support
		tcp_md5 -- not yet support

	-i index
		Index of entry.
		default index = 0

####Manage security association
	sa -- Manage SA(Security Association) entries.
######SUB COMMANDS
	add [interface] -- Add security association entry
	remove [interface] -- Remove security association entry
	list [interface] --List security association entry

######PARAMETERS
	-p Protocols
		Protocol specification.
		any -- TCP & UDP
		tcp -- TCP
		udp -- UDP
		default protocol = any

	-s [address][/mask][:port]
		Source specification.
		defalut address = any
		default mask = 32
		default port = any

	-d [address][/mask][:port]
		Destination specificiation.
		defalut address = any
		default mask = 24
		default port = any

	-E encapsulating security payload method[key: HEX][spi: HEX]
		des_cbc -- key length: 8 Bytes
		3des_cbc -- key length: 24 Bytes
		blowfish_cbc -- key length: 5 ~ 56 Bytes
		cast128_cbc -- key length: 5 ~ 56 Bytes
		rijndael_cbc -- key length: 16, 24, 32 Bytes
		camellia_cbc -- key length: 16, 24, 32 Bytes
		aes_ctr -- key length: 16
		twofish_cbc -- not yet support
		des_deriv -- not yet support
		3des_deriv -- not yet support

	-A authentication method[key: HEX][spi: HEX]
		hmac_md5 -- key length: 16 Bytes
		hmac_sha1 -- key length: 20 Bytes
		hmac_sha256 -- key length: 32 Bytes
		hmac_sha384 -- key length: 48 Bytes
		hmac_sha512 -- key length: 64 Bytes
		hmac_ripemd160 -- key length: 20 Bytes
		keyed_md5 -- not yet support
		keyed_sha1 -- not yet support
		aes_xcbc_mac -- not yet support
		tcp_md5 -- not yet support

###EXAMPLES
	ip add eth0 192.168.10.254
	ip add eth1 192.168.11.254

	spd add -p tcp -s eth0 192.168.10.0/24 -d eth1 192.168.100.0/24 -a ipsec/bi
	spd add -p any -a bypass -i 1

	content add eth0
	sad add

# License

PacketNgin IPsec is distributed under GPL2 license.
