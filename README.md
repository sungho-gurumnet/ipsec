# PacketNgin IPSec

## CLI

###COMMAND BASIC FORMATS

	[command] [option]

###COMMANDS

####ip
	Manage network interface ip
######Sub command
	add -- allocate ip to network interface
	remove -- free ip from network interface
#####spd
	Manage security policy databse entry
######Sub command
	add -- Add security policy database entry
	remove -- Remove security policy database entry
	list -- List of security policy database entry

######Parameter
	-p Protocols
		Protocol specification.
		any -- TCP & UDP
		tcp -- TCP
		udp -- UDP

	-s address[/mask][:port][interface]
		Source specification.
		defalut address = any
		default mask = 24
		default port = any

	-d address[/mask][:port][interface]
		Destination specificiation.
		defalut address = any
		default mask = 24
		default port = any

	-a actions
		ipsec -- IPSec process
		bypass -- Bypass process
		default action = bypass

	-i index
		Index of entry.
		default index = 0

####content -- Manage security policy database entry's content
	add -- Add security policy databse entry content
	remove -- Remove security policy databse entry content
	list -- List security policy databse entry content

	sa -- Manage security association
		add -- Add security association entry
		remove -- Remove security association entry
		list --List security association entry

###PARAMETERS

	-S SPI(security parameter index)

	-A authentication method[key: HEX]
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

	-E encapsulating security payload method[key: HEX]
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
	spd add
	content add 
	sad add

# License

PacketNgin IPsec is distributed under GPL2 license.
