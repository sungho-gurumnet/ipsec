# PacketNgin IPSec

# CLI
	COMMAND BASIC FORMATS
	[command] [option]

	COMMANDS
		spd Security policy databse entry
			add -- Add security policy database entry
			remove -- Remove security policy database entry
			list -- List of security policy database entry

		content Security policy database entry's content
			add -- Add security policy databse entry content
			remove -- Remove security policy databse entry content
			list -- List security policy databse entry content

		sa Security association
			add -- Add security association entry
			remove -- Remove security association entry
			list --List security association entry
	
	PARAMETERS
		-i interface <U>number</U>

		-s address[/mask][:port]
			Source specification.

		-d address[/mask][:port]
			Destination specificiation.

		-p Protocols
			any -- TCP & UDP
			tcp -- TCP
			udp -- UDP

		-p Priority
			Priority of entry.

		-a Actions
			ipsec -- IPSec
			bypass -- Bypass

		-k Key

		-A Authentication Method
			hmac_md5
			hmac_sha1
			keyed_md5
			keyed_sha1
			hmac_sha256
			hmac_sha384
			hmac_sha512
			hmac_sha384
			aes_xcbc_mac
			tcp_md5

		-E Encapsulating Security Payload Method
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

	EXAMPLES

# License

PacketNgin IPsec is distributed under GPL2 license.
