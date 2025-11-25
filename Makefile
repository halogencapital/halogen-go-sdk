eckey:
	mkdir -p .key/
	openssl ecparam -name prime256v1 -genkey -noout -out .key/ec_private_key.pem
	openssl req -new -key .key/ec_private_key.pem -out .key/ec_csr.pem -sha256 -subj "/C=MY/ST=Kuala Lumpur/L=Kuala Lumpur/O=Organization/OU=Unit/CN=example.com"

rsakey:
	mkdir -p .key/
	openssl req -new -newkey rsa:4096 -nodes -keyout .key/rsa_private_key.pem -out .key/rsa_csr.pem -subj "/C=MY/ST=Kuala Lumpur/L=Kuala Lumpur/O=Organization/OU=Unit/CN=example.com"

serve-documentation:
	pkgsite --http localhost:4444 --open .