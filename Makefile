
set-up:
	openssl genrsa -out rsa_e_3 -3 2048

forge:
	./forge_verify.py ./to_sign.txt ./rsa_e_3
