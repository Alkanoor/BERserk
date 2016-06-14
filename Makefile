
check-message:
	nss/verify inputs/message certifs/signer.crt certifs/root.crt

check-spoof:
	nss/verify inputs/message certifs/spoof_signer.crt certifs/root.crt

forge:
	final/forge_verify.py final/to_sign final/rsa_e_3