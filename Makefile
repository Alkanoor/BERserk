
check-message:
	nss/verify inputs/message certifs/signer.crt certifs/root.crt

check-spoof:
	nss/verify inputs/message certifs/spoof_signer.crt certifs/root.crt

generate:
	forgery_scripts/forge_signature.py inputs/message_a_signer.txt certifs/signature certifs/Alka.crt