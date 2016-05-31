
check-message:
	nss/verify inputs/message certifs/signer.crt certifs/root.crt

check-spoof:
	nss/verify inputs/message certifs/spoof_signer.crt certifs/root.crt
	