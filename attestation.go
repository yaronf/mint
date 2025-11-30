package mint

import (
	"crypto/x509"
	"fmt"
)

// DeriveAttestationMainSecret derives the attestation main secret from the TLS master secret.
func DeriveAttestationMainSecret(
	params CipherSuiteParams,
	masterSecret []byte,
	transcriptHash []byte,
	isClient bool,
) []byte {
	label := "s attestation master"
	if isClient {
		label = "c attestation master"
	}
	return deriveSecret(params, masterSecret, label, transcriptHash)
}

// DeriveAttestationSecret derives the attestation secret (nonce) from attestation main secret.
func DeriveAttestationSecret(
	params CipherSuiteParams,
	attestationMainSecret []byte,
	publicKeyDER []byte,
) []byte {
	return deriveSecret(params, attestationMainSecret, "Early Attestation", publicKeyDER)
}

// MarshalPublicKeyToDER marshals a public key to DER format.
func MarshalPublicKeyToDER(publicKey interface{}) ([]byte, error) {
	derBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key to DER: %w", err)
	}
	return derBytes, nil
}
