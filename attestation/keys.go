package attestation

import (
	"crypto/x509"
	"fmt"
)

// MarshalPublicKeyToDER marshals a public key to DER format.
// Supports RSA, ECDSA, and Ed25519 keys.
func MarshalPublicKeyToDER(publicKey interface{}) ([]byte, error) {
	// Use x509.MarshalPKIXPublicKey which produces DER format
	derBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key to DER: %w", err)
	}
	return derBytes, nil
}
