package attestation

import (
	"crypto"

	"github.com/bifurcation/mint"
)

// DeriveAttestationMainSecret derives the attestation main secret from TLS master secret.
// This is part of the public API as applications may need it for custom providers.
//
// Parameters:
//   - hash: Hash function (e.g., crypto.SHA256)
//   - masterSecret: TLS master secret
//   - transcriptHash: Hash of messages up to ServerHello (h2)
//   - isClient: true for client attestation, false for server attestation
//
// Returns: c_attestation_main or s_attestation_main
func DeriveAttestationMainSecret(
	hash crypto.Hash,
	masterSecret []byte,
	transcriptHash []byte, // h2: hash of messages up to ServerHello
	isClient bool,
) []byte {
	label := "s attestation master"
	if isClient {
		label = "c attestation master"
	}
	// Use mint's internal HKDF function
	// We need to create a CipherSuiteParams to use deriveSecret
	// For now, we'll use a helper that directly calls HkdfExpandLabel
	return mint.HkdfExpandLabel(hash, masterSecret, label, transcriptHash, hash.Size())
}

// DeriveAttestationSecret derives the attestation secret (nonce) from attestation main secret.
// This is part of the public API as applications may need it for custom providers.
//
// Parameters:
//   - hash: Hash function (e.g., crypto.SHA256)
//   - attestationMainSecret: c_attestation_main or s_attestation_main
//   - publicKeyDER: TLS Identity Key public key in DER format
//
// Returns: c_attestation_secret or s_attestation_secret (the nonce)
func DeriveAttestationSecret(
	hash crypto.Hash,
	attestationMainSecret []byte,
	publicKeyDER []byte, // TLS Identity Key public key in DER format
) []byte {
	// Use HKDF-Expand-Label equivalent
	return mint.HkdfExpandLabel(hash, attestationMainSecret, "Early Attestation", publicKeyDER, hash.Size())
}
