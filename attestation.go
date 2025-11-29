package mint

import (
	"crypto/x509"
	"encoding/json"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// CMWPayload represents a simplified CMW (Conceptual Message Wrapper) structure
// for mock attestation evidence. Contains attestation secret (nonce) and values
// used to derive it.
type CMWPayload struct {
	// Attestation secret (nonce) derived from TLS handshake (see Section 5.6)
	AttestationSecret []byte `cbor:"1,keyasint" json:"attestation_secret"`

	// Public key (TLS Identity Key) in DER format
	// TODO: Verify DER format is correct per spec
	PublicKeyDER []byte `cbor:"2,keyasint" json:"public_key_der"`

	// Additional metadata for logging/debugging
	EvidenceType uint16 `cbor:"3,keyasint" json:"evidence_type"`
}

// DeriveAttestationMainSecret derives the attestation main secret
// from the TLS master secret according to Section 5.6 of the spec.
//
// Parameters:
//   - params: Cipher suite parameters
//   - masterSecret: TLS master secret
//   - transcriptHash: Hash of messages up to ServerHello (h2)
//   - isClient: true for client attestation, false for server attestation
//
// Returns: c_attestation_main or s_attestation_main
func DeriveAttestationMainSecret(
	params CipherSuiteParams,
	masterSecret []byte,
	transcriptHash []byte, // h2: hash of messages up to ServerHello
	isClient bool,
) []byte {
	label := "s attestation master"
	if isClient {
		label = "c attestation master"
	}
	return deriveSecret(params, masterSecret, label, transcriptHash)
}

// DeriveAttestationSecret derives the attestation secret (nonce) from
// the attestation main secret according to Section 5.6 of the spec.
//
// Parameters:
//   - params: Cipher suite parameters
//   - attestationMainSecret: c_attestation_main or s_attestation_main
//   - publicKeyDER: TLS Identity Key public key in DER format
//
// Returns: c_attestation_secret or s_attestation_secret (the nonce)
func DeriveAttestationSecret(
	params CipherSuiteParams,
	attestationMainSecret []byte,
	publicKeyDER []byte, // TLS Identity Key public key in DER format
) []byte {
	// TODO: Verify public key format (DER) is correct per spec
	// Use HKDF-Expand-Label equivalent (deriveSecret uses HKDF-Expand-Label internally)
	return deriveSecret(params, attestationMainSecret, "Early Attestation", publicKeyDER)
}

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

// LogCMWAsJSON logs the CMW payload as structured JSON for debugging.
func LogCMWAsJSON(cmw CMWPayload, prefix string) {
	cmwJSON, err := json.MarshalIndent(cmw, "", "  ")
	if err != nil {
		logf(logTypeHandshake, "%s Failed to marshal CMW to JSON: %v", prefix, err)
		return
	}
	logf(logTypeHandshake, "%s CMW: %s", prefix, string(cmwJSON))
}

// EncodeCMWToCBOR encodes a CMW payload to CBOR format.
func EncodeCMWToCBOR(cmw CMWPayload) ([]byte, error) {
	return cbor.Marshal(cmw)
}

// DecodeCMWFromCBOR decodes a CBOR-encoded CMW payload.
func DecodeCMWFromCBOR(data []byte) (CMWPayload, error) {
	var cmw CMWPayload
	err := cbor.Unmarshal(data, &cmw)
	if err != nil {
		return cmw, fmt.Errorf("failed to decode CMW from CBOR: %w", err)
	}
	return cmw, nil
}
