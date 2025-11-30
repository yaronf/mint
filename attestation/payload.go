package attestation

import "github.com/fxamacker/cbor/v2"

// CMWPayload is the internal evidence structure that will be CBOR-encoded
// and wrapped in a Veraison CMW monad. This structure contains the attestation
// secret (nonce) and values used to derive it.
type CMWPayload struct {
	// Attestation secret (nonce) derived from TLS handshake (see Section 5.6)
	AttestationSecret []byte `cbor:"1,keyasint" json:"attestation_secret"`

	// Public key (TLS Identity Key) in DER format
	PublicKeyDER []byte `cbor:"2,keyasint" json:"public_key_der"`

	// Evidence type content format
	EvidenceType uint16 `cbor:"3,keyasint" json:"evidence_type"`
}

// encodePayload encodes the CMWPayload to CBOR format
func encodePayload(payload CMWPayload) ([]byte, error) {
	return cbor.Marshal(payload)
}

// decodePayload decodes a CBOR-encoded CMWPayload
func decodePayload(data []byte) (CMWPayload, error) {
	var payload CMWPayload
	err := cbor.Unmarshal(data, &payload)
	if err != nil {
		return payload, err
	}
	return payload, nil
}
