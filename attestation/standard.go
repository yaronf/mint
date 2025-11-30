package attestation

import (
	"bytes"
	"crypto"
	"fmt"

	"github.com/bifurcation/mint"
	"github.com/veraison/cmw"
)

// EvidenceMediaType is the media type for TLS early attestation evidence
const EvidenceMediaType = "application/vnd.tls-early-attestation+cbor"

// StandardProvider implements the standard attestation format using Veraison CMW.
// This is the reference implementation per the RATS CMW spec.
type StandardProvider struct {
	hash crypto.Hash // Hash function for secret derivation
}

// NewStandardProvider creates a new StandardProvider with the given hash function.
func NewStandardProvider(hash crypto.Hash) *StandardProvider {
	return &StandardProvider{
		hash: hash,
	}
}

// GenerateEvidence creates attestation evidence for the given parameters.
// Returns opaque evidence bytes that will be sent in Attestation handshake message.
func (s *StandardProvider) GenerateEvidence(
	attestationMainSecret []byte,
	publicKeyDER []byte,
	evidenceType mint.EvidenceType,
	rotName string,
) ([]byte, error) {
	// 1. Derive attestation secret (nonce)
	attestationSecret := DeriveAttestationSecret(s.hash, attestationMainSecret, publicKeyDER)

	// 2. Create internal payload structure
	payload := CMWPayload{
		AttestationSecret: attestationSecret,
		PublicKeyDER:      publicKeyDER,
		EvidenceType:      evidenceType.ContentFormat,
		ROTName:           rotName,
	}

	// 3. CBOR-encode the payload
	payloadBytes, err := encodePayload(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to encode payload: %w", err)
	}

	// 4. Wrap in Veraison CMW monad
	cmwWrapper, err := cmw.NewMonad(EvidenceMediaType, payloadBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to create CMW: %w", err)
	}

	// 5. Encode CMW to CBOR
	evidenceBytes, err := cmwWrapper.MarshalCBOR()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal CMW: %w", err)
	}

	return evidenceBytes, nil
}

// VerifyEvidence verifies attestation evidence received from peer.
// Returns error if verification fails.
func (s *StandardProvider) VerifyEvidence(
	evidence []byte,
	attestationMainSecret []byte,
	publicKeyDER []byte,
	evidenceType mint.EvidenceType,
	trustedROTs []string,
) error {
	// 1. Decode CMW from CBOR
	var cmwWrapper cmw.CMW
	if err := cmwWrapper.UnmarshalCBOR(evidence); err != nil {
		return fmt.Errorf("failed to unmarshal CMW: %w", err)
	}

	// 2. Verify media type
	mediaType, err := cmwWrapper.GetMonadType()
	if err != nil {
		return fmt.Errorf("failed to get CMW media type: %w", err)
	}
	if mediaType != EvidenceMediaType {
		return fmt.Errorf("invalid media type: got %q, want %q", mediaType, EvidenceMediaType)
	}

	// 3. Extract payload bytes
	payloadBytes, err := cmwWrapper.GetMonadValue()
	if err != nil {
		return fmt.Errorf("failed to get CMW value: %w", err)
	}

	// 4. Decode payload
	payload, err := decodePayload(payloadBytes)
	if err != nil {
		return fmt.Errorf("failed to decode payload: %w", err)
	}

	// 5. Derive expected attestation secret
	expectedSecret := DeriveAttestationSecret(s.hash, attestationMainSecret, publicKeyDER)

	// 6. Verify attestation secret matches
	if !bytes.Equal(payload.AttestationSecret, expectedSecret) {
		return fmt.Errorf("attestation secret mismatch")
	}

	// 7. Verify public key matches
	if !bytes.Equal(payload.PublicKeyDER, publicKeyDER) {
		return fmt.Errorf("public key mismatch")
	}

	// 8. Verify evidence type matches (optional, but good to check)
	if payload.EvidenceType != evidenceType.ContentFormat {
		return fmt.Errorf("evidence type mismatch: got %d, want %d", payload.EvidenceType, evidenceType.ContentFormat)
	}

	// 9. Verify ROT name is in trusted list
	if len(trustedROTs) == 0 {
		return fmt.Errorf("no trusted ROTs configured")
	}
	rotTrusted := false
	for _, trustedROT := range trustedROTs {
		if payload.ROTName == trustedROT {
			rotTrusted = true
			break
		}
	}
	if !rotTrusted {
		return fmt.Errorf("ROT %q not in trusted list (trusted: %v)", payload.ROTName, trustedROTs)
	}

	return nil
}
