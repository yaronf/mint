package attestation

import "github.com/bifurcation/mint"

// AttestationProvider defines the interface for generating and verifying attestation evidence
type AttestationProvider interface {
	// GenerateEvidence creates attestation evidence for the given parameters
	// Returns opaque evidence bytes that will be sent in Attestation handshake message
	GenerateEvidence(
		attestationMainSecret []byte, // Derived from TLS master secret
		publicKeyDER []byte, // TLS Identity Key in DER format
		evidenceType mint.EvidenceType, // Selected evidence type
		rotName string, // Root of Trust name that signs this evidence
	) ([]byte, error)

	// VerifyEvidence verifies attestation evidence received from peer
	// Returns error if verification fails
	VerifyEvidence(
		evidence []byte, // Evidence received from peer
		attestationMainSecret []byte, // Derived from TLS master secret
		publicKeyDER []byte, // TLS Identity Key in DER format
		evidenceType mint.EvidenceType, // Selected evidence type
		trustedROTs []string, // List of trusted Root of Trust names
	) error
}
