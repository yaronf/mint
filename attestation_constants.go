package mint

// Temporary constants for early attestation (TBD values)
// These will be replaced with IANA-assigned values once the draft is finalized

const (
	// Handshake message type
	HandshakeTypeAttestation HandshakeType = 100 // Temporary, replace with IANA value

	// Extension types
	ExtensionTypeEvidenceRequest  ExtensionType = 0xFA00 // Temporary
	ExtensionTypeEvidenceProposal ExtensionType = 0xFA01 // Temporary
	// Note: results_request and results_proposal not implemented in initial version
	// ExtensionTypeResultsRequest    ExtensionType = 0xFA02  // Temporary
	// ExtensionTypeResultsProposal   ExtensionType = 0xFA03  // Temporary

	// Alert type
	AlertUnsupportedEvidenceValue Alert = 121 // Temporary for early attestation
)
