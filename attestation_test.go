package mint

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"testing"
	"time"
)

// testAttestationProvider creates evidence compatible with the attestation package.
// It uses mint's DeriveAttestationSecret and creates a simple CBOR payload.
// Note: This is a test-only provider. Production code should use attestation.NewStandardProvider().
type testAttestationProvider struct{}

func newTestAttestationProvider() *testAttestationProvider {
	return &testAttestationProvider{}
}

func (t *testAttestationProvider) GenerateEvidence(attestationMainSecret []byte, publicKeyDER []byte, evidenceType EvidenceType, rotName string) ([]byte, error) {
	// Use mint's DeriveAttestationSecret (which matches attestation package logic)
	params := cipherSuiteMap[TLS_AES_128_GCM_SHA256]
	attestationSecret := DeriveAttestationSecret(params, attestationMainSecret, publicKeyDER)

	// Create minimal CBOR-encoded payload manually (to avoid CBOR dependency in main module)
	// CBOR encoding for map with 4 entries: {1: attestationSecret, 2: publicKeyDER, 3: evidenceType, 4: rotName}
	// This is a simplified encoding - production should use attestation package
	var result []byte
	// CBOR map header: 0xa4 = map with 4 pairs
	result = append(result, 0xa4)
	// Key 1 (uint): 0x01
	result = append(result, 0x01)
	// Value: byte string with attestationSecret
	result = append(result, byte(0x58), byte(len(attestationSecret)))
	result = append(result, attestationSecret...)
	// Key 2 (uint): 0x02
	result = append(result, 0x02)
	// Value: byte string with publicKeyDER
	result = append(result, byte(0x58), byte(len(publicKeyDER)))
	result = append(result, publicKeyDER...)
	// Key 3 (uint): 0x03
	result = append(result, 0x03)
	// Value: uint16 evidenceType
	result = append(result, 0x19, byte(evidenceType.ContentFormat>>8), byte(evidenceType.ContentFormat&0xff))
	// Key 4 (uint): 0x04
	result = append(result, 0x04)
	// Value: text string with rotName
	rotNameBytes := []byte(rotName)
	result = append(result, byte(0x78), byte(len(rotNameBytes)>>8), byte(len(rotNameBytes)&0xff))
	result = append(result, rotNameBytes...)

	return result, nil
}

func (t *testAttestationProvider) VerifyEvidence(evidence []byte, attestationMainSecret []byte, publicKeyDER []byte, evidenceType EvidenceType, trustedROTs []string) error {
	// Simple verification - just check that we can parse the structure
	// For proper verification, use attestation package StandardProvider
	if len(evidence) < 10 {
		return fmt.Errorf("evidence too short")
	}

	params := cipherSuiteMap[TLS_AES_128_GCM_SHA256]
	expectedSecret := DeriveAttestationSecret(params, attestationMainSecret, publicKeyDER)

	// Parse CBOR manually (simplified - just verify secret matches and ROT is trusted)
	// This is test-only code - production should use attestation package
	idx := 1 // Skip map header
	if idx >= len(evidence) || evidence[idx] != 0x01 {
		return fmt.Errorf("invalid CBOR structure")
	}
	idx++
	if idx >= len(evidence) || evidence[idx] != 0x58 {
		return fmt.Errorf("invalid secret encoding")
	}
	idx++
	if idx >= len(evidence) {
		return fmt.Errorf("invalid secret length")
	}
	secretLen := int(evidence[idx])
	idx++
	if idx+secretLen > len(evidence) {
		return fmt.Errorf("secret length mismatch")
	}
	secret := evidence[idx : idx+secretLen]

	if len(secret) != len(expectedSecret) {
		return fmt.Errorf("secret length mismatch")
	}
	for i := range secret {
		if secret[i] != expectedSecret[i] {
			return fmt.Errorf("secret mismatch")
		}
	}

	// Parse and verify public key (key 2)
	idx += secretLen
	if idx >= len(evidence) || evidence[idx] != 0x02 {
		return fmt.Errorf("invalid CBOR structure (key 2)")
	}
	idx++
	if idx >= len(evidence) || evidence[idx] != 0x58 {
		return fmt.Errorf("invalid public key encoding")
	}
	idx++
	if idx >= len(evidence) {
		return fmt.Errorf("invalid public key length")
	}
	publicKeyLen := int(evidence[idx])
	idx++
	if idx+publicKeyLen > len(evidence) {
		return fmt.Errorf("public key length mismatch")
	}
	publicKeyFromEvidence := evidence[idx : idx+publicKeyLen]
	// Verify public key matches
	if !bytes.Equal(publicKeyFromEvidence, publicKeyDER) {
		return fmt.Errorf("public key mismatch")
	}
	idx += publicKeyLen
	// Skip key 3
	if idx >= len(evidence) || evidence[idx] != 0x03 {
		return fmt.Errorf("invalid CBOR structure (key 3)")
	}
	idx++
	// Skip evidence type (uint16 = 3 bytes: 0x19 + 2 bytes)
	idx += 3
	// Now at key 4
	if idx >= len(evidence) || evidence[idx] != 0x04 {
		return fmt.Errorf("invalid CBOR structure (key 4)")
	}
	idx++
	// Parse text string (0x78 = text string with 2-byte length)
	if idx >= len(evidence) || evidence[idx] != 0x78 {
		return fmt.Errorf("invalid ROT name encoding")
	}
	idx++
	if idx+2 > len(evidence) {
		return fmt.Errorf("invalid ROT name length")
	}
	rotNameLen := int(evidence[idx])<<8 | int(evidence[idx+1])
	idx += 2
	if idx+rotNameLen > len(evidence) {
		return fmt.Errorf("ROT name length mismatch")
	}
	rotName := string(evidence[idx : idx+rotNameLen])

	// Verify ROT is trusted
	if len(trustedROTs) == 0 {
		return fmt.Errorf("no trusted ROTs configured")
	}
	rotTrusted := false
	for _, trustedROT := range trustedROTs {
		if rotName == trustedROT {
			rotTrusted = true
			break
		}
	}
	if !rotTrusted {
		return fmt.Errorf("ROT %q not in trusted list", rotName)
	}

	return nil
}

// badAttestationProvider wraps a good provider but corrupts evidence generation/verification
type badAttestationProvider struct {
	goodProvider *testAttestationProvider
	corruption   string // "wrong_secret", "wrong_public_key", "wrong_evidence_type", "invalid_cbor", "too_short"
}

func newBadAttestationProvider(corruption string) *badAttestationProvider {
	return &badAttestationProvider{
		goodProvider: newTestAttestationProvider(),
		corruption:   corruption,
	}
}

func (b *badAttestationProvider) GenerateEvidence(attestationMainSecret []byte, publicKeyDER []byte, evidenceType EvidenceType, rotName string) ([]byte, error) {
	// Generate valid evidence first
	evidence, err := b.goodProvider.GenerateEvidence(attestationMainSecret, publicKeyDER, evidenceType, rotName)
	if err != nil {
		return nil, err
	}

	// Corrupt based on corruption type
	switch b.corruption {
	case "wrong_secret":
		// Corrupt the attestation secret in the evidence
		// CBOR structure: 0xa3 (map 3), 0x01 (key 1), 0x58 (byte string), len, secret bytes...
		// Find the secret bytes and corrupt them
		idx := 1 // Skip map header (0xa3)
		if idx < len(evidence) && evidence[idx] == 0x01 {
			idx++ // Skip key 1
			if idx < len(evidence) && evidence[idx] == 0x58 {
				idx++ // Skip byte string marker
				if idx < len(evidence) {
					idx++ // Skip length byte
					// Corrupt first byte of secret
					if idx < len(evidence) {
						evidence[idx] ^= 0xFF
					}
				}
			}
		}
	case "wrong_public_key":
		// Corrupt the public key DER in the evidence
		// Find the second byte string (public key)
		idx := 1 // Skip map header
		if idx < len(evidence) && evidence[idx] == 0x01 {
			idx++ // Skip key 1
			if idx < len(evidence) && evidence[idx] == 0x58 {
				idx++ // Skip byte string marker
				if idx < len(evidence) {
					secretLen := int(evidence[idx])
					idx += 1 + secretLen // Skip secret length and secret
					// Now we're at key 2
					if idx < len(evidence) && evidence[idx] == 0x02 {
						idx++ // Skip key 2
						if idx < len(evidence) && evidence[idx] == 0x58 {
							idx++ // Skip byte string marker
							if idx < len(evidence) {
								// Corrupt first byte of public key data (skip length byte)
								if idx+1 < len(evidence) {
									evidence[idx+1] ^= 0xFF
								}
							}
						}
					}
				}
			}
		}
	case "wrong_evidence_type":
		// Corrupt the evidence type (last 2 bytes are the uint16)
		if len(evidence) >= 3 {
			evidence[len(evidence)-2] ^= 0xFF
			evidence[len(evidence)-1] ^= 0xFF
		}
	case "invalid_cbor":
		// Return completely invalid CBOR
		return []byte{0xFF, 0xFF, 0xFF}, nil
	case "too_short":
		// Return evidence that's too short
		return []byte{0x01, 0x02, 0x03}, nil
	default:
		// No corruption - return valid evidence
		return evidence, nil
	}

	return evidence, nil
}

func (b *badAttestationProvider) VerifyEvidence(evidence []byte, attestationMainSecret []byte, publicKeyDER []byte, evidenceType EvidenceType, trustedROTs []string) error {
	// Always use the good provider for verification (we want it to fail)
	return b.goodProvider.VerifyEvidence(evidence, attestationMainSecret, publicKeyDER, evidenceType, trustedROTs)
}

func TestMarshalPublicKeyToDER(t *testing.T) {
	// Test ECDSA P-256 key
	ecdsaPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assertNotError(t, err, "Failed to generate ECDSA key")
	ecdsaDER, err := MarshalPublicKeyToDER(ecdsaPriv.Public())
	assertNotError(t, err, "Failed to marshal ECDSA key to DER")
	assertNotNil(t, ecdsaDER, "ECDSA DER is nil")
	assertTrue(t, len(ecdsaDER) > 0, "ECDSA DER is empty")

	// Verify it's valid DER by unmarshaling
	pubKey, err := x509.ParsePKIXPublicKey(ecdsaDER)
	assertNotError(t, err, "Failed to parse ECDSA DER")
	assertNotNil(t, pubKey, "Parsed ECDSA public key is nil")

	// Test RSA key
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	assertNotError(t, err, "Failed to generate RSA key")
	rsaDER, err := MarshalPublicKeyToDER(rsaPriv.Public())
	assertNotError(t, err, "Failed to marshal RSA key to DER")
	assertNotNil(t, rsaDER, "RSA DER is nil")
	assertTrue(t, len(rsaDER) > 0, "RSA DER is empty")

	// Verify it's valid DER by unmarshaling
	pubKey2, err := x509.ParsePKIXPublicKey(rsaDER)
	assertNotError(t, err, "Failed to parse RSA DER")
	assertNotNil(t, pubKey2, "Parsed RSA public key is nil")

	// Test ECDSA P-384 key
	ecdsa384Priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	assertNotError(t, err, "Failed to generate ECDSA P-384 key")
	ecdsa384DER, err := MarshalPublicKeyToDER(ecdsa384Priv.Public())
	assertNotError(t, err, "Failed to marshal ECDSA P-384 key to DER")
	assertNotNil(t, ecdsa384DER, "ECDSA P-384 DER is nil")

	// Test invalid key type
	invalidKey := struct{}{}
	_, err = MarshalPublicKeyToDER(invalidKey)
	assertError(t, err, "Should fail to marshal invalid key type")
}

func TestCMWEncodeDecode(t *testing.T) {
	// This test is removed - CMW encoding/decoding is now handled by the attestation package
	t.Skip("CMW encoding/decoding moved to attestation package")
}

func TestCMWLogging(t *testing.T) {
	// This test is removed - CMW logging moved to attestation package
	t.Skip("CMW logging moved to attestation package")
}

func TestAttestationSecretDerivationFlow(t *testing.T) {
	// Test the complete flow: main secret -> attestation secret
	params := cipherSuiteMap[TLS_AES_128_GCM_SHA256]
	masterSecret := make([]byte, params.Hash.Size())
	transcriptHash := make([]byte, params.Hash.Size())
	for i := range masterSecret {
		masterSecret[i] = byte(i)
	}
	for i := range transcriptHash {
		transcriptHash[i] = byte(i + 100)
	}

	// Generate a real public key for testing
	ecdsaPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assertNotError(t, err, "Failed to generate ECDSA key")
	publicKeyDER, err := MarshalPublicKeyToDER(ecdsaPriv.Public())
	assertNotError(t, err, "Failed to marshal public key")

	// Derive attestation main secret
	attestationMainSecret := DeriveAttestationMainSecret(params, masterSecret, transcriptHash, true)
	assertNotNil(t, attestationMainSecret, "Attestation main secret is nil")

	// Derive attestation secret (nonce)
	attestationSecret := DeriveAttestationSecret(params, attestationMainSecret, publicKeyDER)
	assertNotNil(t, attestationSecret, "Attestation secret is nil")
	assertTrue(t, len(attestationSecret) == params.Hash.Size(), "Attestation secret length mismatch")

	// Verify determinism
	attestationSecret2 := DeriveAttestationSecret(params, attestationMainSecret, publicKeyDER)
	assertByteEquals(t, attestationSecret, attestationSecret2)

	// Verify different public keys produce different secrets
	publicKeyDER2 := []byte{0x30, 0x59, 0x30, 0x14} // Different DER
	attestationSecret3 := DeriveAttestationSecret(params, attestationMainSecret, publicKeyDER2)
	assertNotByteEquals(t, attestationSecret, attestationSecret3)
}

// Integration tests for attestation flows

func TestAttestationClientToServer(t *testing.T) {
	// Test: Client provides attestation evidence to server
	// Create test certificates
	serverKey, serverCert, err := MakeNewSelfSignedCert("example.com", ECDSA_P256_SHA256)
	assertNotError(t, err, "Failed to create server certificate")
	testCertificates := []*Certificate{
		{
			Chain:      []*x509.Certificate{serverCert},
			PrivateKey: serverKey,
		},
	}

	// Create client certificate for attestation
	clientKey, clientCert, err := MakeNewSelfSignedCert("client.example.com", ECDSA_P256_SHA256)
	assertNotError(t, err, "Failed to create client certificate")
	clientCertificates := []*Certificate{
		{
			Chain:      []*x509.Certificate{clientCert},
			PrivateKey: clientKey,
		},
	}

	testProvider := newTestAttestationProvider()
	clientConfig := &Config{
		ServerName:         "example.com",
		Certificates:       clientCertificates,
		InsecureSkipVerify: true,
		Attestation: AttestationConfig{
			Enabled:     true,
			Provider:    testProvider,
			MyROT:       "client-rot",
			TrustedROTs: []string{"server-rot"},
		},
		// Client will propose evidence (evidence_proposal extension)
	}
	serverConfig := &Config{
		Certificates:       testCertificates,
		RequireClientAuth:  true, // Server requires client certificate (needed for client attestation)
		InsecureSkipVerify: true,
		Attestation: AttestationConfig{
			Enabled:     true,
			RequestPeer: true, // Server requests evidence from client
			Provider:    testProvider,
			MyROT:       "server-rot",
			TrustedROTs: []string{"client-rot"},
		},
	}

	cConn, sConn := pipe()
	client := Client(cConn, clientConfig)
	server := Server(sConn, serverConfig)

	var clientAlert, serverAlert Alert

	done := make(chan bool)
	go func(t *testing.T) {
		defer close(done)
		serverAlert = server.Handshake()
		assertEquals(t, serverAlert, AlertNoAlert)
	}(t)

	clientAlert = client.Handshake()
	assertEquals(t, clientAlert, AlertNoAlert)

	<-done

	// Verify connection succeeded by checking handshake completed without errors
	assertTrue(t, clientAlert == AlertNoAlert, "Client handshake should succeed")
	assertTrue(t, serverAlert == AlertNoAlert, "Server handshake should succeed")
}

func TestAttestationServerToClient(t *testing.T) {
	// Test: Server provides attestation evidence to client
	serverKey, serverCert, err := MakeNewSelfSignedCert("example.com", ECDSA_P256_SHA256)
	assertNotError(t, err, "Failed to create server certificate")
	testCertificates := []*Certificate{
		{
			Chain:      []*x509.Certificate{serverCert},
			PrivateKey: serverKey,
		},
	}

	testProvider := newTestAttestationProvider()
	clientConfig := &Config{
		ServerName:         "example.com",
		InsecureSkipVerify: true,
		Attestation: AttestationConfig{
			Enabled:     true,
			RequestPeer: true, // Client requests evidence from server
			Provider:    testProvider,
			MyROT:       "client-rot",
			TrustedROTs: []string{"server-rot"},
		},
	}
	serverConfig := &Config{
		Certificates: testCertificates,
		Attestation: AttestationConfig{
			Enabled:     true,
			Provider:    testProvider,
			MyROT:       "server-rot",
			TrustedROTs: []string{"client-rot"},
		},
		// Server will provide evidence when requested
	}

	cConn, sConn := pipe()
	client := Client(cConn, clientConfig)
	server := Server(sConn, serverConfig)

	var clientAlert, serverAlert Alert

	done := make(chan bool)
	go func(t *testing.T) {
		defer close(done)
		serverAlert = server.Handshake()
		assertEquals(t, serverAlert, AlertNoAlert)
	}(t)

	clientAlert = client.Handshake()
	assertEquals(t, clientAlert, AlertNoAlert)

	<-done

	// Verify connection succeeded
	assertTrue(t, clientAlert == AlertNoAlert, "Client handshake should succeed")
	assertTrue(t, serverAlert == AlertNoAlert, "Server handshake should succeed")
}

func TestAttestationBidirectional(t *testing.T) {
	// Test: Both client and server provide attestation evidence
	serverKey, serverCert, err := MakeNewSelfSignedCert("example.com", ECDSA_P256_SHA256)
	assertNotError(t, err, "Failed to create server certificate")
	testCertificates := []*Certificate{
		{
			Chain:      []*x509.Certificate{serverCert},
			PrivateKey: serverKey,
		},
	}

	// Create client certificate for client attestation
	clientKey, clientCert, err := MakeNewSelfSignedCert("client.example.com", ECDSA_P256_SHA256)
	assertNotError(t, err, "Failed to create client certificate")
	clientCertificates := []*Certificate{
		{
			Chain:      []*x509.Certificate{clientCert},
			PrivateKey: clientKey,
		},
	}

	testProvider := newTestAttestationProvider()
	clientConfig := &Config{
		ServerName:         "example.com",
		Certificates:       clientCertificates,
		InsecureSkipVerify: true,
		Attestation: AttestationConfig{
			Enabled:     true,
			RequestPeer: true, // Client requests evidence from server
			Provider:    testProvider,
			MyROT:       "client-rot",
			TrustedROTs: []string{"server-rot"},
		},
		// Client will also propose evidence
	}
	serverConfig := &Config{
		Certificates:       testCertificates,
		RequireClientAuth:  true, // Server requires client certificate (needed for client attestation)
		InsecureSkipVerify: true,
		Attestation: AttestationConfig{
			Enabled:     true,
			RequestPeer: true, // Server requests evidence from client
			Provider:    testProvider,
			MyROT:       "server-rot",
			TrustedROTs: []string{"client-rot"},
		},
		// Server will also provide evidence when requested
	}

	cConn, sConn := pipe()
	client := Client(cConn, clientConfig)
	server := Server(sConn, serverConfig)

	var clientAlert, serverAlert Alert

	done := make(chan bool)
	go func(t *testing.T) {
		defer close(done)
		serverAlert = server.Handshake()
		assertEquals(t, serverAlert, AlertNoAlert)
	}(t)

	clientAlert = client.Handshake()
	assertEquals(t, clientAlert, AlertNoAlert)

	<-done

	// Verify connection succeeded
	assertTrue(t, clientAlert == AlertNoAlert, "Client handshake should succeed")
	assertTrue(t, serverAlert == AlertNoAlert, "Server handshake should succeed")
}

func TestAttestationDisabled(t *testing.T) {
	// Test: Attestation disabled - should work normally
	serverKey, serverCert, err := MakeNewSelfSignedCert("example.com", ECDSA_P256_SHA256)
	assertNotError(t, err, "Failed to create server certificate")
	testCertificates := []*Certificate{
		{
			Chain:      []*x509.Certificate{serverCert},
			PrivateKey: serverKey,
		},
	}

	clientConfig := &Config{
		ServerName:         "example.com",
		InsecureSkipVerify: true,
		Attestation: AttestationConfig{
			Enabled: false,
		},
	}
	serverConfig := &Config{
		Certificates: testCertificates,
		Attestation: AttestationConfig{
			Enabled: false,
		},
	}

	cConn, sConn := pipe()
	client := Client(cConn, clientConfig)
	server := Server(sConn, serverConfig)

	var clientAlert, serverAlert Alert

	done := make(chan bool)
	go func(t *testing.T) {
		defer close(done)
		serverAlert = server.Handshake()
		assertEquals(t, serverAlert, AlertNoAlert)
	}(t)

	clientAlert = client.Handshake()
	assertEquals(t, clientAlert, AlertNoAlert)

	<-done

	// Verify connection succeeded
	assertTrue(t, clientAlert == AlertNoAlert, "Client handshake should succeed")
	assertTrue(t, serverAlert == AlertNoAlert, "Server handshake should succeed")
}

func TestAttestationClientRequiresServerEvidence(t *testing.T) {
	// Test: Client requires server evidence, server provides it
	serverKey, serverCert, err := MakeNewSelfSignedCert("example.com", ECDSA_P256_SHA256)
	assertNotError(t, err, "Failed to create server certificate")
	testCertificates := []*Certificate{
		{
			Chain:      []*x509.Certificate{serverCert},
			PrivateKey: serverKey,
		},
	}

	testProvider := newTestAttestationProvider()
	clientConfig := &Config{
		ServerName:         "example.com",
		InsecureSkipVerify: true,
		Attestation: AttestationConfig{
			Enabled:     true,
			RequestPeer: true,
			RequirePeer: true, // Client requires evidence
			Provider:    testProvider,
			MyROT:       "client-rot",
			TrustedROTs: []string{"server-rot"},
		},
	}
	serverConfig := &Config{
		Certificates: testCertificates,
		Attestation: AttestationConfig{
			Enabled:     true,
			Provider:    testProvider,
			MyROT:       "server-rot",
			TrustedROTs: []string{"client-rot"},
		},
		// Server will provide evidence when requested
	}

	cConn, sConn := pipe()
	client := Client(cConn, clientConfig)
	server := Server(sConn, serverConfig)

	var clientAlert, serverAlert Alert

	done := make(chan bool)
	go func(t *testing.T) {
		defer close(done)
		serverAlert = server.Handshake()
		assertEquals(t, serverAlert, AlertNoAlert)
	}(t)

	clientAlert = client.Handshake()
	assertEquals(t, clientAlert, AlertNoAlert)

	<-done

	// Verify connection succeeded
	assertTrue(t, clientAlert == AlertNoAlert, "Client handshake should succeed")
	assertTrue(t, serverAlert == AlertNoAlert, "Server handshake should succeed")
}

func TestAttestationClientRequiresButServerDoesNotProvide(t *testing.T) {
	// Test: Client requires server evidence, but server doesn't support attestation
	// This should fail the handshake
	serverKey, serverCert, err := MakeNewSelfSignedCert("example.com", ECDSA_P256_SHA256)
	assertNotError(t, err, "Failed to create server certificate")
	testCertificates := []*Certificate{
		{
			Chain:      []*x509.Certificate{serverCert},
			PrivateKey: serverKey,
		},
	}

	clientConfig := &Config{
		ServerName:         "example.com",
		InsecureSkipVerify: true,
		Attestation: AttestationConfig{
			Enabled:     true,
			RequestPeer: true,
			RequirePeer: true, // Client requires evidence
		},
	}
	serverConfig := &Config{
		Certificates: testCertificates,
		Attestation: AttestationConfig{
			Enabled: false, // Server doesn't support attestation
		},
	}

	cConn, sConn := pipe()
	client := Client(cConn, clientConfig)
	server := Server(sConn, serverConfig)

	var clientAlert Alert

	done := make(chan bool, 1)
	go func() {
		defer func() { done <- true }()
		_ = server.Handshake()
		// Server handshake may succeed (it doesn't know about client requirement)
		// but client should fail
	}()

	clientAlert = client.Handshake()
	// Client should abort because server didn't provide required evidence
	assertTrue(t, clientAlert != AlertNoAlert, "Client should abort when server doesn't provide required evidence")

	// Close client connection - server should detect this and terminate
	// (either via alert or connection closure)
	client.Close()

	// Wait for server to finish (should happen quickly since alert is sent)
	// Timeout is a safety net in case something goes wrong
	select {
	case <-done:
		// Server finished normally
	case <-time.After(1 * time.Second):
		// Safety timeout - force close server if it's still waiting
		t.Log("Warning: Server didn't terminate within timeout, forcing close")
		server.Close()
	}
}

// TestAttestationClientInvalidEvidence tests that server rejects invalid client evidence
func TestAttestationClientInvalidEvidence(t *testing.T) {
	serverKey, serverCert, err := MakeNewSelfSignedCert("example.com", ECDSA_P256_SHA256)
	assertNotError(t, err, "Failed to create server certificate")
	testCertificates := []*Certificate{
		{
			Chain:      []*x509.Certificate{serverCert},
			PrivateKey: serverKey,
		},
	}

	// Create client certificate for client auth
	clientKey, clientCert, err := MakeNewSelfSignedCert("client.example.com", ECDSA_P256_SHA256)
	assertNotError(t, err, "Failed to create client certificate")
	clientCertificates := []*Certificate{
		{
			Chain:      []*x509.Certificate{clientCert},
			PrivateKey: clientKey,
		},
	}

	// Server uses good provider
	serverProvider := newTestAttestationProvider()
	serverConfig := &Config{
		Certificates:       testCertificates,
		RequireClientAuth:  true, // Require client certificate
		InsecureSkipVerify: true, // Skip client cert verification for test
		Attestation: AttestationConfig{
			Enabled:     true,
			RequestPeer: true, // Server requests evidence from client
			Provider:    serverProvider,
		},
	}

	// Client uses bad provider that generates invalid evidence
	clientProvider := newBadAttestationProvider("wrong_secret")
	clientConfig := &Config{
		ServerName:         "example.com",
		Certificates:       clientCertificates,
		InsecureSkipVerify: true,
		Attestation: AttestationConfig{
			Enabled:  true,
			Provider: clientProvider,
		},
	}

	cConn, sConn := pipe()
	client := Client(cConn, clientConfig)
	server := Server(sConn, serverConfig)

	var serverAlert Alert

	done := make(chan bool, 1)
	go func() {
		defer func() { done <- true }()
		serverAlert = server.Handshake()
		// Server should reject invalid evidence
		assertTrue(t, serverAlert != AlertNoAlert, "Server should reject invalid client evidence")
	}()

	_ = client.Handshake()
	// Client may succeed in sending, but server should reject
	// Wait for server to finish
	<-done

	// Server should have rejected with AlertUnsupportedEvidence
	assertTrue(t, serverAlert == AlertUnsupportedEvidence || serverAlert != AlertNoAlert,
		fmt.Sprintf("Server should reject invalid evidence, got alert: %v", serverAlert))
}

// TestAttestationServerInvalidEvidence tests that client rejects invalid server evidence
func TestAttestationServerInvalidEvidence(t *testing.T) {
	serverKey, serverCert, err := MakeNewSelfSignedCert("example.com", ECDSA_P256_SHA256)
	assertNotError(t, err, "Failed to create server certificate")
	testCertificates := []*Certificate{
		{
			Chain:      []*x509.Certificate{serverCert},
			PrivateKey: serverKey,
		},
	}

	// Server uses bad provider that generates invalid evidence
	serverProvider := newBadAttestationProvider("wrong_secret")
	serverConfig := &Config{
		Certificates: testCertificates,
		Attestation: AttestationConfig{
			Enabled:     true,
			Provider:    serverProvider,
			MyROT:       "server-rot",
			TrustedROTs: []string{"client-rot"},
		},
	}

	// Client uses good provider
	clientProvider := newTestAttestationProvider()
	clientConfig := &Config{
		ServerName:         "example.com",
		InsecureSkipVerify: true,
		Attestation: AttestationConfig{
			Enabled:     true,
			RequestPeer: true, // Client requests evidence from server
			Provider:    clientProvider,
			MyROT:       "client-rot",
			TrustedROTs: []string{"server-rot"},
		},
	}

	cConn, sConn := pipe()
	client := Client(cConn, clientConfig)
	server := Server(sConn, serverConfig)

	var clientAlert Alert

	done := make(chan bool, 1)
	go func() {
		defer func() { done <- true }()
		_ = server.Handshake()
		// Server may succeed in sending, but client should reject
	}()

	clientAlert = client.Handshake()
	// Client should reject invalid evidence
	assertTrue(t, clientAlert != AlertNoAlert, "Client should reject invalid server evidence")
	assertTrue(t, clientAlert == AlertUnsupportedEvidence,
		fmt.Sprintf("Client should reject with AlertUnsupportedEvidence, got: %v", clientAlert))

	<-done
}

// TestAttestationClientWrongPublicKey tests that server rejects evidence with wrong public key
func TestAttestationClientWrongPublicKey(t *testing.T) {
	serverKey, serverCert, err := MakeNewSelfSignedCert("example.com", ECDSA_P256_SHA256)
	assertNotError(t, err, "Failed to create server certificate")
	testCertificates := []*Certificate{
		{
			Chain:      []*x509.Certificate{serverCert},
			PrivateKey: serverKey,
		},
	}

	// Create client certificate for client auth
	clientKey, clientCert, err := MakeNewSelfSignedCert("client.example.com", ECDSA_P256_SHA256)
	assertNotError(t, err, "Failed to create client certificate")
	clientCertificates := []*Certificate{
		{
			Chain:      []*x509.Certificate{clientCert},
			PrivateKey: clientKey,
		},
	}

	serverProvider := newTestAttestationProvider()
	serverConfig := &Config{
		Certificates:       testCertificates,
		RequireClientAuth:  true,
		InsecureSkipVerify: true,
		Attestation: AttestationConfig{
			Enabled:     true,
			RequestPeer: true,
			Provider:    serverProvider,
			MyROT:       "server-rot",
			TrustedROTs: []string{"client-rot"},
		},
	}

	// Client uses bad provider that corrupts public key in evidence
	clientProvider := newBadAttestationProvider("wrong_public_key")
	clientConfig := &Config{
		ServerName:         "example.com",
		Certificates:       clientCertificates,
		InsecureSkipVerify: true,
		Attestation: AttestationConfig{
			Enabled:     true,
			Provider:    clientProvider,
			MyROT:       "client-rot",
			TrustedROTs: []string{"server-rot"},
		},
	}

	cConn, sConn := pipe()
	client := Client(cConn, clientConfig)
	server := Server(sConn, serverConfig)

	var serverAlert Alert

	done := make(chan bool, 1)
	go func() {
		defer func() { done <- true }()
		serverAlert = server.Handshake()
		assertTrue(t, serverAlert != AlertNoAlert, "Server should reject evidence with wrong public key")
	}()

	_ = client.Handshake()
	<-done

	// Server should reject with decode error (corrupted CBOR) or unsupported evidence
	assertTrue(t, serverAlert == AlertUnsupportedEvidence || serverAlert == AlertDecodeError || serverAlert == AlertUnexpectedMessage,
		fmt.Sprintf("Server should reject invalid evidence, got: %v", serverAlert))
}

// TestAttestationClientInvalidCBOR tests that server rejects invalid CBOR evidence
func TestAttestationClientInvalidCBOR(t *testing.T) {
	serverKey, serverCert, err := MakeNewSelfSignedCert("example.com", ECDSA_P256_SHA256)
	assertNotError(t, err, "Failed to create server certificate")
	testCertificates := []*Certificate{
		{
			Chain:      []*x509.Certificate{serverCert},
			PrivateKey: serverKey,
		},
	}

	// Create client certificate for client auth
	clientKey, clientCert, err := MakeNewSelfSignedCert("client.example.com", ECDSA_P256_SHA256)
	assertNotError(t, err, "Failed to create client certificate")
	clientCertificates := []*Certificate{
		{
			Chain:      []*x509.Certificate{clientCert},
			PrivateKey: clientKey,
		},
	}

	serverProvider := newTestAttestationProvider()
	serverConfig := &Config{
		Certificates:       testCertificates,
		RequireClientAuth:  true,
		InsecureSkipVerify: true,
		Attestation: AttestationConfig{
			Enabled:     true,
			RequestPeer: true,
			Provider:    serverProvider,
			MyROT:       "server-rot",
			TrustedROTs: []string{"client-rot"},
		},
	}

	// Client uses bad provider that generates invalid CBOR
	clientProvider := newBadAttestationProvider("invalid_cbor")
	clientConfig := &Config{
		ServerName:         "example.com",
		Certificates:       clientCertificates,
		InsecureSkipVerify: true,
		Attestation: AttestationConfig{
			Enabled:     true,
			Provider:    clientProvider,
			MyROT:       "client-rot",
			TrustedROTs: []string{"server-rot"},
		},
	}

	cConn, sConn := pipe()
	client := Client(cConn, clientConfig)
	server := Server(sConn, serverConfig)

	var serverAlert Alert

	done := make(chan bool, 1)
	go func() {
		defer func() { done <- true }()
		serverAlert = server.Handshake()
		assertTrue(t, serverAlert != AlertNoAlert, "Server should reject invalid CBOR")
	}()

	_ = client.Handshake()
	<-done

	// Should reject with decode error, unexpected message, or unsupported evidence
	assertTrue(t, serverAlert == AlertUnsupportedEvidence || serverAlert == AlertDecodeError || serverAlert == AlertUnexpectedMessage,
		fmt.Sprintf("Server should reject invalid CBOR, got: %v", serverAlert))
}

// TestAttestationServerWrongSecret tests that client rejects evidence with wrong secret
func TestAttestationServerWrongSecret(t *testing.T) {
	serverKey, serverCert, err := MakeNewSelfSignedCert("example.com", ECDSA_P256_SHA256)
	assertNotError(t, err, "Failed to create server certificate")
	testCertificates := []*Certificate{
		{
			Chain:      []*x509.Certificate{serverCert},
			PrivateKey: serverKey,
		},
	}

	// Server uses bad provider that corrupts secret
	serverProvider := newBadAttestationProvider("wrong_secret")
	serverConfig := &Config{
		Certificates: testCertificates,
		Attestation: AttestationConfig{
			Enabled:     true,
			Provider:    serverProvider,
			MyROT:       "server-rot",
			TrustedROTs: []string{"client-rot"},
		},
	}

	clientProvider := newTestAttestationProvider()
	clientConfig := &Config{
		ServerName:         "example.com",
		InsecureSkipVerify: true,
		Attestation: AttestationConfig{
			Enabled:     true,
			RequestPeer: true,
			Provider:    clientProvider,
			MyROT:       "client-rot",
			TrustedROTs: []string{"server-rot"},
		},
	}

	cConn, sConn := pipe()
	client := Client(cConn, clientConfig)
	server := Server(sConn, serverConfig)

	var clientAlert Alert

	done := make(chan bool, 1)
	go func() {
		defer func() { done <- true }()
		_ = server.Handshake()
	}()

	clientAlert = client.Handshake()
	assertTrue(t, clientAlert != AlertNoAlert, "Client should reject evidence with wrong secret")
	assertTrue(t, clientAlert == AlertUnsupportedEvidence,
		fmt.Sprintf("Client should reject with AlertUnsupportedEvidence, got: %v", clientAlert))

	<-done
}
