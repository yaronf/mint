package mint

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"testing"
	"time"
)

func TestDeriveAttestationMainSecret(t *testing.T) {
	params := cipherSuiteMap[TLS_AES_128_GCM_SHA256]
	masterSecret := make([]byte, params.Hash.Size())
	transcriptHash := make([]byte, params.Hash.Size())
	// Fill with test data
	for i := range masterSecret {
		masterSecret[i] = byte(i)
	}
	for i := range transcriptHash {
		transcriptHash[i] = byte(i + 100)
	}

	// Test client attestation main secret derivation
	clientSecret := DeriveAttestationMainSecret(params, masterSecret, transcriptHash, true)
	assertNotNil(t, clientSecret, "Client attestation main secret is nil")
	assertTrue(t, len(clientSecret) == params.Hash.Size(), "Client secret length mismatch")

	// Test server attestation main secret derivation
	serverSecret := DeriveAttestationMainSecret(params, masterSecret, transcriptHash, false)
	assertNotNil(t, serverSecret, "Server attestation main secret is nil")
	assertTrue(t, len(serverSecret) == params.Hash.Size(), "Server secret length mismatch")

	// Client and server secrets should be different (different labels)
	assertNotByteEquals(t, clientSecret, serverSecret)

	// Test determinism: same inputs should produce same outputs
	clientSecret2 := DeriveAttestationMainSecret(params, masterSecret, transcriptHash, true)
	assertByteEquals(t, clientSecret, clientSecret2)

	serverSecret2 := DeriveAttestationMainSecret(params, masterSecret, transcriptHash, false)
	assertByteEquals(t, serverSecret, serverSecret2)

	// Test different master secrets produce different outputs
	masterSecret2 := make([]byte, len(masterSecret))
	copy(masterSecret2, masterSecret)
	masterSecret2[0] ^= 0xFF
	clientSecret3 := DeriveAttestationMainSecret(params, masterSecret2, transcriptHash, true)
	assertNotByteEquals(t, clientSecret, clientSecret3)

	// Test different transcript hashes produce different outputs
	transcriptHash2 := make([]byte, len(transcriptHash))
	copy(transcriptHash2, transcriptHash)
	transcriptHash2[0] ^= 0xFF
	clientSecret4 := DeriveAttestationMainSecret(params, masterSecret, transcriptHash2, true)
	assertNotByteEquals(t, clientSecret, clientSecret4)
}

func TestDeriveAttestationSecret(t *testing.T) {
	params := cipherSuiteMap[TLS_AES_128_GCM_SHA256]
	attestationMainSecret := make([]byte, params.Hash.Size())
	publicKeyDER := make([]byte, 100) // Mock DER-encoded public key
	// Fill with test data
	for i := range attestationMainSecret {
		attestationMainSecret[i] = byte(i + 50)
	}
	for i := range publicKeyDER {
		publicKeyDER[i] = byte(i + 200)
	}

	// Test attestation secret derivation
	attestationSecret := DeriveAttestationSecret(params, attestationMainSecret, publicKeyDER)
	assertNotNil(t, attestationSecret, "Attestation secret is nil")
	assertTrue(t, len(attestationSecret) == params.Hash.Size(), "Attestation secret length mismatch")

	// Test determinism: same inputs should produce same outputs
	attestationSecret2 := DeriveAttestationSecret(params, attestationMainSecret, publicKeyDER)
	assertByteEquals(t, attestationSecret, attestationSecret2)

	// Test different main secrets produce different outputs
	attestationMainSecret2 := make([]byte, len(attestationMainSecret))
	copy(attestationMainSecret2, attestationMainSecret)
	attestationMainSecret2[0] ^= 0xFF
	attestationSecret3 := DeriveAttestationSecret(params, attestationMainSecret2, publicKeyDER)
	assertNotByteEquals(t, attestationSecret, attestationSecret3)

	// Test different public keys produce different outputs
	publicKeyDER2 := make([]byte, len(publicKeyDER))
	copy(publicKeyDER2, publicKeyDER)
	publicKeyDER2[0] ^= 0xFF
	attestationSecret4 := DeriveAttestationSecret(params, attestationMainSecret, publicKeyDER2)
	assertNotByteEquals(t, attestationSecret, attestationSecret4)
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
	// Create a test CMW payload
	cmw := CMWPayload{
		AttestationSecret: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32},
		PublicKeyDER:      []byte{0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00},
		EvidenceType:      0xFA00,
	}

	// Test encoding to CBOR
	cborData, err := EncodeCMWToCBOR(cmw)
	assertNotError(t, err, "Failed to encode CMW to CBOR")
	assertNotNil(t, cborData, "CBOR data is nil")
	assertTrue(t, len(cborData) > 0, "CBOR data is empty")

	// Test decoding from CBOR
	decodedCMW, err := DecodeCMWFromCBOR(cborData)
	assertNotError(t, err, "Failed to decode CMW from CBOR")
	assertByteEquals(t, cmw.AttestationSecret, decodedCMW.AttestationSecret)
	assertByteEquals(t, cmw.PublicKeyDER, decodedCMW.PublicKeyDER)
	assertEquals(t, cmw.EvidenceType, decodedCMW.EvidenceType)

	// Test with empty fields
	emptyCMW := CMWPayload{
		AttestationSecret: []byte{},
		PublicKeyDER:      []byte{},
		EvidenceType:      0,
	}
	cborData2, err := EncodeCMWToCBOR(emptyCMW)
	assertNotError(t, err, "Failed to encode empty CMW to CBOR")
	decodedEmptyCMW, err := DecodeCMWFromCBOR(cborData2)
	assertNotError(t, err, "Failed to decode empty CMW from CBOR")
	assertByteEquals(t, emptyCMW.AttestationSecret, decodedEmptyCMW.AttestationSecret)
	assertByteEquals(t, emptyCMW.PublicKeyDER, decodedEmptyCMW.PublicKeyDER)
	assertEquals(t, emptyCMW.EvidenceType, decodedEmptyCMW.EvidenceType)

	// Test with large data
	largeCMW := CMWPayload{
		AttestationSecret: make([]byte, 1024),
		PublicKeyDER:      make([]byte, 2048),
		EvidenceType:      0xFFFF,
	}
	for i := range largeCMW.AttestationSecret {
		largeCMW.AttestationSecret[i] = byte(i % 256)
	}
	for i := range largeCMW.PublicKeyDER {
		largeCMW.PublicKeyDER[i] = byte((i + 100) % 256)
	}
	cborData3, err := EncodeCMWToCBOR(largeCMW)
	assertNotError(t, err, "Failed to encode large CMW to CBOR")
	decodedLargeCMW, err := DecodeCMWFromCBOR(cborData3)
	assertNotError(t, err, "Failed to decode large CMW from CBOR")
	assertByteEquals(t, largeCMW.AttestationSecret, decodedLargeCMW.AttestationSecret)
	assertByteEquals(t, largeCMW.PublicKeyDER, decodedLargeCMW.PublicKeyDER)
	assertEquals(t, largeCMW.EvidenceType, decodedLargeCMW.EvidenceType)

	// Test invalid CBOR data
	invalidCBOR := []byte{0xFF, 0xFF, 0xFF, 0xFF}
	_, err = DecodeCMWFromCBOR(invalidCBOR)
	assertError(t, err, "Should fail to decode invalid CBOR data")
}

func TestCMWLogging(t *testing.T) {
	// Test that LogCMWAsJSON doesn't crash
	cmw := CMWPayload{
		AttestationSecret: []byte{1, 2, 3, 4},
		PublicKeyDER:      []byte{5, 6, 7, 8},
		EvidenceType:      0xFA00,
	}

	// This should not panic
	LogCMWAsJSON(cmw, "[TEST]")

	// Test with empty CMW
	emptyCMW := CMWPayload{}
	LogCMWAsJSON(emptyCMW, "[TEST]")

	// Test with nil slices (should handle gracefully)
	nilCMW := CMWPayload{
		AttestationSecret: nil,
		PublicKeyDER:      nil,
		EvidenceType:      0,
	}
	LogCMWAsJSON(nilCMW, "[TEST]")
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

	// Create CMW with the derived secret
	cmw := CMWPayload{
		AttestationSecret: attestationSecret,
		PublicKeyDER:      publicKeyDER,
		EvidenceType:      uint16(ExtensionTypeEvidenceRequest), // Use a valid evidence type
	}

	// Encode and decode CMW
	cborData, err := EncodeCMWToCBOR(cmw)
	assertNotError(t, err, "Failed to encode CMW")
	decodedCMW, err := DecodeCMWFromCBOR(cborData)
	assertNotError(t, err, "Failed to decode CMW")

	// Verify round-trip
	assertByteEquals(t, cmw.AttestationSecret, decodedCMW.AttestationSecret)
	assertByteEquals(t, cmw.PublicKeyDER, decodedCMW.PublicKeyDER)
	assertEquals(t, cmw.EvidenceType, decodedCMW.EvidenceType)
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

	clientConfig := &Config{
		ServerName:         "example.com",
		InsecureSkipVerify: true,
		EnableAttestation:  true,
		// Client will propose evidence (evidence_proposal extension)
	}
	serverConfig := &Config{
		Certificates:             testCertificates,
		EnableAttestation:        true,
		RequestClientAttestation: true, // Server requests evidence from client
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

	clientConfig := &Config{
		ServerName:               "example.com",
		InsecureSkipVerify:       true,
		EnableAttestation:        true,
		RequestServerAttestation: true, // Client requests evidence from server
	}
	serverConfig := &Config{
		Certificates:      testCertificates,
		EnableAttestation: true,
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

	clientConfig := &Config{
		ServerName:               "example.com",
		InsecureSkipVerify:       true,
		EnableAttestation:        true,
		RequestServerAttestation: true, // Client requests evidence from server
		// Client will also propose evidence
	}
	serverConfig := &Config{
		Certificates:             testCertificates,
		EnableAttestation:        true,
		RequestClientAttestation: true, // Server requests evidence from client
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
		EnableAttestation:  false,
	}
	serverConfig := &Config{
		Certificates:      testCertificates,
		EnableAttestation: false,
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

	clientConfig := &Config{
		ServerName:               "example.com",
		InsecureSkipVerify:       true,
		EnableAttestation:        true,
		RequestServerAttestation: true,
		RequireServerAttestation: true, // Client requires evidence
	}
	serverConfig := &Config{
		Certificates:      testCertificates,
		EnableAttestation: true,
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
		ServerName:               "example.com",
		InsecureSkipVerify:       true,
		EnableAttestation:        true,
		RequestServerAttestation: true,
		RequireServerAttestation: true, // Client requires evidence
	}
	serverConfig := &Config{
		Certificates:      testCertificates,
		EnableAttestation: false, // Server doesn't support attestation
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
