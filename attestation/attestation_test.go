package attestation

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"testing"

	"github.com/bifurcation/mint"
	"github.com/veraison/cmw"
)

// Test helper functions (similar to mint package)
func assertTrue(t *testing.T, test bool, msg string) {
	t.Helper()
	if !test {
		t.Fatalf(msg)
	}
}

func assertError(t *testing.T, err error, msg string) {
	t.Helper()
	assertTrue(t, err != nil, msg)
}

func assertNotError(t *testing.T, err error, msg string) {
	t.Helper()
	if err != nil {
		msg += ": " + err.Error()
	}
	assertTrue(t, err == nil, msg)
}

func assertNil(t *testing.T, x interface{}, msg string) {
	t.Helper()
	assertTrue(t, x == nil, msg)
}

func assertNotNil(t *testing.T, x interface{}, msg string) {
	t.Helper()
	assertTrue(t, x != nil, msg)
}

func assertEquals(t *testing.T, a, b interface{}) {
	t.Helper()
	assertTrue(t, a == b, fmt.Sprintf("%+v != %+v", a, b))
}

func assertByteEquals(t *testing.T, a, b []byte) {
	t.Helper()
	assertTrue(t, bytes.Equal(a, b), fmt.Sprintf("%x != %x", a, b))
}

func assertNotByteEquals(t *testing.T, a, b []byte) {
	t.Helper()
	assertTrue(t, !bytes.Equal(a, b), fmt.Sprintf("%x == %x", a, b))
}

// TestDeriveAttestationMainSecret tests derivation of c_attestation_main and s_attestation_main secrets
func TestDeriveAttestationMainSecret(t *testing.T) {
	hash := crypto.SHA256
	masterSecret := make([]byte, hash.Size())
	transcriptHash := make([]byte, hash.Size())
	for i := range masterSecret {
		masterSecret[i] = byte(i)
	}
	for i := range transcriptHash {
		transcriptHash[i] = byte(i + 100)
	}

	// Test client attestation main secret derivation
	clientSecret := DeriveAttestationMainSecret(hash, masterSecret, transcriptHash, true)
	assertNotNil(t, clientSecret, "Client attestation main secret is nil")
	assertTrue(t, len(clientSecret) == hash.Size(), fmt.Sprintf("Client secret length mismatch: got %d, want %d", len(clientSecret), hash.Size()))

	// Test server attestation main secret derivation
	serverSecret := DeriveAttestationMainSecret(hash, masterSecret, transcriptHash, false)
	assertNotNil(t, serverSecret, "Server attestation main secret is nil")
	assertTrue(t, len(serverSecret) == hash.Size(), fmt.Sprintf("Server secret length mismatch: got %d, want %d", len(serverSecret), hash.Size()))

	// Client and server secrets should be different (different labels)
	assertNotByteEquals(t, clientSecret, serverSecret)

	// Test determinism - same inputs should produce same outputs
	clientSecret2 := DeriveAttestationMainSecret(hash, masterSecret, transcriptHash, true)
	assertByteEquals(t, clientSecret, clientSecret2)

	serverSecret2 := DeriveAttestationMainSecret(hash, masterSecret, transcriptHash, false)
	assertByteEquals(t, serverSecret, serverSecret2)

	// Test different master secrets produce different outputs
	masterSecret2 := make([]byte, hash.Size())
	copy(masterSecret2, masterSecret)
	masterSecret2[0]++
	clientSecret3 := DeriveAttestationMainSecret(hash, masterSecret2, transcriptHash, true)
	assertNotByteEquals(t, clientSecret, clientSecret3)

	// Test different transcript hashes produce different outputs
	transcriptHash2 := make([]byte, hash.Size())
	copy(transcriptHash2, transcriptHash)
	transcriptHash2[0]++
	clientSecret4 := DeriveAttestationMainSecret(hash, masterSecret, transcriptHash2, true)
	assertNotByteEquals(t, clientSecret, clientSecret4)
}

// TestDeriveAttestationSecret tests derivation of attestation secret (nonce) from attestation main secret
func TestDeriveAttestationSecret(t *testing.T) {
	hash := crypto.SHA256
	attestationMainSecret := make([]byte, hash.Size())
	publicKeyDER := []byte{0x30, 0x59, 0x30, 0x14, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01}
	for i := range attestationMainSecret {
		attestationMainSecret[i] = byte(i + 50)
	}

	// Test attestation secret derivation
	attestationSecret := DeriveAttestationSecret(hash, attestationMainSecret, publicKeyDER)
	assertNotNil(t, attestationSecret, "Attestation secret is nil")
	assertTrue(t, len(attestationSecret) == hash.Size(), fmt.Sprintf("Attestation secret length mismatch: got %d, want %d", len(attestationSecret), hash.Size()))

	// Test determinism - same inputs should produce same outputs
	attestationSecret2 := DeriveAttestationSecret(hash, attestationMainSecret, publicKeyDER)
	assertByteEquals(t, attestationSecret, attestationSecret2)

	// Test different main secrets produce different outputs
	attestationMainSecret2 := make([]byte, hash.Size())
	copy(attestationMainSecret2, attestationMainSecret)
	attestationMainSecret2[0]++
	attestationSecret3 := DeriveAttestationSecret(hash, attestationMainSecret2, publicKeyDER)
	assertNotByteEquals(t, attestationSecret, attestationSecret3)

	// Test different public keys produce different outputs
	publicKeyDER2 := []byte{0x30, 0x59, 0x30, 0x14, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x02} // Different DER
	attestationSecret4 := DeriveAttestationSecret(hash, attestationMainSecret, publicKeyDER2)
	assertNotByteEquals(t, attestationSecret, attestationSecret4)
}

// TestMarshalPublicKeyToDER tests marshaling of various public key types to DER format
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

// TestCMWEncodeDecode tests CBOR encoding and decoding of CMW payloads using Veraison CMW
func TestCMWEncodeDecode(t *testing.T) {
	hash := crypto.SHA256
	attestationSecret := make([]byte, hash.Size())
	publicKeyDER := make([]byte, 100)
	evidenceType := uint16(0x1234)

	for i := range attestationSecret {
		attestationSecret[i] = byte(i)
	}
	for i := range publicKeyDER {
		publicKeyDER[i] = byte(i + 200)
	}

	// Create payload
	payload := CMWPayload{
		AttestationSecret: attestationSecret,
		PublicKeyDER:      publicKeyDER,
		EvidenceType:      evidenceType,
		ROTName:           "test-rot",
	}

	// Encode payload to CBOR
	payloadBytes, err := encodePayload(payload)
	assertNotError(t, err, "Failed to encode payload")
	assertNotNil(t, payloadBytes, "Payload bytes is nil")
	assertTrue(t, len(payloadBytes) > 0, "Payload bytes is empty")

	// Wrap in CMW
	cmwWrapper, err := cmw.NewMonad(EvidenceMediaType, payloadBytes)
	assertNotError(t, err, "Failed to create CMW")
	assertNotNil(t, cmwWrapper, "CMW wrapper is nil")

	// Marshal CMW to CBOR
	cmwBytes, err := cmwWrapper.MarshalCBOR()
	assertNotError(t, err, "Failed to marshal CMW")
	assertNotNil(t, cmwBytes, "CMW bytes is nil")
	assertTrue(t, len(cmwBytes) > 0, "CMW bytes is empty")

	// Decode CMW from CBOR
	var cmwWrapper2 cmw.CMW
	err = cmwWrapper2.UnmarshalCBOR(cmwBytes)
	assertNotError(t, err, "Failed to unmarshal CMW")

	// Verify media type
	mediaType, err := cmwWrapper2.GetMonadType()
	assertNotError(t, err, "Failed to get CMW media type")
	assertEquals(t, mediaType, EvidenceMediaType)

	// Extract payload bytes
	payloadBytes2, err := cmwWrapper2.GetMonadValue()
	assertNotError(t, err, "Failed to get CMW value")
	assertByteEquals(t, payloadBytes, payloadBytes2)

	// Decode payload
	payload2, err := decodePayload(payloadBytes2)
	assertNotError(t, err, "Failed to decode payload")

	// Verify round-trip
	assertByteEquals(t, payload.AttestationSecret, payload2.AttestationSecret)
	assertByteEquals(t, payload.PublicKeyDER, payload2.PublicKeyDER)
	assertEquals(t, payload.EvidenceType, payload2.EvidenceType)
	assertEquals(t, payload.ROTName, payload2.ROTName)

	// Test with empty fields
	emptyPayload := CMWPayload{
		AttestationSecret: []byte{},
		PublicKeyDER:      []byte{},
		EvidenceType:      0,
		ROTName:           "",
	}
	emptyPayloadBytes, err := encodePayload(emptyPayload)
	assertNotError(t, err, "Failed to encode empty payload")
	emptyPayload2, err := decodePayload(emptyPayloadBytes)
	assertNotError(t, err, "Failed to decode empty payload")
	assertTrue(t, len(emptyPayload2.AttestationSecret) == 0, "Empty attestation secret should be empty")
	assertTrue(t, len(emptyPayload2.PublicKeyDER) == 0, "Empty public key DER should be empty")
	assertEquals(t, emptyPayload2.EvidenceType, uint16(0))

	// Test with large data
	largeSecret := make([]byte, 1024) // 1KB attestation secret
	largeKey := make([]byte, 2048)    // 2KB public key
	for i := range largeSecret {
		largeSecret[i] = byte(i % 256)
	}
	for i := range largeKey {
		largeKey[i] = byte(i % 256)
	}
	largePayload := CMWPayload{
		AttestationSecret: largeSecret,
		PublicKeyDER:      largeKey,
		EvidenceType:      0x5678,
		ROTName:           "large-test-rot",
	}
	largePayloadBytes, err := encodePayload(largePayload)
	assertNotError(t, err, "Failed to encode large payload")
	largePayload2, err := decodePayload(largePayloadBytes)
	assertNotError(t, err, "Failed to decode large payload")
	assertByteEquals(t, largePayload.AttestationSecret, largePayload2.AttestationSecret)
	assertByteEquals(t, largePayload.PublicKeyDER, largePayload2.PublicKeyDER)
	assertEquals(t, largePayload.EvidenceType, largePayload2.EvidenceType)
	assertEquals(t, largePayload.ROTName, largePayload2.ROTName)

	// Test invalid CBOR data
	invalidCBOR := []byte{0xff, 0xff, 0xff}
	_, err = decodePayload(invalidCBOR)
	assertError(t, err, "Should fail to decode invalid CBOR")
}

// TestAttestationSecretDerivationFlow tests complete flow: main secret -> attestation secret -> CMW creation
func TestAttestationSecretDerivationFlow(t *testing.T) {
	hash := crypto.SHA256
	masterSecret := make([]byte, hash.Size())
	transcriptHash := make([]byte, hash.Size())
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
	attestationMainSecret := DeriveAttestationMainSecret(hash, masterSecret, transcriptHash, true)
	assertNotNil(t, attestationMainSecret, "Attestation main secret is nil")
	assertTrue(t, len(attestationMainSecret) == hash.Size(), "Attestation main secret length mismatch")

	// Derive attestation secret (nonce)
	attestationSecret := DeriveAttestationSecret(hash, attestationMainSecret, publicKeyDER)
	assertNotNil(t, attestationSecret, "Attestation secret is nil")
	assertTrue(t, len(attestationSecret) == hash.Size(), "Attestation secret length mismatch")

	// Verify determinism
	attestationSecret2 := DeriveAttestationSecret(hash, attestationMainSecret, publicKeyDER)
	assertByteEquals(t, attestationSecret, attestationSecret2)

	// Verify different public keys produce different secrets
	publicKeyDER2 := []byte{0x30, 0x59, 0x30, 0x14} // Different DER
	attestationSecret3 := DeriveAttestationSecret(hash, attestationMainSecret, publicKeyDER2)
	assertNotByteEquals(t, attestationSecret, attestationSecret3)

	// Create CMW using StandardProvider
	provider := NewStandardProvider(hash)
	evidenceType := mint.EvidenceType{ContentFormat: 0x1234}
	rotName := "test-rot"
	evidence, err := provider.GenerateEvidence(attestationMainSecret, publicKeyDER, evidenceType, rotName)
	assertNotError(t, err, "Failed to generate evidence")
	assertNotNil(t, evidence, "Evidence is nil")
	assertTrue(t, len(evidence) > 0, "Evidence is empty")

	// Verify evidence can be decoded and verified
	trustedROTs := []string{"test-rot"}
	err = provider.VerifyEvidence(evidence, attestationMainSecret, publicKeyDER, evidenceType, trustedROTs)
	assertNotError(t, err, "Failed to verify evidence")
}

// TestStandardProvider tests GenerateEvidence and VerifyEvidence methods
func TestStandardProvider(t *testing.T) {
	hash := crypto.SHA256
	provider := NewStandardProvider(hash)

	// Generate test data
	masterSecret := make([]byte, hash.Size())
	transcriptHash := make([]byte, hash.Size())
	for i := range masterSecret {
		masterSecret[i] = byte(i)
	}
	for i := range transcriptHash {
		transcriptHash[i] = byte(i + 100)
	}

	// Generate a real public key
	ecdsaPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assertNotError(t, err, "Failed to generate ECDSA key")
	publicKeyDER, err := MarshalPublicKeyToDER(ecdsaPriv.Public())
	assertNotError(t, err, "Failed to marshal public key")

	// Derive attestation main secret
	attestationMainSecret := DeriveAttestationMainSecret(hash, masterSecret, transcriptHash, true)

	// Test GenerateEvidence
	evidenceType := mint.EvidenceType{ContentFormat: 0x1234}
	rotName := "test-rot"
	trustedROTs := []string{"test-rot"}
	evidence, err := provider.GenerateEvidence(attestationMainSecret, publicKeyDER, evidenceType, rotName)
	assertNotError(t, err, "Failed to generate evidence")
	assertNotNil(t, evidence, "Evidence is nil")
	assertTrue(t, len(evidence) > 0, "Evidence is empty")

	// Test VerifyEvidence with correct parameters
	err = provider.VerifyEvidence(evidence, attestationMainSecret, publicKeyDER, evidenceType, trustedROTs)
	assertNotError(t, err, "Failed to verify evidence")

	// Test VerifyEvidence with wrong attestation main secret
	wrongMainSecret := make([]byte, hash.Size())
	copy(wrongMainSecret, attestationMainSecret)
	wrongMainSecret[0]++
	err = provider.VerifyEvidence(evidence, wrongMainSecret, publicKeyDER, evidenceType, trustedROTs)
	assertError(t, err, "Should fail with wrong attestation main secret")

	// Test VerifyEvidence with wrong public key
	wrongPublicKeyDER := make([]byte, len(publicKeyDER))
	copy(wrongPublicKeyDER, publicKeyDER)
	wrongPublicKeyDER[0]++
	err = provider.VerifyEvidence(evidence, attestationMainSecret, wrongPublicKeyDER, evidenceType, trustedROTs)
	assertError(t, err, "Should fail with wrong public key")

	// Test VerifyEvidence with wrong evidence type
	wrongEvidenceType := mint.EvidenceType{ContentFormat: 0x5678}
	err = provider.VerifyEvidence(evidence, attestationMainSecret, publicKeyDER, wrongEvidenceType, trustedROTs)
	assertError(t, err, "Should fail with wrong evidence type")

	// Test VerifyEvidence with invalid CMW data
	invalidEvidence := []byte{0xff, 0xff, 0xff}
	err = provider.VerifyEvidence(invalidEvidence, attestationMainSecret, publicKeyDER, evidenceType, trustedROTs)
	assertError(t, err, "Should fail with invalid CMW data")

	// Test VerifyEvidence with wrong media type (create CMW with different media type)
	wrongMediaTypePayload := CMWPayload{
		AttestationSecret: DeriveAttestationSecret(hash, attestationMainSecret, publicKeyDER),
		PublicKeyDER:      publicKeyDER,
		EvidenceType:      evidenceType.ContentFormat,
		ROTName:           rotName,
	}
	wrongPayloadBytes, err := encodePayload(wrongMediaTypePayload)
	assertNotError(t, err, "Failed to encode payload")
	wrongCMW, err := cmw.NewMonad("application/unknown", wrongPayloadBytes)
	assertNotError(t, err, "Failed to create CMW with wrong media type")
	wrongEvidenceBytes, err := wrongCMW.MarshalCBOR()
	assertNotError(t, err, "Failed to marshal wrong CMW")
	err = provider.VerifyEvidence(wrongEvidenceBytes, attestationMainSecret, publicKeyDER, evidenceType, trustedROTs)
	assertError(t, err, "Should fail with wrong media type")

	// Test VerifyEvidence with untrusted ROT
	untrustedROTs := []string{"other-rot"}
	err = provider.VerifyEvidence(evidence, attestationMainSecret, publicKeyDER, evidenceType, untrustedROTs)
	assertError(t, err, "Should fail with untrusted ROT")
}

// TestStandardProviderRoundTrip tests complete round-trip: generate -> verify
func TestStandardProviderRoundTrip(t *testing.T) {
	hash := crypto.SHA256
	provider := NewStandardProvider(hash)

	// Generate test data
	masterSecret := make([]byte, hash.Size())
	transcriptHash := make([]byte, hash.Size())
	for i := range masterSecret {
		masterSecret[i] = byte(i)
	}
	for i := range transcriptHash {
		transcriptHash[i] = byte(i + 100)
	}

	// Generate a real public key
	ecdsaPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assertNotError(t, err, "Failed to generate ECDSA key")
	publicKeyDER, err := MarshalPublicKeyToDER(ecdsaPriv.Public())
	assertNotError(t, err, "Failed to marshal public key")

	// Derive attestation main secret
	attestationMainSecret := DeriveAttestationMainSecret(hash, masterSecret, transcriptHash, true)

	// Generate evidence
	evidenceType := mint.EvidenceType{ContentFormat: 0x1234}
	rotName := "test-rot"
	trustedROTs := []string{"test-rot"}
	evidence, err := provider.GenerateEvidence(attestationMainSecret, publicKeyDER, evidenceType, rotName)
	assertNotError(t, err, "Failed to generate evidence")

	// Verify evidence
	err = provider.VerifyEvidence(evidence, attestationMainSecret, publicKeyDER, evidenceType, trustedROTs)
	assertNotError(t, err, "Failed to verify evidence")

	// Test with different evidence types
	for _, et := range []uint16{0x0001, 0x1234, 0x5678, 0xFFFF} {
		evType := mint.EvidenceType{ContentFormat: et}
		ev, err := provider.GenerateEvidence(attestationMainSecret, publicKeyDER, evType, rotName)
		assertNotError(t, err, fmt.Sprintf("Failed to generate evidence for type %d", et))
		err = provider.VerifyEvidence(ev, attestationMainSecret, publicKeyDER, evType, trustedROTs)
		assertNotError(t, err, fmt.Sprintf("Failed to verify evidence for type %d", et))
	}
}

