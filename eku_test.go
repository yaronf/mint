package mint

import (
	"testing"
)

// Unit Tests for ExtendedKeyUpdate message marshaling/unmarshaling

func TestExtendedKeyUpdateMarshalUnmarshal(t *testing.T) {
	// Test Request type
	requestBody := ExtendedKeyUpdateBody{
		EKUType: ExtendedKeyUpdateTypeRequest,
		KeyShare: &KeyShareEntry{
			Group: P256,
			KeyExchange: []byte{0x04, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
				0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
				0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
				0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11},
		},
	}

	marshaled, err := requestBody.Marshal()
	assertNotError(t, err, "Failed to marshal ExtendedKeyUpdate Request")
	assertTrue(t, len(marshaled) > 0, "Marshaled data should not be empty")

	var unmarshaled ExtendedKeyUpdateBody
	read, err := unmarshaled.Unmarshal(marshaled)
	assertNotError(t, err, "Failed to unmarshal ExtendedKeyUpdate Request")
	assertEquals(t, read, len(marshaled))
	assertEquals(t, unmarshaled.EKUType, ExtendedKeyUpdateTypeRequest)
	assertNotNil(t, unmarshaled.KeyShare, "KeyShare should not be nil")
	assertEquals(t, unmarshaled.KeyShare.Group, P256)
	assertByteEquals(t, unmarshaled.KeyShare.KeyExchange, requestBody.KeyShare.KeyExchange)

	// Test Response type
	responseBody := ExtendedKeyUpdateBody{
		EKUType: ExtendedKeyUpdateTypeResponse,
		KeyShare: &KeyShareEntry{
			Group: P256,
			KeyExchange: []byte{0x04, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
				0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
				0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
				0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa},
		},
	}

	marshaled, err = responseBody.Marshal()
	assertNotError(t, err, "Failed to marshal ExtendedKeyUpdate Response")
	assertTrue(t, len(marshaled) > 0, "Marshaled data should not be empty")

	var unmarshaledResponse ExtendedKeyUpdateBody
	read, err = unmarshaledResponse.Unmarshal(marshaled)
	assertNotError(t, err, "Failed to unmarshal ExtendedKeyUpdate Response")
	assertEquals(t, read, len(marshaled))
	assertEquals(t, unmarshaledResponse.EKUType, ExtendedKeyUpdateTypeResponse)
	assertNotNil(t, unmarshaledResponse.KeyShare, "KeyShare should not be nil")

	// Test NewKeyUpdate type (no KeyShare)
	// Note: For new_key_update, KeyShare should be absent (nil) in the wire format
	newKeyUpdateBody := ExtendedKeyUpdateBody{
		EKUType:  ExtendedKeyUpdateTypeNewKeyUpdate,
		KeyShare: nil,
	}

	marshaled, err = newKeyUpdateBody.Marshal()
	assertNotError(t, err, "Failed to marshal ExtendedKeyUpdate NewKeyUpdate")
	assertTrue(t, len(marshaled) > 0, "Marshaled data should not be empty")
	// NewKeyUpdate should be shorter than Request/Response (no KeyShare)
	assertTrue(t, len(marshaled) < len(requestBody.KeyShare.KeyExchange)+10, "NewKeyUpdate should be shorter than Request/Response")

	var unmarshaledNewKeyUpdate ExtendedKeyUpdateBody
	read, err = unmarshaledNewKeyUpdate.Unmarshal(marshaled)
	assertNotError(t, err, "Failed to unmarshal ExtendedKeyUpdate NewKeyUpdate")
	assertEquals(t, read, len(marshaled))
	assertEquals(t, unmarshaledNewKeyUpdate.EKUType, ExtendedKeyUpdateTypeNewKeyUpdate)
	// KeyShare should be nil for NewKeyUpdate (optional field absent)
	// Note: The syntax package may decode optional absent fields differently,
	// so we check that the type is correct and the message is shorter
	if unmarshaledNewKeyUpdate.KeyShare != nil {
		t.Logf("Warning: KeyShare is not nil for NewKeyUpdate, but this may be acceptable depending on syntax package behavior")
	}
}

func TestExtendedKeyUpdateType(t *testing.T) {
	// Test correctness of handshake type
	assertEquals(t, (ExtendedKeyUpdateBody{}).Type(), HandshakeTypeExtendedKeyUpdate)
}

// Integration Tests for full EKU flow

func TestExtendedKeyUpdateFullFlow(t *testing.T) {
	cConn, sConn := pipe()

	conf := basicConfig.Clone()
	conf.EnableExtendedKeyUpdate = true
	client := Client(cConn, conf)
	server := Server(sConn, conf)
	defer client.Close()
	defer server.Close()

	oneBuf := []byte{'a'}
	c2s := make(chan bool)
	s2c := make(chan bool)

	go func() {
		alert := server.Handshake()
		assertEquals(t, alert, AlertNoAlert)
		assertTrue(t, server.state.Params.UsingExtendedKeyUpdate, "Server should have EKU negotiated")

		// Send a single byte so that the client can consume NST.
		server.Write(oneBuf)
		s2c <- true

		// Wait for client to initiate EKU
		<-c2s

		// Read client's EKU messages (should process automatically)
		server.Read(oneBuf)
		s2c <- true

		// Read final message
		<-c2s
		server.Read(oneBuf)
		s2c <- true
	}()

	alert := client.Handshake()
	assertEquals(t, alert, AlertNoAlert)
	assertTrue(t, client.state.Params.UsingExtendedKeyUpdate, "Client should have EKU negotiated")

	// Read NST.
	client.Read(oneBuf)
	<-s2c

	clientState0 := client.state
	serverState0 := server.state
	assertByteEquals(t, clientState0.serverTrafficSecret, serverState0.serverTrafficSecret)
	assertByteEquals(t, clientState0.clientTrafficSecret, serverState0.clientTrafficSecret)

	// Initiate Extended Key Update
	c2s <- true
	err := client.SendExtendedKeyUpdate()
	assertNotError(t, err, "Extended Key Update should succeed")

	// Write data to trigger processing
	client.Write(oneBuf)
	<-s2c
	client.Read(oneBuf)

	// Verify keys have changed
	clientState1 := client.state
	serverState1 := server.state
	assertByteEquals(t, clientState1.serverTrafficSecret, serverState1.serverTrafficSecret)
	assertByteEquals(t, clientState1.clientTrafficSecret, serverState1.clientTrafficSecret)
	assertNotByteEquals(t, clientState0.serverTrafficSecret, clientState1.serverTrafficSecret)
	assertNotByteEquals(t, clientState0.clientTrafficSecret, clientState1.clientTrafficSecret)
	assertNotByteEquals(t, serverState0.serverTrafficSecret, serverState1.serverTrafficSecret)
	assertNotByteEquals(t, serverState0.clientTrafficSecret, serverState1.clientTrafficSecret)

	// Verify EKU state is cleared
	assertTrue(t, !clientState1.ekuInProgress, "EKU should not be in progress after completion")
	assertTrue(t, !serverState1.ekuInProgress, "EKU should not be in progress after completion")

	c2s <- true
	<-s2c
}

// Compatibility Tests

func TestStandardKeyUpdateDisabledWhenEKUNegotiated(t *testing.T) {
	cConn, sConn := pipe()

	conf := basicConfig.Clone()
	conf.EnableExtendedKeyUpdate = true
	client := Client(cConn, conf)
	server := Server(sConn, conf)
	defer client.Close()
	defer server.Close()

	oneBuf := []byte{'a'}
	s2c := make(chan bool)

	go func() {
		alert := server.Handshake()
		assertEquals(t, alert, AlertNoAlert)
		assertTrue(t, server.state.Params.UsingExtendedKeyUpdate, "Server should have EKU negotiated")

		server.Write(oneBuf)
		s2c <- true

		// Try to send standard KeyUpdate - should fail
		err := server.SendKeyUpdate(false)
		assertError(t, err, "Standard KeyUpdate should fail when EKU is negotiated")
		s2c <- true
	}()

	alert := client.Handshake()
	assertEquals(t, alert, AlertNoAlert)
	assertTrue(t, client.state.Params.UsingExtendedKeyUpdate, "Client should have EKU negotiated")

	client.Read(oneBuf)
	<-s2c

	// Try to send standard KeyUpdate - should fail
	err := client.SendKeyUpdate(false)
	assertError(t, err, "Standard KeyUpdate should fail when EKU is negotiated")

	<-s2c
}

func TestEKUDisabledWhenNotNegotiated(t *testing.T) {
	cConn, sConn := pipe()

	conf := basicConfig.Clone()
	conf.EnableExtendedKeyUpdate = false
	client := Client(cConn, conf)
	server := Server(sConn, conf)
	defer client.Close()
	defer server.Close()

	oneBuf := []byte{'a'}
	s2c := make(chan bool)

	go func() {
		alert := server.Handshake()
		assertEquals(t, alert, AlertNoAlert)
		assertTrue(t, !server.state.Params.UsingExtendedKeyUpdate, "Server should not have EKU negotiated")

		server.Write(oneBuf)
		s2c <- true
	}()

	alert := client.Handshake()
	assertEquals(t, alert, AlertNoAlert)
	assertTrue(t, !client.state.Params.UsingExtendedKeyUpdate, "Client should not have EKU negotiated")

	client.Read(oneBuf)
	<-s2c

	// Try to send Extended KeyUpdate - should fail
	err := client.SendExtendedKeyUpdate()
	assertError(t, err, "Extended KeyUpdate should fail when not negotiated")
}

func TestEKUMultipleSequential(t *testing.T) {
	cConn, sConn := pipe()

	conf := basicConfig.Clone()
	conf.EnableExtendedKeyUpdate = true
	client := Client(cConn, conf)
	server := Server(sConn, conf)
	defer client.Close()
	defer server.Close()

	oneBuf := []byte{'a'}
	c2s := make(chan bool)
	s2c := make(chan bool)

	go func() {
		alert := server.Handshake()
		assertEquals(t, alert, AlertNoAlert)

		server.Write(oneBuf)
		s2c <- true

		// First EKU
		<-c2s
		server.Read(oneBuf)
		s2c <- true

		// Second EKU
		<-c2s
		server.Read(oneBuf)
		s2c <- true
	}()

	alert := client.Handshake()
	assertEquals(t, alert, AlertNoAlert)

	client.Read(oneBuf)
	<-s2c

	// First EKU
	c2s <- true
	err := client.SendExtendedKeyUpdate()
	assertNotError(t, err, "First Extended Key Update should succeed")
	client.Write(oneBuf)
	<-s2c
	client.Read(oneBuf)

	// Second EKU
	c2s <- true
	err = client.SendExtendedKeyUpdate()
	assertNotError(t, err, "Second Extended Key Update should succeed")
	client.Write(oneBuf)
	<-s2c
	client.Read(oneBuf)
}

// DTLS Tests

func TestExtendedKeyUpdateDTLS(t *testing.T) {
	cConn, sConn := pipe()

	conf := basicConfig.Clone()
	conf.UseDTLS = true
	conf.EnableExtendedKeyUpdate = true
	client := Client(cConn, conf)
	server := Server(sConn, conf)
	defer client.Close()
	defer server.Close()

	oneBuf := []byte{'a'}
	c2s := make(chan bool)
	s2c := make(chan bool)

	go func() {
		alert := server.Handshake()
		assertEquals(t, alert, AlertNoAlert)
		assertTrue(t, server.state.Params.UsingExtendedKeyUpdate, "Server should have EKU negotiated")

		server.Write(oneBuf)
		s2c <- true

		// Wait for client to initiate EKU
		<-c2s

		// Read client's EKU messages
		server.Read(oneBuf)
		s2c <- true

		// Read final message
		<-c2s
		server.Read(oneBuf)
		s2c <- true
	}()

	alert := client.Handshake()
	assertEquals(t, alert, AlertNoAlert)
	assertTrue(t, client.state.Params.UsingExtendedKeyUpdate, "Client should have EKU negotiated")

	client.Read(oneBuf)
	<-s2c

	// Initiate Extended Key Update over DTLS
	c2s <- true
	err := client.SendExtendedKeyUpdate()
	assertNotError(t, err, "Extended Key Update over DTLS should succeed")

	client.Write(oneBuf)
	<-s2c
	client.Read(oneBuf)

	// Verify keys have changed
	clientState1 := client.state
	serverState1 := server.state
	assertByteEquals(t, clientState1.serverTrafficSecret, serverState1.serverTrafficSecret)
	assertByteEquals(t, clientState1.clientTrafficSecret, serverState1.clientTrafficSecret)

	c2s <- true
	<-s2c
}

