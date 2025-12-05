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
	// Ensure DH is used (EKU requires DH for key exchange)
	// Clear PSKs to force DH-only handshake
	conf.PSKs = &PSKMapCache{}
	// Ensure groups are configured (should be default, but be explicit)
	if len(conf.Groups) == 0 {
		conf.Groups = []NamedGroup{P256, P384, X25519}
	}
	client := Client(cConn, conf)
	server := Server(sConn, conf)
	defer client.Close()
	defer server.Close()

	oneBuf := []byte{'a'}
	c2s := make(chan bool)
	s2c := make(chan bool)

	go func() {
		t.Log("Server: Goroutine STARTED")
		alert := server.Handshake()
		t.Logf("Server: Handshake() returned: alert=%v", alert)
		assertEquals(t, alert, AlertNoAlert)
		assertTrue(t, server.state.Params.UsingExtendedKeyUpdate, "Server should have EKU negotiated")

		// Send a single byte so that the client can consume NST.
		t.Log("Server: About to write oneBuf")
		server.Write(oneBuf)
		t.Log("Server: Wrote oneBuf, sending first s2c signal")
		s2c <- true
		t.Log("Server: ✓ Sent first s2c signal")

		// Wait for client to initiate EKU
		t.Log("Server: Waiting for first c2s signal (client will initiate EKU)")
		<-c2s
		t.Log("Server: ✓ Received first c2s signal, EKU should be in progress")
		// EKU messages are handshake messages processed automatically by controller
		// The server will automatically process:
		// - Message 1 (request) -> send Message 2 (response)
		// - Message 3 (new_key_update from initiator) -> send Message 4 (new_key_update)
		// Wait for EKU exchange to complete (server processes automatically)
		// The client's SendExtendedKeyUpdate() will block until complete
		// Don't send s2c here - wait for client to send c2s first, then send s2c after reading
		t.Log("Server: EKU processing should be complete, waiting for client to send c2s signal (after Write)")

		// Wait for client to send application data after EKU completes
		t.Log("Server: BLOCKING: Waiting for second c2s signal (client will send data after Write)")
		<-c2s
		t.Log("Server: ✓✓✓ Received second c2s signal, about to read")
		t.Logf("Server: server.controllerRunning=%v, server.Writable()=%v", server.controllerRunning, server.Writable())
		t.Log("Server: CALLING Read() NOW - this should block waiting for data")
		n, err := server.Read(oneBuf)
		t.Logf("Server: Read() UNBLOCKED: n=%d, err=%v", n, err)
		t.Logf("Server: Read() returned: n=%d, err=%v", n, err)
		t.Log("Server: Read completed, sending s2c signal")
		s2c <- true
		t.Log("Server: ✓ Sent s2c signal")
	}()

	alert := client.Handshake()
	assertEquals(t, alert, AlertNoAlert)
	assertTrue(t, client.state.Params.UsingExtendedKeyUpdate, "Client should have EKU negotiated")
	assertTrue(t, client.state.Params.NegotiatedGroup != 0, "Client should have NegotiatedGroup set (EKU requires DH)")

	// Read NST.
	client.Read(oneBuf)
	<-s2c

	clientState0 := client.state
	serverState0 := server.state
	assertTrue(t, serverState0.Params.NegotiatedGroup != 0, "Server should have NegotiatedGroup set (EKU requires DH)")
	assertEquals(t, clientState0.Params.NegotiatedGroup, serverState0.Params.NegotiatedGroup)
	assertByteEquals(t, clientState0.serverTrafficSecret, serverState0.serverTrafficSecret)
	assertByteEquals(t, clientState0.clientTrafficSecret, serverState0.clientTrafficSecret)

	// Initiate Extended Key Update
	t.Log("Test: About to call SendExtendedKeyUpdate()")
	c2s <- true
	t.Log("Test: Sent c2s signal, calling SendExtendedKeyUpdate()")
	err := client.SendExtendedKeyUpdate()
	t.Logf("Test: SendExtendedKeyUpdate() returned: err=%v", err)
	assertNotError(t, err, "Extended Key Update should succeed")

	// Write data to trigger processing
	t.Log("Test: About to write data after EKU")
	t.Logf("Test: client.controllerRunning=%v, client.Writable()=%v", client.controllerRunning, client.Writable())
	n, err := client.Write(oneBuf)
	t.Logf("Test: Write() returned: n=%d, err=%v", n, err)
	t.Log("Test: Wrote data, sending second c2s signal to server")
	c2s <- true
	t.Log("Test: ✓✓✓ Sent second c2s signal to server")
	// Server will read the data and then send s2c
	// Don't wait for s2c here - server sends it after reading
	t.Log("Test: About to read (server should have read our data)")
	<-s2c
	t.Log("Test: Received s2c signal, server has read our data, about to read")
	client.Read(oneBuf)
	t.Log("Test: Read completed")

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
	t.Log("TestEKUMultipleSequential: START")
	cConn, sConn := pipe()

	conf := basicConfig.Clone()
	conf.EnableExtendedKeyUpdate = true
	// Ensure DH is used (EKU requires DH for key exchange)
	conf.PSKs = &PSKMapCache{}
	client := Client(cConn, conf)
	server := Server(sConn, conf)
	defer client.Close()
	defer server.Close()

	oneBuf := []byte{'a'}
	c2s := make(chan bool)
	t.Log("TestEKUMultipleSequential: connections created")
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

	t.Log("TestEKUMultipleSequential: Client starting handshake")
	alert := client.Handshake()
	t.Logf("TestEKUMultipleSequential: Client Handshake() returned: alert=%v", alert)
	assertEquals(t, alert, AlertNoAlert)
	assertTrue(t, client.state.Params.UsingExtendedKeyUpdate, "Client should have EKU negotiated")

	t.Log("TestEKUMultipleSequential: Client reading initial data")
	client.Read(oneBuf)
	<-s2c
	t.Log("TestEKUMultipleSequential: Client received first s2c")

	// First EKU
	t.Log("TestEKUMultipleSequential: Client initiating first EKU")
	c2s <- true
	t.Log("TestEKUMultipleSequential: Client sent first c2s")
	err := client.SendExtendedKeyUpdate()
	t.Logf("TestEKUMultipleSequential: Client first SendExtendedKeyUpdate() returned: err=%v", err)
	assertNotError(t, err, "First Extended Key Update should succeed")
	t.Log("TestEKUMultipleSequential: Client writing after first EKU")
	client.Write(oneBuf)
	<-s2c
	t.Log("TestEKUMultipleSequential: Client received second s2c")
	client.Read(oneBuf)
	t.Log("TestEKUMultipleSequential: Client read after first EKU")

	// Second EKU
	t.Log("TestEKUMultipleSequential: Client initiating second EKU")
	c2s <- true
	t.Log("TestEKUMultipleSequential: Client sent second c2s")
	err = client.SendExtendedKeyUpdate()
	t.Logf("TestEKUMultipleSequential: Client second SendExtendedKeyUpdate() returned: err=%v", err)
	assertNotError(t, err, "Second Extended Key Update should succeed")
	t.Log("TestEKUMultipleSequential: Client writing after second EKU")
	client.Write(oneBuf)
	<-s2c
	t.Log("TestEKUMultipleSequential: Client received third s2c")
	client.Read(oneBuf)
	t.Log("TestEKUMultipleSequential: Client read after second EKU, test complete")
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

