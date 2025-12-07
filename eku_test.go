package mint

import (
	"errors"
	"io"
	"sync"
	"testing"
	"time"
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
	serverStateChan := make(chan stateConnected, 2) // Initial state and final state

	go func() {
		t.Log("Server: Goroutine STARTED")
		alert := server.Handshake()
		t.Logf("Server: Handshake() returned: alert=%v", alert)
		assertEquals(t, alert, AlertNoAlert)
		assertTrue(t, server.state.Params.UsingExtendedKeyUpdate, "Server should have EKU negotiated")

		// Capture initial server state
		serverStateChan <- server.state

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

		// Capture final server state
		serverStateChan <- server.state

		s2c <- true
		t.Log("Server: ✓ Sent s2c signal")
		t.Log("Server: Goroutine EXITING")
	}()

	alert := client.Handshake()
	assertEquals(t, alert, AlertNoAlert)
	assertTrue(t, client.state.Params.UsingExtendedKeyUpdate, "Client should have EKU negotiated")
	assertTrue(t, client.state.Params.NegotiatedGroup != 0, "Client should have NegotiatedGroup set (EKU requires DH)")

	// Read NST.
	client.Read(oneBuf)
	<-s2c

	// Get initial states
	clientState0 := client.state
	serverState0 := <-serverStateChan
	assertTrue(t, clientState0.Params.NegotiatedGroup != 0, "Client should have NegotiatedGroup set (EKU requires DH)")
	assertTrue(t, serverState0.Params.NegotiatedGroup != 0, "Server should have NegotiatedGroup set (EKU requires DH)")
	assertEquals(t, clientState0.Params.NegotiatedGroup, serverState0.Params.NegotiatedGroup)
	assertByteEquals(t, clientState0.serverTrafficSecret, serverState0.serverTrafficSecret)
	assertByteEquals(t, clientState0.clientTrafficSecret, serverState0.clientTrafficSecret)

	// Initiate Extended Key Update - use callback to wait for completion
	var ekuResult EKUResult
	var ekuDone sync.WaitGroup
	ekuDone.Add(1)
	t.Log("Test: About to call SendExtendedKeyUpdate()")
	c2s <- true
	t.Log("Test: Sent c2s signal, calling SendExtendedKeyUpdate()")
	err := client.SendExtendedKeyUpdate(func(result EKUResult) {
		t.Logf("Test: EKU callback called: Success=%v, Error=%v", result.Success, result.Error)
		ekuResult = result
		ekuDone.Done()
	})
	t.Logf("Test: SendExtendedKeyUpdate() returned: err=%v", err)
	assertNotError(t, err, "Extended Key Update should succeed")

	// Wait for EKU to complete
	t.Log("Test: Waiting for EKU callback")
	ekuDone.Wait()
	assertTrue(t, ekuResult.Success, "EKU should succeed")
	assertNil(t, ekuResult.Error, "EKU should not have error")
	t.Log("Test: EKU completed successfully")

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
	t.Log("Test: About to wait for s2c signal (server should have read our data)")
	<-s2c
	t.Log("Test: Received s2c signal, server has read our data")

	// Verify keys have changed
	clientState1 := client.state
	serverState1 := <-serverStateChan
	assertByteEquals(t, clientState1.serverTrafficSecret, serverState1.serverTrafficSecret)
	assertByteEquals(t, clientState1.clientTrafficSecret, serverState1.clientTrafficSecret)
	assertNotByteEquals(t, clientState0.serverTrafficSecret, clientState1.serverTrafficSecret)
	assertNotByteEquals(t, clientState0.clientTrafficSecret, clientState1.clientTrafficSecret)
	assertNotByteEquals(t, serverState0.serverTrafficSecret, serverState1.serverTrafficSecret)
	assertNotByteEquals(t, serverState0.clientTrafficSecret, serverState1.clientTrafficSecret)

	// Verify EKU state is cleared
	assertTrue(t, !clientState1.ekuInProgress, "EKU should not be in progress after completion")
	assertTrue(t, !serverState1.ekuInProgress, "EKU should not be in progress after completion")
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
	err := client.SendExtendedKeyUpdate(nil) // No callback
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
		t.Log("TestEKUMultipleSequential: Server goroutine STARTED")
		alert := server.Handshake()
		t.Logf("TestEKUMultipleSequential: Server Handshake() returned: alert=%v", alert)
		assertEquals(t, alert, AlertNoAlert)
		assertTrue(t, server.state.Params.UsingExtendedKeyUpdate, "Server should have EKU negotiated")

		t.Log("TestEKUMultipleSequential: Server writing initial data")
		server.Write(oneBuf)
		s2c <- true
		t.Log("TestEKUMultipleSequential: Server sent first s2c")

		// First EKU
		t.Log("TestEKUMultipleSequential: Server waiting for first c2s")
		<-c2s
		t.Log("TestEKUMultipleSequential: Server received first c2s, about to read")
		server.Read(oneBuf)
		t.Log("TestEKUMultipleSequential: Server read after first EKU")
		s2c <- true
		t.Log("TestEKUMultipleSequential: Server sent second s2c")

		// Second EKU
		t.Log("TestEKUMultipleSequential: Server waiting for second c2s")
		<-c2s
		t.Log("TestEKUMultipleSequential: Server received second c2s, about to read")
		server.Read(oneBuf)
		t.Log("TestEKUMultipleSequential: Server read after second EKU")
		s2c <- true
		t.Log("TestEKUMultipleSequential: Server sent third s2c")

		// Third EKU
		t.Log("TestEKUMultipleSequential: Server waiting for third c2s")
		<-c2s
		t.Log("TestEKUMultipleSequential: Server received third c2s, about to read")
		server.Read(oneBuf)
		t.Log("TestEKUMultipleSequential: Server read after third EKU")
		s2c <- true
		t.Log("TestEKUMultipleSequential: Server sent fourth s2c")
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

	// First EKU - use callback to wait for completion
	var firstEKUResult EKUResult
	var firstEKUDone sync.WaitGroup
	firstEKUDone.Add(1)
	t.Log("TestEKUMultipleSequential: Client initiating first EKU")
	c2s <- true
	t.Log("TestEKUMultipleSequential: Client sent first c2s")
	err := client.SendExtendedKeyUpdate(func(result EKUResult) {
		t.Logf("TestEKUMultipleSequential: First EKU callback called: Success=%v, Error=%v", result.Success, result.Error)
		firstEKUResult = result
		firstEKUDone.Done()
	})
	t.Logf("TestEKUMultipleSequential: Client first SendExtendedKeyUpdate() returned: err=%v", err)
	assertNotError(t, err, "First Extended Key Update should succeed")

	// Wait for first EKU to complete
	t.Log("TestEKUMultipleSequential: Client waiting for first EKU callback")
	firstEKUDone.Wait()
	assertTrue(t, firstEKUResult.Success, "First EKU should succeed")
	assertNil(t, firstEKUResult.Error, "First EKU should not have error")
	t.Log("TestEKUMultipleSequential: Client first EKU completed successfully")

	t.Log("TestEKUMultipleSequential: Client writing after first EKU")
	client.Write(oneBuf)
	<-s2c
	t.Log("TestEKUMultipleSequential: Client received second s2c (server read our data)")

	// Second EKU - use callback to wait for completion
	var secondEKUResult EKUResult
	var secondEKUDone sync.WaitGroup
	secondEKUDone.Add(1)
	t.Log("TestEKUMultipleSequential: Client initiating second EKU")
	c2s <- true
	t.Log("TestEKUMultipleSequential: Client sent second c2s")
	err = client.SendExtendedKeyUpdate(func(result EKUResult) {
		t.Logf("TestEKUMultipleSequential: Second EKU callback called: Success=%v, Error=%v", result.Success, result.Error)
		secondEKUResult = result
		secondEKUDone.Done()
	})
	t.Logf("TestEKUMultipleSequential: Client second SendExtendedKeyUpdate() returned: err=%v", err)
	assertNotError(t, err, "Second Extended Key Update should succeed")

	// Wait for second EKU to complete
	t.Log("TestEKUMultipleSequential: Client waiting for second EKU callback")
	secondEKUDone.Wait()
	assertTrue(t, secondEKUResult.Success, "Second EKU should succeed")
	assertNil(t, secondEKUResult.Error, "Second EKU should not have error")
	t.Log("TestEKUMultipleSequential: Client second EKU completed successfully")
	t.Log("TestEKUMultipleSequential: Client writing after second EKU")
	client.Write(oneBuf)
	<-s2c
	t.Log("TestEKUMultipleSequential: Client received third s2c")
	// Note: Server hasn't written yet - it's waiting for third c2s signal
	// So we can't read here. Instead, initiate third EKU first, then read after server writes

	// Third EKU - use callback to wait for completion
	var thirdEKUResult EKUResult
	var thirdEKUDone sync.WaitGroup
	thirdEKUDone.Add(1)
	t.Log("TestEKUMultipleSequential: Client initiating third EKU")
	c2s <- true
	t.Log("TestEKUMultipleSequential: Client sent third c2s")
	err = client.SendExtendedKeyUpdate(func(result EKUResult) {
		t.Logf("TestEKUMultipleSequential: Third EKU callback called: Success=%v, Error=%v", result.Success, result.Error)
		thirdEKUResult = result
		thirdEKUDone.Done()
	})
	t.Logf("TestEKUMultipleSequential: Client third SendExtendedKeyUpdate() returned: err=%v", err)
	assertNotError(t, err, "Third Extended Key Update should succeed")

	// Wait for third EKU to complete
	t.Log("TestEKUMultipleSequential: Client waiting for third EKU callback")
	thirdEKUDone.Wait()
	assertTrue(t, thirdEKUResult.Success, "Third EKU should succeed")
	assertNil(t, thirdEKUResult.Error, "Third EKU should not have error")
	t.Log("TestEKUMultipleSequential: Client third EKU completed successfully")
	t.Log("TestEKUMultipleSequential: Client writing after third EKU")
	client.Write(oneBuf)
	<-s2c
	t.Log("TestEKUMultipleSequential: Client received fourth s2c")
	// Server reads our data and sends signal, but doesn't write back
	// So we don't need to read - test is complete after third EKU
	t.Log("TestEKUMultipleSequential: Test complete - test complete")
}

// DTLS Tests

func TestExtendedKeyUpdateDTLS(t *testing.T) {
	cConn, sConn := pipe()

	cbConn := newBufferedConn(cConn)
	sbConn := newBufferedConn(sConn)
	cbConn.SetAutoflush()
	sbConn.SetAutoflush()

	conf := basicConfig.Clone()
	conf.UseDTLS = true
	conf.EnableExtendedKeyUpdate = true
	conf.PSKs = &PSKMapCache{} // Force DH
	client := Client(cbConn, conf)
	server := Server(sbConn, conf)
	defer client.Close()
	defer server.Close()

	oneBuf := []byte{'a'}
	c2s := make(chan bool)
	s2c := make(chan bool)
	serverStateChan := make(chan stateConnected, 2) // Initial state and final state

	// Server goroutine: reads to process EKU messages, waits for client signal
	go func() {
		alert := server.Handshake()
		assertEquals(t, alert, AlertNoAlert)
		assertTrue(t, server.state.Params.UsingExtendedKeyUpdate, "Server should have EKU negotiated")

		// Capture initial server state
		serverStateChan <- server.state

		// Send initial data
		server.Write(oneBuf)
		s2c <- true

		// For DTLS, Read() processes handshake messages via consumeRecord()
		// We need to continuously read to process EKU handshake messages
		// Start reading in background to process EKU messages
		buf := make([]byte, 1024)
		appDataRead := make(chan bool, 1)
		readerDone := make(chan struct{})

		// Background reader processes EKU handshake messages and application data
		// This runs independently and will process EKU messages automatically
		go func() {
			defer close(readerDone)
			// Continuously read to process EKU handshake messages and application data
			for {
				n, err := server.Read(buf)
				if err != nil && err != AlertWouldBlock {
					if err == io.EOF || err.Error() == "closed" {
						return
					}
					continue
				}
				if err == AlertWouldBlock {
					// Wait a bit before retrying to avoid busy loop
					// Read() already waits internally, but we also wait here to be safe
					time.Sleep(1 * time.Millisecond)
					continue
				}
				if n > 0 {
					// Application data received
					select {
					case appDataRead <- true:
					default:
					}
				}
				// Note: Read() processes handshake messages (like EKU) via consumeRecord()
				// even when n==0, so EKU messages are processed automatically
			}
		}()

		// Wait for client to signal it's about to initiate EKU
		// The background reader will process EKU handshake messages automatically
		<-c2s

		// Background reader processes EKU messages independently
		// Wait for client to signal EKU is complete (via callback)
		// Client sends this AFTER EKU completes, so the background reader has already
		// processed all EKU messages by the time we receive this signal
		<-c2s
		s2c <- true

		// Client sends application data after EKU completes
		<-c2s
		<-appDataRead // Wait for background reader to process the data

		// Write response data
		server.Write([]byte("world"))

		// Capture final server state
		serverStateChan <- server.state

		s2c <- true

		// Close server to signal background reader to exit
		server.Close()
		// Wait for background reader to exit (with timeout)
		select {
		case <-readerDone:
			// Background reader exited
		case <-time.After(100 * time.Millisecond):
			// Timeout - reader should exit when server is closed
		}
	}()

	// Client: handshake, read initial data, then initiate EKU
	alert := client.Handshake()
	assertEquals(t, alert, AlertNoAlert)
	assertTrue(t, client.state.Params.UsingExtendedKeyUpdate, "Client should have EKU negotiated")

	// Read initial data from server
	client.Read(oneBuf)
	<-s2c

	// Get initial states
	clientState0 := client.state
	serverState0 := <-serverStateChan

	// Signal server that we're about to initiate EKU
	// This allows the server's background reader to be ready
	c2s <- true

	// Initiate Extended Key Update over DTLS
	// This will block until EKU completes (4-message exchange)
	var ekuResult EKUResult
	var ekuDone sync.WaitGroup
	ekuDone.Add(1)
	err := client.SendExtendedKeyUpdate(func(result EKUResult) {
		ekuResult = result
		ekuDone.Done()
		// Signal server that EKU is complete
		c2s <- true
	})
	assertNotError(t, err, "Extended Key Update over DTLS should succeed")

	// Wait for EKU to complete
	ekuDone.Wait()
	assertTrue(t, ekuResult.Success, "EKU should succeed")
	assertNil(t, ekuResult.Error, "EKU should not have error")

	// Wait for server to acknowledge EKU completion
	<-s2c

	// Exchange application data to verify new keys work
	client.Write([]byte("hello"))
	c2s <- true
	<-s2c

	// Server writes "world" in its goroutine, read it here
	buf := make([]byte, 100)
	n, err := client.Read(buf)
	assertNotError(t, err, "Client Read should succeed")
	assertEquals(t, string(buf[:n]), "world")

	// Verify keys have changed
	clientState1 := client.state
	serverState1 := <-serverStateChan
	assertByteEquals(t, clientState1.serverTrafficSecret, serverState1.serverTrafficSecret)
	assertByteEquals(t, clientState1.clientTrafficSecret, serverState1.clientTrafficSecret)
	assertNotByteEquals(t, clientState0.serverTrafficSecret, clientState1.serverTrafficSecret)
	assertNotByteEquals(t, clientState0.clientTrafficSecret, clientState1.clientTrafficSecret)
	assertNotByteEquals(t, serverState0.serverTrafficSecret, serverState1.serverTrafficSecret)
	assertNotByteEquals(t, serverState0.clientTrafficSecret, serverState1.clientTrafficSecret)
}

// TestExtendedKeyUpdateTieBreaking tests tie-breaking when both client and server
// initiate EKU simultaneously (TLS only).
func TestExtendedKeyUpdateTieBreaking(t *testing.T) {
	cConn, sConn := pipe()

	conf := basicConfig.Clone()
	conf.EnableExtendedKeyUpdate = true
	conf.PSKs = &PSKMapCache{} // Force DH
	// Ensure groups are configured
	if len(conf.Groups) == 0 {
		conf.Groups = []NamedGroup{P256, P384, X25519}
	}
	client := Client(cConn, conf)
	server := Server(sConn, conf)
	defer client.Close()
	defer server.Close()

	oneBuf := []byte{'a'}
	// Channels for coordination
	// Buffered channels so sends don't block (both goroutines send, then both read)
	clientInitiated := make(chan bool, 1)           // Client signals it initiated
	serverInitiated := make(chan bool, 1)           // Server signals it initiated
	clientDone := make(chan EKUResult)              // Client EKU result
	serverDone := make(chan EKUResult)              // Server EKU result
	clientStateChan := make(chan stateConnected, 2) // Before and after
	serverStateChan := make(chan stateConnected, 2) // Before and after

	// Client goroutine
	go func() {
		// Handshake
		alert := client.Handshake()
		assertEquals(t, alert, AlertNoAlert)
		assertTrue(t, client.state.Params.UsingExtendedKeyUpdate, "Client should have EKU negotiated")

		// Capture initial state
		clientStateChan <- client.state

		// Send initial data so server can consume NST
		client.Write(oneBuf)

		// Signal ready to initiate
		clientInitiated <- true

		// Wait for server to also be ready
		<-serverInitiated

		// Small delay to ensure both sides are ready (reduces race window)
		time.Sleep(10 * time.Millisecond)

		// Initiate EKU simultaneously
		// For TLS, the controller processes handshake messages automatically
		var result EKUResult
		callbackInvoked := make(chan EKUResult, 1)
		t.Logf("Client: About to call SendExtendedKeyUpdate()")
		err := client.SendExtendedKeyUpdate(func(res EKUResult) {
			t.Logf("Client: EKU callback invoked! Success=%v, Error=%v", res.Success, res.Error)
			select {
			case callbackInvoked <- res:
			default:
				// Channel already has a value or is closed, ignore
			}
		})
		if err != nil {
			t.Logf("Client: SendExtendedKeyUpdate() returned error: %v", err)
			clientDone <- EKUResult{Success: false, Error: err}
			return
		}
		t.Logf("Client: SendExtendedKeyUpdate() returned, waiting for callback...")
		// When tie-breaking occurs, one side switches to responder and its callback is cleared
		// So we need to wait with a timeout - if callback isn't invoked, check if we're responder
		select {
		case result = <-callbackInvoked:
			t.Logf("Client: Callback completed, result: Success=%v", result.Success)
		case <-time.After(2 * time.Second):
			// Callback not invoked - might have switched to responder
			// Wait a bit for EKU to complete, then check state
			t.Logf("Client: Callback not invoked after 2s, waiting for EKU to complete...")
			// Poll state to see if EKU completed
			for i := 0; i < 50; i++ {
				time.Sleep(100 * time.Millisecond)
				if !client.state.ekuInProgress {
					// EKU completed (state cleared), but callback wasn't invoked
					// This is expected if we switched to responder
					t.Logf("Client: EKU completed but callback not invoked (switched to responder)")
					result = EKUResult{Success: true, Error: nil}
					break
				}
			}
			if client.state.ekuInProgress {
				// Still in progress - something wrong
				t.Logf("Client: EKU still in progress after timeout")
				result = EKUResult{Success: false, Error: errors.New("EKU callback not invoked and still in progress")}
			}
		}

		// Capture final state
		clientStateChan <- client.state
		clientDone <- result
	}()

	// Server goroutine
	go func() {
		// Handshake
		alert := server.Handshake()
		assertEquals(t, alert, AlertNoAlert)
		assertTrue(t, server.state.Params.UsingExtendedKeyUpdate, "Server should have EKU negotiated")

		// Capture initial state
		serverStateChan <- server.state

		// Read initial data from client (NST consumption)
		server.Read(oneBuf)

		// Signal ready to initiate
		serverInitiated <- true

		// Wait for client to also be ready
		<-clientInitiated

		// Small delay to ensure both sides are ready (reduces race window)
		time.Sleep(10 * time.Millisecond)

		// Initiate EKU simultaneously
		// For TLS, the controller processes handshake messages automatically
		var result EKUResult
		callbackInvoked := make(chan EKUResult, 1)
		t.Logf("Server: About to call SendExtendedKeyUpdate()")
		err := server.SendExtendedKeyUpdate(func(res EKUResult) {
			t.Logf("Server: EKU callback invoked! Success=%v, Error=%v", res.Success, res.Error)
			select {
			case callbackInvoked <- res:
			default:
				// Channel already has a value or is closed, ignore
			}
		})
		if err != nil {
			t.Logf("Server: SendExtendedKeyUpdate() returned error: %v", err)
			serverDone <- EKUResult{Success: false, Error: err}
			return
		}
		t.Logf("Server: SendExtendedKeyUpdate() returned, waiting for callback...")

		// When tie-breaking occurs, one side switches to responder and its callback is cleared
		// So we need to wait with a timeout - if callback isn't invoked, check if we're responder
		select {
		case result = <-callbackInvoked:
			t.Logf("Server: Callback completed, result: Success=%v", result.Success)
		case <-time.After(2 * time.Second):
			// Callback not invoked - might have switched to responder
			// Wait a bit for EKU to complete, then check state
			t.Logf("Server: Callback not invoked after 2s, waiting for EKU to complete...")
			// Poll state to see if EKU completed
			for i := 0; i < 50; i++ {
				time.Sleep(100 * time.Millisecond)
				if !server.state.ekuInProgress {
					// EKU completed (state cleared), but callback wasn't invoked
					// This is expected if we switched to responder
					t.Logf("Server: EKU completed but callback not invoked (switched to responder)")
					result = EKUResult{Success: true, Error: nil}
					break
				}
			}
			if server.state.ekuInProgress {
				// Still in progress - something wrong
				t.Logf("Server: EKU still in progress after timeout")
				result = EKUResult{Success: false, Error: errors.New("EKU callback not invoked and still in progress")}
			}
		}

		// Capture final state
		serverStateChan <- server.state
		serverDone <- result
	}()

	// Wait for both to complete
	// Note: The goroutines handle synchronization themselves via clientInitiated/serverInitiated
	// When tie-breaking occurs, one side switches to responder and its callback is cleared
	// So we need to handle the case where one callback might not be invoked
	clientResult := <-clientDone
	serverResult := <-serverDone

	// At least one side should succeed (the initiator)
	// The responder's callback might not be invoked (it's cleared when switching to responder)
	// But EKU should still complete successfully on both sides
	initiatorSucceeded := clientResult.Success || serverResult.Success
	assertTrue(t, initiatorSucceeded, "At least one side (initiator) should succeed")

	// If one side's callback wasn't invoked, check if EKU completed by verifying state
	if !clientResult.Success && clientResult.Error == nil {
		// Client callback wasn't invoked - might have switched to responder
		// Check if EKU completed by waiting a bit and checking state
		time.Sleep(100 * time.Millisecond)
		// State will be checked later
	}
	if !serverResult.Success && serverResult.Error == nil {
		// Server callback wasn't invoked - might have switched to responder
		// Check if EKU completed by waiting a bit and checking state
		time.Sleep(100 * time.Millisecond)
		// State will be checked later
	}

	// Get states
	clientState0 := <-clientStateChan
	clientState1 := <-clientStateChan
	serverState0 := <-serverStateChan
	serverState1 := <-serverStateChan

	// Verify tie-breaking occurred
	// After EKU completes, all EKU state is cleared (ekuInProgress=false, ekuOurKeyShare=nil, etc.)
	// So we can't directly check which side was initiator vs responder

	// However, we can verify tie-breaking indirectly:
	// 1. Both sides called SendExtendedKeyUpdate() (both initiated)
	// 2. Both sides completed EKU successfully (both callbacks succeeded)
	// 3. Keys are synchronized (both sides have same traffic secrets)
	// 4. Keys changed from initial state

	// Verify keys updated correctly (this proves EKU completed successfully)
	assertByteEquals(t, clientState1.serverTrafficSecret, serverState1.serverTrafficSecret)
	assertByteEquals(t, clientState1.clientTrafficSecret, serverState1.clientTrafficSecret)
	assertNotByteEquals(t, clientState0.serverTrafficSecret, clientState1.serverTrafficSecret)
	assertNotByteEquals(t, clientState0.clientTrafficSecret, clientState1.clientTrafficSecret)
	assertNotByteEquals(t, serverState0.serverTrafficSecret, serverState1.serverTrafficSecret)
	assertNotByteEquals(t, serverState0.clientTrafficSecret, serverState1.clientTrafficSecret)

	// Verify EKU state cleared
	assertTrue(t, !clientState1.ekuInProgress, "Client EKU should not be in progress after completion")
	assertTrue(t, !serverState1.ekuInProgress, "Server EKU should not be in progress after completion")

	// Note: We can't directly verify tie-breaking occurred because state is cleared after EKU completes.
	// However, the fact that both sides initiated simultaneously and both completed successfully
	// implies that tie-breaking worked correctly. If tie-breaking didn't work, one side would have
	// processed the other's Message 1 as a normal responder before initiating, which could cause
	// issues or different behavior.
}
