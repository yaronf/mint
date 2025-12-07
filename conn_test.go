package mint

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"go.uber.org/goleak"
)

type pipeConn struct {
	closed bool
	r      *bytes.Buffer
	w      *bytes.Buffer
	rLock  *sync.Mutex
	wLock  *sync.Mutex
	name   string // For debugging: "client" or "server"
}

// closeAndVerifyNoLeaks closes connections and verifies no goroutine leaks
func closeAndVerifyNoLeaks(t *testing.T, conns ...*Conn) {
	for _, conn := range conns {
		if conn != nil {
			conn.Close()
		}
	}
	// Give goroutines a moment to exit
	time.Sleep(10 * time.Millisecond)
	goleak.VerifyNone(t)
}

func pipe() (client *pipeConn, server *pipeConn) {
	client = new(pipeConn)
	server = new(pipeConn)
	client.name = "client"
	server.name = "server"

	c2s := bytes.NewBuffer(nil)
	server.r = c2s
	client.w = c2s

	c2sLock := new(sync.Mutex)
	server.rLock = c2sLock
	client.wLock = c2sLock

	s2c := bytes.NewBuffer(nil)
	client.r = s2c
	server.w = s2c

	s2cLock := new(sync.Mutex)
	client.rLock = s2cLock
	server.wLock = s2cLock
	return
}

func (p *pipeConn) Read(data []byte) (n int, err error) {
	p.rLock.Lock()
	defer p.rLock.Unlock()

	if p.closed {
		// If closed and buffer is empty, return io.EOF immediately
		// This allows ReadRecord() to return io.EOF and exit loops properly
		if p.r.Len() == 0 {
			return 0, io.EOF
		}
		// If closed but buffer has data, read it first, then return io.EOF next time
		return 0, errors.New("closed")
	}
	bufLenBefore := p.r.Len()
	n, err = p.r.Read(data)
	bufLenAfter := p.r.Len()
	// Log buffer state for debugging EKU issues (always log to see empty reads too)
	logf(logTypeIO, "%s pipeConn.Read: buffer before=%d, read=%d, buffer after=%d, err=%v", p.name, bufLenBefore, n, bufLenAfter, err)
	// If buffer is empty and connection is closed, return io.EOF
	// This allows record-layer to properly handle connection closure
	if n == 0 && err == nil && p.r.Len() == 0 && p.closed {
		return 0, io.EOF
	}
	// Suppress bytes.Buffer's EOF on an empty buffer (but only if connection is not closed)
	// This allows the record layer to return AlertWouldBlock for empty reads when connection is still open
	if err == io.EOF {
		err = nil
	}
	return
}

func (p *pipeConn) Write(data []byte) (n int, err error) {
	p.wLock.Lock()
	defer p.wLock.Unlock()
	if p.closed {
		return 0, errors.New("closed")
	}
	bufLenBefore := p.w.Len()
	n, err = p.w.Write(data)
	bufLenAfter := p.w.Len()
	// Log writes for debugging EKU issues (only log handshake messages to avoid spam)
	if len(data) > 5 && data[0] == 0x17 { // TLS handshake record
		logf(logTypeIO, "%s pipeConn.Write: wrote %d bytes (handshake record), buffer before=%d, buffer after=%d", p.name, n, bufLenBefore, bufLenAfter)
	}
	return n, err
}

func (p *pipeConn) Close() error {
	p.rLock.Lock()
	p.wLock.Lock()
	p.closed = true
	p.wLock.Unlock()
	p.rLock.Unlock()
	return nil
}

func (p *pipeConn) LocalAddr() net.Addr                { return nil }
func (p *pipeConn) RemoteAddr() net.Addr               { return nil }
func (p *pipeConn) SetDeadline(t time.Time) error      { return nil }
func (p *pipeConn) SetReadDeadline(t time.Time) error  { return nil }
func (p *pipeConn) SetWriteDeadline(t time.Time) error { return nil }
func (p *pipeConn) Empty() bool                        { return p.r.Len() == 0 }

type bufferedConn struct {
	autoflush    bool
	buffer       bytes.Buffer
	w            net.Conn
	writeCounter int
	lostWrite    map[int]bool
}

func (b *bufferedConn) Write(buf []byte) (int, error) {
	ctr := b.writeCounter
	b.writeCounter++
	if b.lostWrite[ctr] {
		return 0, nil
	}

	n, err := b.buffer.Write(buf)
	if err != nil {
		return 0, err
	}
	if n != len(buf) {
		return n, fmt.Errorf("Incomplete write")
	}
	if b.autoflush {
		err := b.Flush()
		if err != nil {
			return 0, err
		}
	}
	return 0, nil
}

func (p *bufferedConn) Read(data []byte) (n int, err error) {
	return p.w.Read(data)
}
func (p *bufferedConn) Close() error {
	// Forward Close() to underlying connection so it can signal closure
	return p.w.Close()
}

func (p *bufferedConn) LocalAddr() net.Addr                { return nil }
func (p *bufferedConn) RemoteAddr() net.Addr               { return nil }
func (p *bufferedConn) SetDeadline(t time.Time) error      { return nil }
func (p *bufferedConn) SetReadDeadline(t time.Time) error  { return nil }
func (p *bufferedConn) SetWriteDeadline(t time.Time) error { return nil }
func (b *bufferedConn) SetAutoflush() {
	b.autoflush = true
}
func (b *bufferedConn) Empty() bool {
	p := b.w.(*pipeConn)
	return p.Empty()
}

func (b *bufferedConn) Flush() error {
	buf := b.buffer.Bytes()

	n, err := b.w.Write(buf)
	if err != nil {
		return err
	}
	if n != len(buf) {
		return fmt.Errorf("Incomplete flush")
	}
	b.buffer.Reset()
	return nil
}

func (b *bufferedConn) Lose(m int) {
	b.lostWrite[m] = true
}

func (b *bufferedConn) Clear() {
	b.buffer.Reset()
}

func newBufferedConn(p net.Conn) *bufferedConn {
	return &bufferedConn{
		autoflush: false,
		buffer:    bytes.Buffer{},
		w:         p,
		lostWrite: make(map[int]bool, 0),
	}
}

var (
	serverKey, clientKey             crypto.Signer
	serverCert, clientCert           *x509.Certificate
	certificates, clientCertificates []*Certificate
	clientName, serverName           string

	psk  PreSharedKey
	psks *PSKMapCache

	basicConfig, dtlsConfig, nbConfig, nbDTLSConfig, hrrConfig, alpnConfig, pskConfig, pskDTLSConfig, pskECDHEConfig, pskDHEConfig, resumptionConfig, ffdhConfig, x25519Config *Config
)

func init() {
	var err error

	serverName = "example.com"
	clientName = "example.org"

	serverKey, serverCert, err = MakeNewSelfSignedCert(serverName, ECDSA_P256_SHA256)
	if err != nil {
		panic(err)
	}
	clientKey, clientCert, err = MakeNewSelfSignedCert(clientName, ECDSA_P256_SHA256)
	if err != nil {
		panic(err)
	}

	psk = PreSharedKey{
		CipherSuite:  TLS_AES_128_GCM_SHA256,
		IsResumption: false,
		Identity:     []byte{0, 1, 2, 3},
		Key:          []byte{4, 5, 6, 7},
	}
	certificates = []*Certificate{
		{
			Chain:      []*x509.Certificate{serverCert},
			PrivateKey: serverKey,
		},
	}
	clientCertificates = []*Certificate{
		{
			Chain:      []*x509.Certificate{clientCert},
			PrivateKey: clientKey,
		},
	}
	psks = &PSKMapCache{
		serverName: psk,
		"00010203": psk,
	}

	basicConfig = &Config{
		ServerName:         serverName,
		Certificates:       certificates,
		InsecureSkipVerify: true,
	}

	dtlsConfig = &Config{
		ServerName:         serverName,
		Certificates:       certificates,
		UseDTLS:            true,
		InsecureSkipVerify: true,
	}

	nbConfig = &Config{
		ServerName:         serverName,
		Certificates:       certificates,
		NonBlocking:        true,
		InsecureSkipVerify: true,
	}

	nbDTLSConfig = &Config{
		ServerName:         serverName,
		Certificates:       certificates,
		NonBlocking:        true,
		UseDTLS:            true,
		InsecureSkipVerify: true,
	}

	hrrConfig = &Config{
		ServerName:         serverName,
		Certificates:       certificates,
		RequireCookie:      true,
		InsecureSkipVerify: true,
	}

	alpnConfig = &Config{
		ServerName:         serverName,
		Certificates:       certificates,
		NextProtos:         []string{"http/1.1", "h2"},
		InsecureSkipVerify: true,
	}

	pskConfig = &Config{
		ServerName:         serverName,
		CipherSuites:       []CipherSuite{TLS_AES_128_GCM_SHA256},
		PSKs:               psks,
		AllowEarlyData:     true,
		InsecureSkipVerify: true,
	}

	pskDTLSConfig = &Config{
		ServerName:         serverName,
		CipherSuites:       []CipherSuite{TLS_AES_128_GCM_SHA256},
		PSKs:               psks,
		AllowEarlyData:     true,
		UseDTLS:            true,
		NonBlocking:        true,
		InsecureSkipVerify: true,
	}

	pskECDHEConfig = &Config{
		ServerName:         serverName,
		CipherSuites:       []CipherSuite{TLS_AES_128_GCM_SHA256},
		Certificates:       certificates,
		PSKs:               psks,
		InsecureSkipVerify: true,
	}

	pskDHEConfig = &Config{
		ServerName:         serverName,
		CipherSuites:       []CipherSuite{TLS_AES_128_GCM_SHA256},
		Certificates:       certificates,
		PSKs:               psks,
		Groups:             []NamedGroup{FFDHE2048},
		InsecureSkipVerify: true,
	}

	resumptionConfig = &Config{
		ServerName:         serverName,
		Certificates:       certificates,
		SendSessionTickets: true,
		InsecureSkipVerify: true,
	}

	ffdhConfig = &Config{
		ServerName:         serverName,
		Certificates:       certificates,
		CipherSuites:       []CipherSuite{TLS_AES_128_GCM_SHA256},
		Groups:             []NamedGroup{FFDHE2048},
		InsecureSkipVerify: true,
	}

	x25519Config = &Config{
		ServerName:         serverName,
		Certificates:       certificates,
		CipherSuites:       []CipherSuite{TLS_AES_128_GCM_SHA256},
		Groups:             []NamedGroup{X25519},
		InsecureSkipVerify: true,
	}
}

// TestMain verifies that no goroutines leak after all tests complete
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m,
		// Ignore common background goroutines that may legitimately remain
		goleak.IgnoreTopFunction("runtime/pprof.writeRuntimeProfile"),
		goleak.IgnoreTopFunction("runtime/pprof.writeHeapInternal"),
		goleak.IgnoreTopFunction("go.uber.org/goleak.(*goroutine).isLeaked"),
	)
	os.Exit(m.Run())
}

func assertKeySetEquals(t *testing.T, k1, k2 KeySet) {
	t.Helper()
	// Assume cipher is the same
	assertTrue(t, len(k1.Keys) > 0, "assert that there are some keys")
	assertEquals(t, len(k1.Keys), len(k2.Keys))
	for k, v := range k1.Keys {
		assertByteEquals(t, v, k2.Keys[k])
	}
}

func computeExporter(t *testing.T, c *Conn, label string, context []byte, length int) []byte {
	t.Helper()
	res, err := c.ComputeExporter(label, context, length)
	assertNotError(t, err, "Could not compute exporter")
	return res
}

func checkConsistency(t *testing.T, client *Conn, server *Conn) {
	assertDeepEquals(t, client.state.Params, server.state.Params)
	assertCipherSuiteParamsEquals(t, client.state.cryptoParams, server.state.cryptoParams)
	assertByteEquals(t, client.state.resumptionSecret, server.state.resumptionSecret)
	assertByteEquals(t, client.state.clientTrafficSecret, server.state.clientTrafficSecret)
	assertByteEquals(t, client.state.serverTrafficSecret, server.state.serverTrafficSecret)
	assertByteEquals(t, client.state.exporterSecret, server.state.exporterSecret)

	emptyContext := []byte{}

	assertByteEquals(t, computeExporter(t, client, "E", emptyContext, 20), computeExporter(t, server, "E", emptyContext, 20))
	assertNotByteEquals(t, computeExporter(t, client, "E", emptyContext, 20), computeExporter(t, server, "E", emptyContext, 21))
	assertNotByteEquals(t, computeExporter(t, client, "E", emptyContext, 20), computeExporter(t, server, "F", emptyContext, 20))
	assertByteEquals(t, computeExporter(t, client, "E", []byte{'A'}, 20), computeExporter(t, server, "E", []byte{'A'}, 20))
	assertNotByteEquals(t, computeExporter(t, client, "E", []byte{'A'}, 20), computeExporter(t, server, "E", []byte{'B'}, 20))
}

func testConnInner(t *testing.T, name string, p testInstanceState) {
	// Configs array:
	configs := map[string]*Config{"basic config": basicConfig,
		"HRR":    hrrConfig,
		"ALPN":   alpnConfig,
		"FFDH":   ffdhConfig,
		"x25519": x25519Config,
	}

	c := configs[p["config"]]
	conf := *c

	// Set up the test parameters.
	if p["nonblocking"] == "true" {
		conf.NonBlocking = true
	}

	cConn, sConn := pipe()

	client := Client(cConn, &conf)
	server := Server(sConn, &conf)
	defer client.Close()
	defer server.Close()

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

	checkConsistency(t, client, server)
}

func TestBasicFlows(t *testing.T) {
	params := map[string][]string{
		"config": {
			"basic config",
			"HRR",
			"ALPN",
			"FFDH",
			"x25519",
		},
		"blocking": {"true", "false"},
	}

	runParametrizedTest(t, params, testConnInner)
	// Note: testConnInner handles cleanup, so we just check for leaks
	time.Sleep(10 * time.Millisecond)
	goleak.VerifyNone(t)
}

func TestInvalidSelfSigned(t *testing.T) {
	cConn, sConn := pipe()
	client := Client(cConn, &Config{ServerName: serverName})
	// The server uses a self-signed certificate
	server := Server(sConn, &Config{Certificates: certificates})
	defer client.Close()
	defer server.Close()

	done := make(chan bool)
	go func() {
		server.Handshake()
		done <- true
	}()

	clientAlert := client.Handshake()
	assertEquals(t, clientAlert, AlertBadCertificate)

	// Close server explicitly to unblock if handshake is stuck
	server.Close()
	<-done
	closeAndVerifyNoLeaks(t, client, server)
}

func TestExpiredCert(t *testing.T) {
	clientConfig := &Config{
		ServerName: serverName,
		Time:       func() time.Time { return time.Now().Add(-365 * 24 * time.Hour) },
	}

	cConn, sConn := pipe()
	client := Client(cConn, clientConfig)
	// The server uses a self-signed certificate
	server := Server(sConn, &Config{Certificates: certificates})
	defer client.Close()
	defer server.Close()

	done := make(chan bool)
	go func() {
		server.Handshake()
		done <- true
	}()

	clientAlert := client.Handshake()
	assertEquals(t, clientAlert, AlertBadCertificate)

	<-done
	closeAndVerifyNoLeaks(t, client, server)
}

func TestRootCAPool(t *testing.T) {
	pool := x509.NewCertPool()
	pool.AddCert(certificates[0].Chain[0])
	clientConfig := &Config{
		ServerName: serverName,
		RootCAs:    pool,
	}

	cConn, sConn := pipe()
	client := Client(cConn, clientConfig)
	// The server uses a self-signed certificate
	server := Server(sConn, &Config{Certificates: certificates})
	defer client.Close()
	defer server.Close()

	var clientAlert, serverAlert Alert
	done := make(chan bool)
	go func(t *testing.T) {
		serverAlert = server.Handshake()
		assertEquals(t, serverAlert, AlertNoAlert)
		done <- true
	}(t)

	clientAlert = client.Handshake()
	assertEquals(t, clientAlert, AlertNoAlert)
	<-done
	closeAndVerifyNoLeaks(t, client, server)
}

func TestVerifyPeerCertificateAccepted(t *testing.T) {
	var verifyCalled bool
	pool := x509.NewCertPool()
	pool.AddCert(certificates[0].Chain[0])
	clientConfig := &Config{
		ServerName: serverName,
		RootCAs:    pool,
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			verifyCalled = true
			assertEquals(t, len(rawCerts), 1)
			assertEquals(t, len(verifiedChains), 1)
			assertEquals(t, len(verifiedChains[0]), 1)
			cert, err := x509.ParseCertificate(rawCerts[0])
			assertNotError(t, err, "cert parsing error")
			assertEquals(t, cert.Equal(verifiedChains[0][0]), true)
			return nil
		},
	}

	cConn, sConn := pipe()
	client := Client(cConn, clientConfig)
	// The server uses a self-signed certificate
	server := Server(sConn, &Config{Certificates: certificates})
	defer client.Close()
	defer server.Close()

	var clientAlert, serverAlert Alert
	done := make(chan bool)
	go func(t *testing.T) {
		serverAlert = server.Handshake()
		assertEquals(t, serverAlert, AlertNoAlert)
		done <- true
	}(t)

	clientAlert = client.Handshake()
	assertEquals(t, clientAlert, AlertNoAlert)
	assertEquals(t, verifyCalled, true)
	<-done
	closeAndVerifyNoLeaks(t, client, server)
}

func TestVerifyPeerCertificateInsecureSkipVerify(t *testing.T) {
	var verifyCalled bool
	clientConfig := &Config{
		ServerName:         serverName,
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			verifyCalled = true
			assertEquals(t, len(rawCerts), 1)
			assertEquals(t, len(verifiedChains), 0)
			return nil
		},
	}

	cConn, sConn := pipe()
	client := Client(cConn, clientConfig)
	// The server uses a self-signed certificate
	server := Server(sConn, &Config{Certificates: certificates})
	defer client.Close()
	defer server.Close()

	var clientAlert, serverAlert Alert
	done := make(chan bool)
	go func(t *testing.T) {
		serverAlert = server.Handshake()
		assertEquals(t, serverAlert, AlertNoAlert)
		done <- true
	}(t)

	clientAlert = client.Handshake()
	assertEquals(t, clientAlert, AlertNoAlert)
	assertEquals(t, verifyCalled, true)
	<-done
	closeAndVerifyNoLeaks(t, client, server)
}

func TestVerifyPeerCertificateRejected(t *testing.T) {
	var verifyCalled bool
	clientConfig := &Config{
		ServerName:         serverName,
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			verifyCalled = true
			return errors.New("verify failed")
		},
	}

	cConn, sConn := pipe()
	client := Client(cConn, clientConfig)
	// The server uses a self-signed certificate
	server := Server(sConn, &Config{Certificates: certificates})
	defer client.Close()
	defer server.Close()

	done := make(chan bool)
	go func() {
		server.Handshake()
		done <- true
	}()

	clientAlert := client.Handshake()
	assertEquals(t, clientAlert, AlertBadCertificate)
	assertEquals(t, verifyCalled, true)

	// Close server explicitly to unblock if handshake is stuck
	server.Close()
	<-done
	closeAndVerifyNoLeaks(t, client, server)
}

func TestCertChain(t *testing.T) {
	// generate a CA cert
	cakey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	certTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	cacertDER, _ := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, cakey.Public(), cakey)
	cacert, _ := x509.ParseCertificate(cacertDER)
	// generate a server cert
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		Subject:      pkix.Name{CommonName: serverName},
		DNSNames:     []string{serverName},
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, cacert, key.Public(), cakey)
	cert, _ := x509.ParseCertificate(certDER)

	serverConfig := &Config{
		Certificates: []*Certificate{
			{Chain: []*x509.Certificate{cert, cacert}, PrivateKey: key},
		},
	}

	pool := x509.NewCertPool()
	pool.AddCert(cacert)
	clientConfig := &Config{
		ServerName: serverName,
		RootCAs:    pool,
	}
	cConn, sConn := pipe()
	client := Client(cConn, clientConfig)
	// The server uses a self-signed certificate
	server := Server(sConn, serverConfig)
	defer client.Close()
	defer server.Close()

	var clientAlert, serverAlert Alert
	done := make(chan bool)
	go func(t *testing.T) {
		serverAlert = server.Handshake()
		assertEquals(t, serverAlert, AlertNoAlert)
		done <- true
	}(t)

	clientAlert = client.Handshake()
	assertEquals(t, clientAlert, AlertNoAlert)
	<-done
	closeAndVerifyNoLeaks(t, client, server)
}

// TODO(#90): Add a test with mismatching server name

func TestClientAuth(t *testing.T) {
	configServer := &Config{
		RequireClientAuth: true,
		Certificates:      certificates,
	}
	configClient := &Config{
		ServerName:         serverName,
		Certificates:       clientCertificates,
		InsecureSkipVerify: true,
	}

	cConn, sConn := pipe()
	client := Client(cConn, configClient)
	server := Server(sConn, configServer)
	defer client.Close()
	defer server.Close()

	var clientAlert, serverAlert Alert
	done := make(chan bool)
	go func(t *testing.T) {
		serverAlert = server.Handshake()
		assertEquals(t, serverAlert, AlertNoAlert)
		done <- true
	}(t)

	clientAlert = client.Handshake()
	assertEquals(t, clientAlert, AlertNoAlert)

	<-done

	checkConsistency(t, client, server)
	assertTrue(t, client.state.Params.UsingClientAuth, "Session did not negotiate client auth")
	closeAndVerifyNoLeaks(t, client, server)
}

func TestClientAuthVerifyPeerAccepted(t *testing.T) {
	var verifyCalled bool
	configServer := &Config{
		RequireClientAuth: true,
		Certificates:      certificates,
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			verifyCalled = true
			assertEquals(t, len(verifiedChains), 0)
			assertEquals(t, len(rawCerts), 1)
			cert, err := x509.ParseCertificate(rawCerts[0])
			assertNotError(t, err, "cert parsing")
			assertEquals(t, cert.Equal(clientCert), true)
			return nil
		},
	}
	configClient := &Config{
		ServerName:         serverName,
		Certificates:       clientCertificates,
		InsecureSkipVerify: true,
	}

	cConn, sConn := pipe()
	client := Client(cConn, configClient)
	server := Server(sConn, configServer)
	defer client.Close()
	defer server.Close()

	var clientAlert, serverAlert Alert
	done := make(chan bool)
	go func(t *testing.T) {
		clientAlert = client.Handshake()
		assertEquals(t, clientAlert, AlertNoAlert)
		done <- true
	}(t)

	serverAlert = server.Handshake()
	assertEquals(t, serverAlert, AlertNoAlert)
	assertEquals(t, verifyCalled, true)

	<-done
	closeAndVerifyNoLeaks(t, client, server)
}

func TestClientAuthVerifyPeerRejected(t *testing.T) {
	var verifyCalled bool
	configServer := &Config{
		RequireClientAuth: true,
		Certificates:      certificates,
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			verifyCalled = true
			return errors.New("verify failed")
		},
	}
	configClient := &Config{
		ServerName:         serverName,
		Certificates:       clientCertificates,
		InsecureSkipVerify: true,
	}

	cConn, sConn := pipe()
	client := Client(cConn, configClient)
	server := Server(sConn, configServer)
	defer client.Close()
	defer server.Close()

	done := make(chan bool)
	go func() {
		client.Handshake()
		done <- true
	}()

	serverAlert := server.Handshake()
	assertEquals(t, serverAlert, AlertBadCertificate)
	assertEquals(t, verifyCalled, true)

	<-done
	closeAndVerifyNoLeaks(t, client, server)
}

func TestPSKFlows(t *testing.T) {
	for _, conf := range []*Config{pskConfig, pskECDHEConfig, pskDHEConfig} {
		cConn, sConn := pipe()

		client := Client(cConn, conf)
		server := Server(sConn, conf)
		defer client.Close()
		defer server.Close()

		var clientAlert, serverAlert Alert

		done := make(chan bool)
		go func(t *testing.T) {
			serverAlert = server.Handshake()
			assertEquals(t, serverAlert, AlertNoAlert)
			done <- true
		}(t)

		clientAlert = client.Handshake()
		assertEquals(t, clientAlert, AlertNoAlert)

		<-done

		checkConsistency(t, client, server)

		assertTrue(t, client.state.Params.UsingPSK, "Session did not use the provided PSK")

		// Close connections explicitly before checking for leaks
		client.Close()
		server.Close()
	}
	// Give goroutines a moment to exit
	time.Sleep(10 * time.Millisecond)
	goleak.VerifyNone(t)
}

func TestNonBlockingReadBeforeConnected(t *testing.T) {
	conn := Client(&bufferedConn{}, &Config{NonBlocking: true})
	_, err := conn.Read(make([]byte, 10))
	assertEquals(t, err.Error(), "Read called before the handshake completed")
	// Don't close - connection was never started (no controller)
	time.Sleep(10 * time.Millisecond)
	goleak.VerifyNone(t)
}

func TestResumption(t *testing.T) {
	// Phase 1: Verify that the session ticket gets sent and stored
	clientConfig := resumptionConfig.Clone()
	serverConfig := resumptionConfig.Clone()

	cConn1, sConn1 := pipe()
	client1 := Client(cConn1, clientConfig)
	server1 := Server(sConn1, serverConfig)
	defer client1.Close()
	defer server1.Close()

	var clientAlert, serverAlert Alert

	done := make(chan bool)
	go func(t *testing.T) {
		serverAlert = server1.Handshake()
		assertEquals(t, serverAlert, AlertNoAlert)
		server1.Write([]byte{'a'})
		done <- true
	}(t)

	clientAlert = client1.Handshake()
	assertEquals(t, clientAlert, AlertNoAlert)

	tmpBuf := make([]byte, 1)
	n, err := client1.Read(tmpBuf)
	assertNil(t, err, "Couldn't read one byte")
	assertEquals(t, 1, n)
	<-done

	checkConsistency(t, client1, server1)
	assertEquals(t, clientConfig.PSKs.Size(), 1)
	assertEquals(t, serverConfig.PSKs.Size(), 1)

	clientCache := clientConfig.PSKs.(*PSKMapCache)
	serverCache := serverConfig.PSKs.(*PSKMapCache)

	var serverPSK PreSharedKey
	for _, key := range *serverCache {
		serverPSK = key
	}
	var clientPSK PreSharedKey
	for _, key := range *clientCache {
		clientPSK = key
	}

	// Ensure that the PSKs are the same, except with regard to the
	// receivedAt/expiresAt times, which might differ by a little.
	assertEquals(t, clientPSK.CipherSuite, serverPSK.CipherSuite)
	assertEquals(t, clientPSK.IsResumption, serverPSK.IsResumption)
	assertByteEquals(t, clientPSK.Identity, serverPSK.Identity)
	assertByteEquals(t, clientPSK.Key, serverPSK.Key)
	assertEquals(t, clientPSK.NextProto, serverPSK.NextProto)
	assertEquals(t, clientPSK.TicketAgeAdd, serverPSK.TicketAgeAdd)

	receivedDelta := clientPSK.ReceivedAt.Sub(serverPSK.ReceivedAt) / time.Millisecond
	expiresDelta := clientPSK.ExpiresAt.Sub(serverPSK.ExpiresAt) / time.Millisecond
	assertTrue(t, receivedDelta < 10 && receivedDelta > -10, "Unequal received times")
	assertTrue(t, expiresDelta < 10 && expiresDelta > -10, "Unequal received times")

	// Phase 2: Verify that the session ticket gets used as a PSK
	cConn2, sConn2 := pipe()
	client2 := Client(cConn2, clientConfig)
	server2 := Server(sConn2, serverConfig)
	defer client2.Close()
	defer server2.Close()

	go func(t *testing.T) {
		serverAlert = server2.Handshake()
		assertEquals(t, serverAlert, AlertNoAlert)
		done <- true
	}(t)

	clientAlert = client2.Handshake()
	assertEquals(t, clientAlert, AlertNoAlert)

	client2.Read(nil)
	<-done

	checkConsistency(t, client2, server2)
	assertTrue(t, client2.state.Params.UsingPSK, "Session did not use the provided PSK")
	closeAndVerifyNoLeaks(t, client1, server1, client2, server2)
}

func test0xRTT(t *testing.T, name string, p testInstanceState) {
	conf := *pskConfig
	conf.NonBlocking = true

	if p["dtls"] == "true" {
		conf.UseDTLS = true
	}

	cConn, sConn := pipe()
	cbConn := newBufferedConn(cConn)
	cbConn.SetAutoflush()
	sbConn := newBufferedConn(sConn)
	sbConn.SetAutoflush()

	client := Client(cbConn, &conf)
	server := Server(sbConn, &conf)
	defer client.Close()
	defer server.Close()

	client.Handshake() // This sends CH
	zdata := []byte("ABC")
	n, err := client.Write(zdata) // This should succeeed
	assertNotError(t, err, "Client was not able to write")
	assertEquals(t, n, len(zdata))
	hsUntilBlocked(t, server, sbConn) // Read CH and early data.
	tmp := make([]byte, 10)
	n, err = server.Read(tmp)
	assertNotError(t, err, "Error reading early data")
	tmp = tmp[:n]
	assertByteEquals(t, zdata, tmp)
	hsRunHandshakeOneThread(t, client, server)

	assertTrue(t, client.state.Params.UsingEarlyData, "Session did not negotiate early data")
	n, err = server.Read(tmp)
	assertEquals(t, AlertWouldBlock, err)
	assertEquals(t, 0, n)
}

func Test0xRTT(t *testing.T) {
	params := map[string][]string{
		"dtls": {"true", "false"},
	}
	runParametrizedTest(t, params, test0xRTT)
	// Note: test0xRTT handles cleanup, so we just check for leaks
	time.Sleep(10 * time.Millisecond)
	goleak.VerifyNone(t)
}

func Test0xRTTFailure(t *testing.T) {
	// Client thinks it has a PSK
	clientConfig := &Config{
		ServerName:         serverName,
		CipherSuites:       []CipherSuite{TLS_AES_128_GCM_SHA256},
		PSKs:               psks,
		InsecureSkipVerify: true,
	}

	// Server doesn't
	serverConfig := &Config{
		CipherSuites: []CipherSuite{TLS_AES_128_GCM_SHA256},
		Certificates: certificates,
	}

	cConn, sConn := pipe()

	client := Client(cConn, clientConfig)
	defer client.Close()

	server := Server(sConn, serverConfig)
	defer server.Close()

	done := make(chan bool)
	go func(t *testing.T) {
		alert := server.Handshake()
		assertEquals(t, alert, AlertNoAlert)
		done <- true
	}(t)

	alert := client.Handshake()
	assertEquals(t, alert, AlertNoAlert)

	<-done
	closeAndVerifyNoLeaks(t, client, server)
}

func TestKeyUpdate(t *testing.T) {
	cConn, sConn := pipe()

	conf := basicConfig
	client := Client(cConn, conf)
	server := Server(sConn, conf)

	oneBuf := []byte{'a'}
	c2s := make(chan bool)
	s2c := make(chan bool)
	go func(t *testing.T) {
		alert := server.Handshake()
		assertEquals(t, alert, AlertNoAlert)

		// Send a single byte so that the client can consume NST.
		server.Write(oneBuf)
		s2c <- true

		// Test server-initiated KeyUpdate
		<-c2s
		err := server.SendKeyUpdate(false)
		assertNotError(t, err, "Key update send failed")

		// Write a single byte so that the client can read it
		// after KeyUpdate.
		server.Write(oneBuf)
		s2c <- true

		// Null read to trigger key update
		<-c2s
		server.Read(oneBuf)
		s2c <- true

		// Null read to trigger key update and KeyUpdate response
		<-c2s
		server.Read(oneBuf)
		server.Write(oneBuf)
		s2c <- true
	}(t)

	alert := client.Handshake()
	assertEquals(t, alert, AlertNoAlert)

	// Read NST.
	client.Read(oneBuf)
	<-s2c

	clientState0 := client.state
	serverState0 := server.state
	assertByteEquals(t, clientState0.serverTrafficSecret, serverState0.serverTrafficSecret)
	assertByteEquals(t, clientState0.clientTrafficSecret, serverState0.clientTrafficSecret)

	// Null read to trigger key update
	c2s <- true
	<-s2c
	client.Read(oneBuf)
	logf(logTypeHandshake, "Client read key update")

	clientState1 := client.state
	serverState1 := server.state
	assertByteEquals(t, clientState1.serverTrafficSecret, serverState1.serverTrafficSecret)
	assertByteEquals(t, clientState1.clientTrafficSecret, serverState1.clientTrafficSecret)
	assertNotByteEquals(t, serverState0.serverTrafficSecret, serverState1.serverTrafficSecret)
	assertByteEquals(t, clientState0.clientTrafficSecret, clientState1.clientTrafficSecret)

	// Test client-initiated KeyUpdate
	client.SendKeyUpdate(false)
	client.Write(oneBuf)
	c2s <- true
	<-s2c

	clientState2 := client.state
	serverState2 := server.state
	assertByteEquals(t, clientState2.serverTrafficSecret, serverState2.serverTrafficSecret)
	assertByteEquals(t, clientState2.clientTrafficSecret, serverState2.clientTrafficSecret)
	assertByteEquals(t, serverState1.serverTrafficSecret, serverState2.serverTrafficSecret)
	assertNotByteEquals(t, clientState1.clientTrafficSecret, clientState2.clientTrafficSecret)

	// Test client-initiated with keyUpdateRequested
	client.SendKeyUpdate(true)
	client.Write(oneBuf)
	c2s <- true
	<-s2c
	client.Read(oneBuf)

	clientState3 := client.state
	serverState3 := server.state
	assertByteEquals(t, clientState3.serverTrafficSecret, serverState3.serverTrafficSecret)
	assertByteEquals(t, clientState3.clientTrafficSecret, serverState3.clientTrafficSecret)
	assertNotByteEquals(t, serverState2.serverTrafficSecret, serverState3.serverTrafficSecret)
	assertNotByteEquals(t, clientState2.clientTrafficSecret, clientState3.clientTrafficSecret)
	closeAndVerifyNoLeaks(t, client, server)
}

func TestKeyUpdateMultipleSequential(t *testing.T) {
	// Test multiple sequential KeyUpdates to verify:
	// 1. Sequence numbers reset correctly after each KeyUpdate
	// 2. Keys continue to update correctly through multiple cycles
	// 3. Controller handles multiple KeyUpdate operations correctly
	// 4. EpochUpdate handling works for subsequent KeyUpdates
	cConn, sConn := pipe()

	conf := basicConfig
	client := Client(cConn, conf)
	server := Server(sConn, conf)

	oneBuf := []byte{'a'}
	c2s := make(chan bool)
	s2c := make(chan bool)
	serverDone := make(chan bool)
	go func(t *testing.T) {
		defer func() { serverDone <- true }()
		alert := server.Handshake()
		assertEquals(t, alert, AlertNoAlert)

		// Send initial data
		server.Write(oneBuf)
		s2c <- true

		// Perform multiple server-initiated KeyUpdates
		for i := 0; i < 3; i++ {
			<-c2s
			err := server.SendKeyUpdate(false)
			assertNotError(t, err, "Key update send failed")
			server.Write(oneBuf)
			s2c <- true
		}

		// Perform multiple client-initiated KeyUpdates
		for i := 0; i < 3; i++ {
			<-c2s
			server.Read(oneBuf)
			server.Write(oneBuf)
			s2c <- true
		}
	}(t)

	alert := client.Handshake()
	assertEquals(t, alert, AlertNoAlert)

	// Read initial data
	client.Read(oneBuf)
	<-s2c

	// Track states through multiple KeyUpdates
	prevClientState := client.state
	prevServerState := server.state

	// Test multiple server-initiated KeyUpdates
	for i := 0; i < 3; i++ {
		c2s <- true
		<-s2c
		client.Read(oneBuf)

		clientState := client.state
		serverState := server.state

		// Verify secrets match between client and server
		assertByteEquals(t, clientState.serverTrafficSecret, serverState.serverTrafficSecret)
		assertByteEquals(t, clientState.clientTrafficSecret, serverState.clientTrafficSecret)

		// Verify server secrets changed (server-initiated KeyUpdate)
		assertNotByteEquals(t, prevServerState.serverTrafficSecret, serverState.serverTrafficSecret)
		// Client secrets should remain unchanged (server only updated its own keys)
		assertByteEquals(t, prevClientState.clientTrafficSecret, clientState.clientTrafficSecret)

		prevClientState = clientState
		prevServerState = serverState
	}

	// Test multiple client-initiated KeyUpdates
	for i := 0; i < 3; i++ {
		client.SendKeyUpdate(false)
		client.Write(oneBuf)
		c2s <- true
		<-s2c

		clientState := client.state
		serverState := server.state

		// Verify secrets match between client and server
		assertByteEquals(t, clientState.serverTrafficSecret, serverState.serverTrafficSecret)
		assertByteEquals(t, clientState.clientTrafficSecret, serverState.clientTrafficSecret)

		// Verify client secrets changed (client-initiated KeyUpdate)
		assertNotByteEquals(t, prevClientState.clientTrafficSecret, clientState.clientTrafficSecret)
		// Server secrets should remain unchanged (client only updated its own keys)
		assertByteEquals(t, prevServerState.serverTrafficSecret, serverState.serverTrafficSecret)

		prevClientState = clientState
		prevServerState = serverState
	}
	// Wait for server goroutine to finish
	<-serverDone
	closeAndVerifyNoLeaks(t, client, server)
}

func TestNonblockingHandshakeAndDataFlow(t *testing.T) {
	cConn, sConn := pipe()

	// Wrap these in a buffer so we can simulate blocking
	cbConn := newBufferedConn(cConn)
	sbConn := newBufferedConn(sConn)

	client := Client(cbConn, nbConfig)
	server := Server(sbConn, nbConfig)
	defer client.Close()
	defer server.Close()

	var clientAlert, serverAlert Alert

	// Send ClientHello
	clientAlert = client.Handshake()
	assertEquals(t, clientAlert, AlertNoAlert)
	assertEquals(t, client.GetHsState(), StateClientWaitSH)
	serverAlert = server.Handshake()
	assertEquals(t, serverAlert, AlertWouldBlock)
	assertEquals(t, server.GetHsState(), StateServerStart)

	// Release ClientHello
	cbConn.Flush()

	// Process ClientHello, send server first flight.
	states := []State{StateServerNegotiated, StateServerWaitFlight2, StateServerWaitFinished}
	for _, state := range states {
		serverAlert = server.Handshake()
		assertEquals(t, serverAlert, AlertNoAlert)
		assertEquals(t, server.GetHsState(), state)
	}
	serverAlert = server.Handshake()
	assertEquals(t, serverAlert, AlertWouldBlock)

	clientAlert = client.Handshake()
	assertEquals(t, clientAlert, AlertWouldBlock)

	// Release server first flight
	sbConn.Flush()
	states = []State{StateClientWaitEE, StateClientWaitCertCR, StateClientWaitCV, StateClientWaitFinished, StateClientConnected}
	for _, state := range states {
		clientAlert = client.Handshake()
		assertEquals(t, client.GetHsState(), state)
		assertEquals(t, clientAlert, AlertNoAlert)
	}

	serverAlert = server.Handshake()
	assertEquals(t, serverAlert, AlertWouldBlock)
	assertEquals(t, server.GetHsState(), StateServerWaitFinished)

	// Release client's second flight.
	cbConn.Flush()
	serverAlert = server.Handshake()
	assertEquals(t, serverAlert, AlertNoAlert)
	assertEquals(t, server.GetHsState(), StateServerConnected)

	assertDeepEquals(t, client.state.Params, server.state.Params)
	assertCipherSuiteParamsEquals(t, client.state.cryptoParams, server.state.cryptoParams)
	assertByteEquals(t, client.state.resumptionSecret, server.state.resumptionSecret)
	assertByteEquals(t, client.state.clientTrafficSecret, server.state.clientTrafficSecret)
	assertByteEquals(t, client.state.serverTrafficSecret, server.state.serverTrafficSecret)

	buf := []byte{'a', 'b', 'c'}
	n, err := client.Write(buf)
	assertNotError(t, err, "Couldn't write")
	assertEquals(t, n, len(buf))

	// read := make([]byte, 5)
	// n, err = server.Read(buf)
	closeAndVerifyNoLeaks(t, client, server)
}

type testExtensionHandler struct {
	sent map[HandshakeType]bool
	rcvd map[HandshakeType]bool
}

func newTestExtensionHandler() *testExtensionHandler {
	return &testExtensionHandler{
		make(map[HandshakeType]bool),
		make(map[HandshakeType]bool),
	}
}

type testExtensionBody struct {
	t HandshakeType
}

const (
	testExtensionType = ExtensionType(240) // Dummy type.
)

func (t testExtensionBody) Type() ExtensionType {
	return testExtensionType
}

func (t testExtensionBody) Marshal() ([]byte, error) {
	return []byte{byte(t.t)}, nil
}

func (t *testExtensionBody) Unmarshal(data []byte) (int, error) {
	if len(data) != 1 {
		return 0, fmt.Errorf("Illegal length")
	}

	t.t = HandshakeType(data[0])
	return 1, nil
}

func (t *testExtensionHandler) Send(hs HandshakeType, el *ExtensionList) error {
	t.sent[hs] = true
	el.Add(&testExtensionBody{t: hs})
	return nil
}

func (t *testExtensionHandler) Receive(hs HandshakeType, el *ExtensionList) error {
	var body testExtensionBody

	ok, _ := el.Find(&body)
	if !ok {
		return fmt.Errorf("Couldn't find extension")
	}

	if hs != body.t {
		return fmt.Errorf("Does not match hs type")
	}

	t.rcvd[hs] = true
	return nil
}

func (h *testExtensionHandler) Check(t *testing.T, hs []HandshakeType) {
	assertEquals(t, len(hs), len(h.sent))
	assertEquals(t, len(hs), len(h.rcvd))

	for _, ht := range hs {
		v, ok := h.sent[ht]
		assertTrue(t, ok, "Cannot find handshake type in sent")
		assertTrue(t, v, "Value wasn't true in sent")
		v, ok = h.rcvd[ht]
		assertTrue(t, ok, "Cannot find handshake type in rcvd")
		assertTrue(t, v, "Value wasn't true in rcvd")
	}
}

func TestExternalExtensions(t *testing.T) {
	cConn, sConn := pipe()

	handler := newTestExtensionHandler()
	config := basicConfig.Clone()
	config.ExtensionHandler = handler

	client := Client(cConn, config)
	server := Server(sConn, config)
	defer client.Close()
	defer server.Close()

	var clientAlert, serverAlert Alert

	done := make(chan bool)
	go func(t *testing.T) {
		serverAlert = server.Handshake()
		assertEquals(t, serverAlert, AlertNoAlert)
		done <- true
	}(t)

	clientAlert = client.Handshake()
	assertEquals(t, clientAlert, AlertNoAlert)

	<-done

	assertDeepEquals(t, client.state.Params, server.state.Params)
	assertCipherSuiteParamsEquals(t, client.state.cryptoParams, server.state.cryptoParams)
	assertByteEquals(t, client.state.resumptionSecret, server.state.resumptionSecret)
	assertByteEquals(t, client.state.clientTrafficSecret, server.state.clientTrafficSecret)
	assertByteEquals(t, client.state.serverTrafficSecret, server.state.serverTrafficSecret)
	handler.Check(t, []HandshakeType{
		HandshakeTypeClientHello,
		HandshakeTypeServerHello,
		HandshakeTypeEncryptedExtensions,
	})
	closeAndVerifyNoLeaks(t, client, server)
}

func TestConnectionState(t *testing.T) {
	pool := x509.NewCertPool()
	pool.AddCert(serverCert)
	configClient := &Config{
		ServerName:   serverName,
		RootCAs:      pool,
		Certificates: clientCertificates,
	}
	serverConfig := &Config{
		RequireClientAuth: true,
		Certificates:      certificates,
	}
	cConn, sConn := pipe()
	client := Client(cConn, configClient)
	server := Server(sConn, serverConfig)
	defer client.Close()
	defer server.Close()

	done := make(chan bool)
	go func(t *testing.T) {
		serverAlert := server.Handshake()
		assertEquals(t, serverAlert, AlertNoAlert)
		done <- true
	}(t)

	clientAlert := client.Handshake()
	assertEquals(t, clientAlert, AlertNoAlert)
	<-done

	clientCS := client.ConnectionState()
	serverCS := server.ConnectionState()
	assertEquals(t, clientCS.CipherSuite.Suite, configClient.CipherSuites[0])
	assertDeepEquals(t, clientCS.VerifiedChains, [][]*x509.Certificate{{serverCert}})
	assertDeepEquals(t, clientCS.PeerCertificates, []*x509.Certificate{serverCert})
	assertEquals(t, serverCS.CipherSuite.Suite, serverConfig.CipherSuites[0])
	assertDeepEquals(t, serverCS.PeerCertificates, []*x509.Certificate{clientCert})
	closeAndVerifyNoLeaks(t, client, server)
}

func TestDTLS(t *testing.T) {
	cConn, sConn := pipe()

	handler := newTestExtensionHandler()
	config := dtlsConfig.Clone()
	config.ExtensionHandler = handler
	client := Client(cConn, config)
	server := Server(sConn, config)
	defer client.Close()
	defer server.Close()

	var clientAlert, serverAlert Alert

	done := make(chan bool)
	go func(t *testing.T) {
		serverAlert = server.Handshake()
		assertEquals(t, serverAlert, AlertNoAlert)
		done <- true
	}(t)

	clientAlert = client.Handshake()
	assertEquals(t, clientAlert, AlertNoAlert)

	<-done

	assertDeepEquals(t, client.state.Params, server.state.Params)
	assertCipherSuiteParamsEquals(t, client.state.cryptoParams, server.state.cryptoParams)
	assertByteEquals(t, client.state.resumptionSecret, server.state.resumptionSecret)
	assertByteEquals(t, client.state.clientTrafficSecret, server.state.clientTrafficSecret)
	assertByteEquals(t, client.state.serverTrafficSecret, server.state.serverTrafficSecret)
	handler.Check(t, []HandshakeType{
		HandshakeTypeClientHello,
		HandshakeTypeServerHello,
		HandshakeTypeEncryptedExtensions,
	})
	closeAndVerifyNoLeaks(t, client, server)
}

func TestNonblockingHandshakeAndDataFlowDTLS(t *testing.T) {
	cConn, sConn := pipe()

	// Wrap these in a buffer so we can simulate blocking
	cbConn := newBufferedConn(cConn)
	sbConn := newBufferedConn(sConn)

	client := Client(cbConn, nbDTLSConfig)
	server := Server(sbConn, nbDTLSConfig)
	defer client.Close()
	defer server.Close()

	var clientAlert, serverAlert Alert

	// Send ClientHello
	clientAlert = client.Handshake()
	assertEquals(t, clientAlert, AlertNoAlert)
	assertEquals(t, client.GetHsState(), StateClientWaitSH)
	serverAlert = server.Handshake()
	assertEquals(t, serverAlert, AlertWouldBlock)
	assertEquals(t, server.GetHsState(), StateServerStart)

	// Release ClientHello
	cbConn.Flush()

	// Process ClientHello, send server first flight.
	states := []State{StateServerNegotiated, StateServerWaitFlight2, StateServerWaitFinished}
	for _, state := range states {
		serverAlert = server.Handshake()
		assertEquals(t, serverAlert, AlertNoAlert)
		assertEquals(t, server.GetHsState(), state)
	}
	serverAlert = server.Handshake()
	assertEquals(t, serverAlert, AlertWouldBlock)

	clientAlert = client.Handshake()
	assertEquals(t, clientAlert, AlertWouldBlock)

	// Release server first flight
	sbConn.Flush()
	states = []State{StateClientWaitEE, StateClientWaitCertCR, StateClientWaitCV, StateClientWaitFinished, StateClientConnected}
	for _, state := range states {
		clientAlert = client.Handshake()
		assertEquals(t, client.GetHsState(), state)
		assertEquals(t, clientAlert, AlertNoAlert)
	}

	serverAlert = server.Handshake()
	assertEquals(t, serverAlert, AlertWouldBlock)
	assertEquals(t, server.GetHsState(), StateServerWaitFinished)

	// Release client's second flight.
	cbConn.Flush()
	serverAlert = server.Handshake()
	assertEquals(t, serverAlert, AlertNoAlert)
	assertEquals(t, server.GetHsState(), StateServerConnected)

	assertDeepEquals(t, client.state.Params, server.state.Params)
	assertCipherSuiteParamsEquals(t, client.state.cryptoParams, server.state.cryptoParams)
	assertByteEquals(t, client.state.resumptionSecret, server.state.resumptionSecret)
	assertByteEquals(t, client.state.clientTrafficSecret, server.state.clientTrafficSecret)
	assertByteEquals(t, client.state.serverTrafficSecret, server.state.serverTrafficSecret)

	buf := []byte{'a', 'b', 'c'}
	n, err := client.Write(buf)
	assertNotError(t, err, "Couldn't write")
	assertEquals(t, n, len(buf))

	// read := make([]byte, 5)
	// n, err = server.Read(buf)
	closeAndVerifyNoLeaks(t, client, server)
}

func TestTimeoutAndRetransmissionDTLS(t *testing.T) {
	cConn, sConn := pipe()

	// Wrap these in a buffer so we can simulate blocking
	cbConn := newBufferedConn(cConn)
	sbConn := newBufferedConn(sConn)

	client := Client(cbConn, nbDTLSConfig)
	server := Server(sbConn, nbDTLSConfig)
	defer client.Close()
	defer server.Close()

	var clientAlert, serverAlert Alert

	// Send ClientHello
	clientAlert = client.Handshake()
	assertEquals(t, clientAlert, AlertNoAlert)
	assertEquals(t, client.GetHsState(), StateClientWaitSH)
	serverAlert = server.Handshake()
	assertEquals(t, serverAlert, AlertWouldBlock)
	assertEquals(t, server.GetHsState(), StateServerStart)

	// Simulate loss for the ClientHello
	cbConn.Clear()

	// Only client should be running a timer.
	waiting, timeout := server.GetDTLSTimeout()
	assertTrue(t, !waiting, fmt.Sprintf("Server timer armed: %v", timeout))

	waiting, timeout = client.GetDTLSTimeout()
	assertTrue(t, waiting, "Client timer not armed")

	// Now check the timer.
	time.Sleep(timeout)
	clientAlert = client.Handshake()
	assertEquals(t, clientAlert, AlertWouldBlock)
	assertEquals(t, client.GetHsState(), StateClientWaitSH)

	// Release ClientHello
	cbConn.Flush()

	// Process ClientHello, send server first flight.
	states := []State{StateServerNegotiated, StateServerWaitFlight2, StateServerWaitFinished}
	for _, state := range states {
		serverAlert = server.Handshake()
		assertEquals(t, serverAlert, AlertNoAlert)
		assertEquals(t, server.GetHsState(), state)
	}
	serverAlert = server.Handshake()
	assertEquals(t, serverAlert, AlertWouldBlock)

	// Simulate loss for the server's first flight.
	sbConn.Clear()

	// Both sides should be running timers
	waiting, timeout = client.GetDTLSTimeout()
	assertTrue(t, waiting, "Client timer not armed")

	waiting, timeout = server.GetDTLSTimeout()
	assertTrue(t, waiting, "Server timer not armed")

	// Now check the timer.
	time.Sleep(timeout)
	serverAlert = server.Handshake()
	assertEquals(t, serverAlert, AlertWouldBlock)
	assertEquals(t, server.GetHsState(), StateServerWaitFinished)

	sbConn.Flush()
	states = []State{StateClientWaitEE, StateClientWaitCertCR, StateClientWaitCV, StateClientWaitFinished, StateClientConnected}
	for _, state := range states {
		clientAlert = client.Handshake()
		assertEquals(t, client.GetHsState(), state)
		assertEquals(t, clientAlert, AlertNoAlert)
	}

	serverAlert = server.Handshake()
	assertEquals(t, serverAlert, AlertWouldBlock)
	assertEquals(t, server.GetHsState(), StateServerWaitFinished)

	// Release client's second flight.
	cbConn.Flush()
	serverAlert = server.Handshake()
	assertEquals(t, serverAlert, AlertNoAlert)
	assertEquals(t, server.GetHsState(), StateServerConnected)

	assertDeepEquals(t, client.state.Params, server.state.Params)
	assertCipherSuiteParamsEquals(t, client.state.cryptoParams, server.state.cryptoParams)
	assertByteEquals(t, client.state.resumptionSecret, server.state.resumptionSecret)
	assertByteEquals(t, client.state.clientTrafficSecret, server.state.clientTrafficSecret)
	assertByteEquals(t, client.state.serverTrafficSecret, server.state.serverTrafficSecret)
}

func checkTimersEqualLabels(t *testing.T, c *Conn, labels []string) {
	timers := c.hsCtx.timers.getAllTimers()

	timerLabels := make(map[string]bool)
	expectedLabels := make(map[string]bool)

	// Check that the arrays are the same
	for _, timer := range timers {
		timerLabels[timer] = true
	}

	for _, label := range labels {
		expectedLabels[label] = true
		assertTrue(t, timerLabels[label], fmt.Sprintf("Timer should have been armed: %v", label))
	}

	for _, timer := range timers {
		assertTrue(t, expectedLabels[timer], fmt.Sprintf("Timer should not have been armed: %v", timer))
	}

}

func hsUntilBlocked(t *testing.T, c *Conn, b *bufferedConn) {
	// First run until we have consumed all the data
	for !b.Empty() {
		alert := c.Handshake()
		switch alert {
		default:
			t.Fatalf("Unexpected alert")
		case AlertWouldBlock, AlertNoAlert, AlertStatelessRetry:
		}
	}

	// Now run until we block
	for {
		alert := c.Handshake()
		if alert == AlertWouldBlock {
			return
		}
		assertEquals(t, alert, AlertNoAlert)
	}
}

func hsUntilComplete(t *testing.T, c *Conn) {
	for {
		alert := c.Handshake()
		assertTrue(t,
			alert == AlertWouldBlock ||
				alert == AlertNoAlert,
			"Unexpected alert")

		if c.GetHsState() == StateClientConnected ||
			c.GetHsState() == StateServerConnected {
			break
		}
	}
}

func hsRunHandshakeOneThread(t *testing.T, client *Conn, server *Conn) {
	assertTrue(t, client.config.NonBlocking && server.config.NonBlocking, "Both sides need to be in nonblocking mode")
	for client.GetHsState() != StateClientConnected || server.GetHsState() != StateServerConnected {
		alert := client.Handshake()
		switch alert {
		default:
			t.Fatalf("Unexpected alert")
		case AlertWouldBlock, AlertNoAlert:
		}

		alert = server.Handshake()
		switch alert {
		default:
			t.Fatalf("Unexpected alert %v", alert)
		case AlertWouldBlock, AlertNoAlert, AlertStatelessRetry:
		}
	}
	checkConsistency(t, client, server)
}

func runAllTimers(t *testing.T, c *Conn) {
	for {
		waiting, timeout := c.GetDTLSTimeout()
		if !waiting {
			return
		}

		if timeout > 0 {
			time.Sleep(timeout)
		}

		alert := c.Handshake()
		assertEquals(t, alert, AlertWouldBlock)
	}
}

func TestAckDTLSNormal(t *testing.T) {
	cConn, sConn := pipe()

	cbConn := newBufferedConn(cConn)
	sbConn := newBufferedConn(sConn)
	cbConn.SetAutoflush()
	sbConn.SetAutoflush()

	client := Client(cbConn, nbDTLSConfig)
	server := Server(sbConn, nbDTLSConfig)
	defer client.Close()
	defer server.Close()

	// Send ClientHello
	hsUntilBlocked(t, client, cbConn)

	// Process ClientHello, send server first flight.
	hsUntilBlocked(t, server, sbConn)

	// Both sides should be have armed retransmit timers.
	checkTimersEqualLabels(t, client, []string{retransmitTimerLabel})
	checkTimersEqualLabels(t, server, []string{retransmitTimerLabel})

	// Now run the client and server to completion
	hsUntilComplete(t, client)
	hsUntilComplete(t, server)

	// Client will have retransmit until we read the ACK
	checkTimersEqualLabels(t, client, []string{retransmitTimerLabel})

	// Server should have no timer
	checkTimersEqualLabels(t, server, []string{})

	// Now read some data from the server so we get the ACK
	b := make([]byte, 10)
	n, _ := client.Read(b)
	assertEquals(t, 0, n)

	// Client will now have no timers
	checkTimersEqualLabels(t, client, []string{})
	closeAndVerifyNoLeaks(t, client, server)
}

func TestAckDTLSLoseEE(t *testing.T) {
	cConn, sConn := pipe()

	cbConn := newBufferedConn(cConn)
	sbConn := newBufferedConn(sConn)
	sbConn.Lose(1) // Lose EE
	cbConn.SetAutoflush()
	sbConn.SetAutoflush()

	client := Client(cbConn, nbDTLSConfig)
	server := Server(sbConn, nbDTLSConfig)
	defer client.Close()
	defer server.Close()

	// Send ClientHello
	hsUntilBlocked(t, client, cbConn)

	// Process ClientHello, send server first flight.
	hsUntilBlocked(t, server, sbConn)

	// Both sides should be have armed retransmit timers.
	checkTimersEqualLabels(t, client, []string{retransmitTimerLabel})
	checkTimersEqualLabels(t, server, []string{retransmitTimerLabel})

	// Now process as much of the server first flight as is there.
	hsUntilBlocked(t, client, cbConn)

	// Client should now have the ACK timer armed
	checkTimersEqualLabels(t, client, []string{ackTimerLabel})

	// Now expire the timers
	runAllTimers(t, client)

	// Process ACK
	hsUntilBlocked(t, server, sbConn)

	// Now run the client and server to completion
	hsUntilComplete(t, client)
	hsUntilComplete(t, server)
	closeAndVerifyNoLeaks(t, client, server)
}

func readWriteExpectFail(t *testing.T, c *Conn) {
	tmp := make([]byte, 10)
	n, err := c.Read(tmp)
	assertEquals(t, 0, n)
	assertError(t, err, "Read too early worked")

	n, err = c.Write(tmp)
	assertEquals(t, 0, n)
	assertError(t, err, "Write too early worked")
}

func writeExpectFail(t *testing.T, c *Conn) {
	tmp := make([]byte, 10)
	n, err := c.Write(tmp)
	assertEquals(t, 0, n)
	assertError(t, err, "Write too early worked")
}

func TestEarlyIOFail(t *testing.T) {
	cConn, sConn := pipe()

	cbConn := newBufferedConn(cConn)
	sbConn := newBufferedConn(sConn)
	cbConn.SetAutoflush()
	sbConn.SetAutoflush()

	client := Client(cbConn, nbConfig)
	server := Server(sbConn, nbConfig)
	defer client.Close()
	defer server.Close()
	readWriteExpectFail(t, client)
	readWriteExpectFail(t, server)

	client.Handshake()
	server.Handshake()
	readWriteExpectFail(t, client)
	readWriteExpectFail(t, server)
	closeAndVerifyNoLeaks(t, client, server)
}

func TestDTLSOutOfEpochHSFail(t *testing.T) {
	cConn, sConn := pipe()

	cbConn := newBufferedConn(cConn)
	sbConn := newBufferedConn(sConn)
	cbConn.SetAutoflush()
	sbConn.SetAutoflush()

	client := Client(cbConn, nbDTLSConfig)
	server := Server(sbConn, nbDTLSConfig)
	defer client.Close()
	defer server.Close()

	hsUntilBlocked(t, client, cbConn)
	hsUntilBlocked(t, server, sbConn)

	cbConn.Write([]byte{byte(RecordTypeApplicationData),
		byte(dtls12WireVersion >> 8), byte(dtls12WireVersion & 0xff),
		0, 0, 0, 0, 0, 0, 0, 0, // Epoch 0, seq 0
		0, 5, 1, 2, 3, 4, 5, // Payload
	})

	// This causes an error because it's an unexpected record type.
	err := server.Handshake()
	assertEquals(t, err, AlertCloseNotify)
	closeAndVerifyNoLeaks(t, client, server)
}

func TestDTLSOutOfEpochPostHSDiscard(t *testing.T) {
	cConn, sConn := pipe()

	cbConn := newBufferedConn(cConn)
	sbConn := newBufferedConn(sConn)
	cbConn.SetAutoflush()
	sbConn.SetAutoflush()

	client := Client(cbConn, pskDTLSConfig)
	server := Server(sbConn, pskDTLSConfig)
	defer client.Close()
	defer server.Close()

	hsRunHandshakeOneThread(t, client, server)

	// Now inject something with epoch 0, but as app data.
	// It will get discarded.
	cbConn.Write([]byte{byte(RecordTypeApplicationData),
		byte(dtls12WireVersion >> 8), byte(dtls12WireVersion & 0xff),
		0, 0, 0, 0, 0, 0, 0, 0, // Epoch 0, seq 0
		0, 5, 1, 2, 3, 4, 5, // Payload
	})

	tmp := make([]byte, 10)
	_, err := server.Read(tmp)
	assertEquals(t, err, AlertWouldBlock)
	closeAndVerifyNoLeaks(t, client, server)
}

func TestHRRRecordVersion(t *testing.T) {
	cConn, sConn := pipe()
	cbConn := newBufferedConn(cConn)
	sbConn := newBufferedConn(sConn)

	cconf := *pskConfig
	cconf.NonBlocking = true
	client := Client(cbConn, &cconf)
	sconf := *hrrConfig
	sconf.NonBlocking = true
	cp, err := NewDefaultCookieProtector()
	assertNotError(t, err, "Couldn't make default cookie protector")
	sconf.CookieProtector = cp
	server := Server(sbConn, &sconf)
	defer client.Close()
	defer server.Close()

	hsUntilBlocked(t, client, cbConn) // CH1
	cbConn.Flush()
	hsUntilBlocked(t, server, sbConn) // HRR
	sbConn.Flush()
	hsUntilBlocked(t, client, cbConn) // CH2

	p := make([]byte, 3)
	_, err = io.ReadFull(&cbConn.buffer, p)
	assertNotError(t, err, "should have records available")
	expectedRecord := []byte{
		byte(RecordTypeHandshake),
		byte(tls12Version >> 8),
		byte(tls12Version & 0xff),
	}
	assertByteEquals(t, p, expectedRecord)
	closeAndVerifyNoLeaks(t, client, server)
}

// Test for issue #175.
func TestEarlyDataWithHRR(t *testing.T) {
	cConn, sConn := pipe()

	cconf := *pskConfig
	cconf.NonBlocking = true
	client := Client(cConn, &cconf)
	sconf := *hrrConfig
	cp, err := NewDefaultCookieProtector()
	assertNotError(t, err, "Couldn't make default cookie protector")
	sconf.CookieProtector = cp
	sconf.NonBlocking = true
	server := Server(sConn, &sconf)
	defer client.Close()
	defer server.Close()

	hsRunHandshakeOneThread(t, client, server)
	closeAndVerifyNoLeaks(t, client, server)
}

func TestEarlyDataNotWritableAfterHRR(t *testing.T) {
	cConn, sConn := pipe()
	cbConn := newBufferedConn(cConn)
	sbConn := newBufferedConn(sConn)
	cbConn.SetAutoflush()
	sbConn.SetAutoflush()

	cconf := *pskConfig
	cconf.NonBlocking = true
	client := Client(cbConn, &cconf)
	sconf := *hrrConfig
	cp, err := NewDefaultCookieProtector()
	assertNotError(t, err, "Couldn't make default cookie protector")
	sconf.CookieProtector = cp
	sconf.NonBlocking = true
	server := Server(sbConn, &sconf)
	defer client.Close()
	defer server.Close()

	// Send CH
	hsUntilBlocked(t, client, cbConn)
	assertTrue(t, client.Writable(), "Client was not writeable")

	// Reject 0-RTT
	hsUntilBlocked(t, server, sbConn)

	// Process HRR
	err = client.Handshake()
	assertEquals(t, err, AlertNoAlert)
	assertTrue(t, !client.Writable(), "Client not writeable after HRR")
	n, err := client.Write([]byte{1, 2, 3})
	assertError(t, err, "Write succeeded")
	assertEquals(t, n, 0)

	// Finish handshake
	hsRunHandshakeOneThread(t, client, server)
	closeAndVerifyNoLeaks(t, client, server)
}

func TestHandshakeMessageAcrossBoundary(t *testing.T) {
	cConn, sConn := pipe()

	// Wrap these in a buffer so we can simulate blocking
	cbConn := newBufferedConn(cConn)
	sbConn := newBufferedConn(sConn)

	client := Client(cbConn, nbConfig)
	server := Server(sbConn, nbConfig)
	defer client.Close()
	defer server.Close()

	var clientAlert, serverAlert Alert

	// Send ClientHello
	clientAlert = client.Handshake()
	assertEquals(t, clientAlert, AlertNoAlert)
	assertEquals(t, client.GetHsState(), StateClientWaitSH)
	serverAlert = server.Handshake()
	assertEquals(t, serverAlert, AlertWouldBlock)
	assertEquals(t, server.GetHsState(), StateServerStart)

	// Release ClientHello
	cbConn.Flush()

	// Process ClientHello, send server first flight.
	states := []State{StateServerNegotiated, StateServerWaitFlight2, StateServerWaitFinished}
	for _, state := range states {
		serverAlert = server.Handshake()
		assertEquals(t, serverAlert, AlertNoAlert)
		assertEquals(t, server.GetHsState(), state)
	}
	serverAlert = server.Handshake()
	assertEquals(t, serverAlert, AlertWouldBlock)

	clientAlert = client.Handshake()
	assertEquals(t, clientAlert, AlertWouldBlock)

	// Rewrite the SH to include an extra byte.
	sbConn.Flush()
	buf := make([]byte, 1024)
	n, err := cbConn.Read(buf)
	assertNotError(t, err, "Error reading SH")
	assertTrue(t, n < len(buf), "SH is too long")
	buf = buf[:n]

	l, _ := decodeUint(buf[3:], 2)
	l++
	encodeUint(l, 2, buf[3:])
	buf = append(buf, byte(HandshakeTypeEncryptedExtensions))

	sbConn.Write(buf)
	sbConn.Flush()

	err = client.Handshake()
	assertEquals(t, AlertDecodeError, err)
	closeAndVerifyNoLeaks(t, client, server)
}
