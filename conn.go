package mint

import (
	"crypto"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"reflect"
	"sync"
	"time"
)

type Certificate struct {
	Chain      []*x509.Certificate
	PrivateKey crypto.Signer
}

type PreSharedKey struct {
	CipherSuite  CipherSuite
	IsResumption bool
	Identity     []byte
	Key          []byte
	NextProto    string
	ReceivedAt   time.Time
	ExpiresAt    time.Time
	TicketAgeAdd uint32
}

type PreSharedKeyCache interface {
	Get(string) (PreSharedKey, bool)
	Put(string, PreSharedKey)
	Size() int
}

// A CookieHandler can be used to give the application more fine-grained control over Cookies.
// Generate receives the Conn as an argument, so the CookieHandler can decide when to send the cookie based on that, and offload state to the client by encoding that into the Cookie.
// When the client echoes the Cookie, Validate is called. The application can then recover the state from the cookie.
type CookieHandler interface {
	// Generate a byte string that is sent as a part of a cookie to the client in the HelloRetryRequest
	// If Generate returns nil, mint will not send a HelloRetryRequest.
	Generate(*Conn) ([]byte, error)
	// Validate is called when receiving a ClientHello containing a Cookie.
	// If validation failed, the handshake is aborted.
	Validate(*Conn, []byte) bool
}

type PSKMapCache map[string]PreSharedKey

func (cache PSKMapCache) Get(key string) (psk PreSharedKey, ok bool) {
	psk, ok = cache[key]
	return
}

func (cache *PSKMapCache) Put(key string, psk PreSharedKey) {
	(*cache)[key] = psk
}

func (cache PSKMapCache) Size() int {
	return len(cache)
}

// Config is the struct used to pass configuration settings to a TLS client or
// server instance.  The settings for client and server are pretty different,
// but we just throw them all in here.
type Config struct {
	// Client fields
	ServerName string

	// Server fields
	SendSessionTickets bool
	TicketLifetime     uint32
	TicketLen          int
	EarlyDataLifetime  uint32
	AllowEarlyData     bool
	// Require the client to echo a cookie.
	RequireCookie bool
	// A CookieHandler can be used to set and validate a cookie.
	// The cookie returned by the CookieHandler will be part of the cookie sent on the wire, and encoded using the CookieProtector.
	// If no CookieHandler is set, mint will always send a cookie.
	// The CookieHandler can be used to decide on a per-connection basis, if a cookie should be sent.
	CookieHandler CookieHandler
	// The CookieProtector is used to encrypt / decrypt cookies.
	// It should make sure that the Cookie cannot be read and tampered with by the client.
	// If non-blocking mode is used, and cookies are required, this field has to be set.
	// In blocking mode, a default cookie protector is used, if this is unused.
	CookieProtector CookieProtector
	// The ExtensionHandler is used to add custom extensions.
	ExtensionHandler  AppExtensionHandler
	RequireClientAuth bool

	// Time returns the current time as the number of seconds since the epoch.
	// If Time is nil, TLS uses time.Now.
	Time func() time.Time
	// RootCAs defines the set of root certificate authorities
	// that clients use when verifying server certificates.
	// If RootCAs is nil, TLS uses the host's root CA set.
	RootCAs *x509.CertPool
	// InsecureSkipVerify controls whether a client verifies the
	// server's certificate chain and host name.
	// If InsecureSkipVerify is true, TLS accepts any certificate
	// presented by the server and any host name in that certificate.
	// In this mode, TLS is susceptible to man-in-the-middle attacks.
	// This should be used only for testing.
	InsecureSkipVerify bool

	// Shared fields
	Certificates []*Certificate
	// VerifyPeerCertificate, if not nil, is called after normal
	// certificate verification by either a TLS client or server. It
	// receives the raw ASN.1 certificates provided by the peer and also
	// any verified chains that normal processing found. If it returns a
	// non-nil error, the handshake is aborted and that error results.
	//
	// If normal verification fails then the handshake will abort before
	// considering this callback. If normal verification is disabled by
	// setting InsecureSkipVerify then this callback will be considered but
	// the verifiedChains argument will always be nil.
	VerifyPeerCertificate func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error

	CipherSuites     []CipherSuite
	Groups           []NamedGroup
	SignatureSchemes []SignatureScheme
	NextProtos       []string
	PSKs             PreSharedKeyCache
	PSKModes         []PSKKeyExchangeMode
	NonBlocking      bool
	UseDTLS          bool
	// EnableExtendedKeyUpdate enables support for Extended Key Update (EKU) as specified
	// in draft-ietf-tls-extended-key-update-07. When enabled, EKU provides post-compromise
	// security through fresh (EC)DHE key exchange during an active session.
	// If EKU is negotiated, standard KeyUpdate MUST NOT be used (mutually exclusive).
	// Both peers must enable EKU for it to be negotiated.
	// Default: false (disabled for backward compatibility).
	EnableExtendedKeyUpdate bool

	RecordLayer RecordLayerFactory

	// The same config object can be shared among different connections, so it
	// needs its own mutex
	mutex sync.RWMutex
}

// Clone returns a shallow clone of c. It is safe to clone a Config that is
// being used concurrently by a TLS client or server.
func (c *Config) Clone() *Config {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	return &Config{
		ServerName: c.ServerName,

		SendSessionTickets: c.SendSessionTickets,
		TicketLifetime:     c.TicketLifetime,
		TicketLen:          c.TicketLen,
		EarlyDataLifetime:  c.EarlyDataLifetime,
		AllowEarlyData:     c.AllowEarlyData,
		RequireCookie:      c.RequireCookie,
		CookieHandler:      c.CookieHandler,
		CookieProtector:    c.CookieProtector,
		ExtensionHandler:   c.ExtensionHandler,
		RequireClientAuth:  c.RequireClientAuth,
		Time:               c.Time,
		RootCAs:            c.RootCAs,
		InsecureSkipVerify: c.InsecureSkipVerify,

		Certificates:          c.Certificates,
		VerifyPeerCertificate: c.VerifyPeerCertificate,
		CipherSuites:          c.CipherSuites,
		Groups:                c.Groups,
		SignatureSchemes:      c.SignatureSchemes,
		NextProtos:            c.NextProtos,
		PSKs:                  c.PSKs,
		PSKModes:              c.PSKModes,
		NonBlocking:           c.NonBlocking,
		UseDTLS:               c.UseDTLS,
		EnableExtendedKeyUpdate: c.EnableExtendedKeyUpdate,
	}
}

func (c *Config) Init(isClient bool) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	// Set defaults
	if len(c.CipherSuites) == 0 {
		c.CipherSuites = defaultSupportedCipherSuites
	}
	if len(c.Groups) == 0 {
		c.Groups = defaultSupportedGroups
	}
	if len(c.SignatureSchemes) == 0 {
		c.SignatureSchemes = defaultSignatureSchemes
	}
	if c.TicketLen == 0 {
		c.TicketLen = defaultTicketLen
	}
	if !reflect.ValueOf(c.PSKs).IsValid() {
		c.PSKs = &PSKMapCache{}
	}
	if len(c.PSKModes) == 0 {
		c.PSKModes = defaultPSKModes
	}
	return nil
}

func (c *Config) ValidForServer() bool {
	return (reflect.ValueOf(c.PSKs).IsValid() && c.PSKs.Size() > 0) ||
		(len(c.Certificates) > 0 &&
			len(c.Certificates[0].Chain) > 0 &&
			c.Certificates[0].PrivateKey != nil)
}

func (c *Config) ValidForClient() bool {
	return len(c.ServerName) > 0
}

func (c *Config) time() time.Time {
	t := c.Time
	if t == nil {
		t = time.Now
	}
	return t()
}

var (
	defaultSupportedCipherSuites = []CipherSuite{
		TLS_AES_128_GCM_SHA256,
		TLS_AES_256_GCM_SHA384,
	}

	defaultSupportedGroups = []NamedGroup{
		P256,
		P384,
		FFDHE2048,
		X25519,
	}

	defaultSignatureSchemes = []SignatureScheme{
		RSA_PSS_SHA256,
		RSA_PSS_SHA384,
		RSA_PSS_SHA512,
		ECDSA_P256_SHA256,
		ECDSA_P384_SHA384,
		ECDSA_P521_SHA512,
	}

	defaultTicketLen = 16

	defaultPSKModes = []PSKKeyExchangeMode{
		PSKModeKE,
		PSKModeDHEKE,
	}
)

type ConnectionState struct {
	HandshakeState   State
	CipherSuite      CipherSuiteParams     // cipher suite in use (TLS_RSA_WITH_RC4_128_SHA, ...)
	PeerCertificates []*x509.Certificate   // certificate chain presented by remote peer
	VerifiedChains   [][]*x509.Certificate // verified chains built from PeerCertificates
	NextProto        string                // Selected ALPN proto
	UsingPSK         bool                  // Are we using PSK.
	UsingEarlyData   bool                  // Did we negotiate 0-RTT.
}

// Controller command types
type controllerCommandType int

const (
	cmdKeyUpdate controllerCommandType = iota
	cmdExtendedKeyUpdate
	cmdClose
)

type controllerCommand struct {
	cmdType       controllerCommandType
	requestUpdate bool // For KeyUpdate command
	result        chan commandResult
}

type commandResult struct {
	err error
}

// Conn implements the net.Conn interface, as with "crypto/tls"
// * Read, Write, and Close are provided locally
// * LocalAddr, RemoteAddr, and Set*Deadline are forwarded to the inner Conn
type Conn struct {
	config   *Config
	conn     net.Conn
	isClient bool

	state             stateConnected
	hState            HandshakeState
	handshakeMutex    sync.Mutex
	handshakeAlert    Alert
	handshakeComplete bool

	readBuffer []byte
	in, out    RecordLayer
	hsCtx      *HandshakeContext

	// Controller channels
	dataToSend     chan []byte
	dataToReceive  chan []byte
	commands       chan controllerCommand
	errors         chan error
	socketRecords  chan *TLSPlaintext
	socketErrors   chan error
	controllerDone chan struct{}
	closed         chan struct{}

	// Controller state
	controllerRunning bool

	// KeyUpdate waiting state
	pendingKeyUpdateResponse chan struct{} // Signals when KeyUpdate response is received

	// ExtendedKeyUpdate waiting state
	pendingEKUResponse chan struct{} // Signals when EKU response (Message 2) or new_key_update (Message 4) is received
}

func NewConn(conn net.Conn, config *Config, isClient bool) *Conn {
	c := &Conn{
		conn:                     conn,
		config:                   config,
		isClient:                 isClient,
		hsCtx:                    &HandshakeContext{},
		dataToSend:               make(chan []byte),               // unbuffered - Write() blocks until controller processes
		dataToReceive:            make(chan []byte, 65536),        // 64KB buffer
		commands:                 make(chan controllerCommand, 1), // buffered, size 1 - allows non-blocking sends
		errors:                   make(chan error, 1),             // buffered, size 1
		socketRecords:            make(chan *TLSPlaintext),        // unbuffered
		socketErrors:             make(chan error),                // unbuffered
		controllerDone:           make(chan struct{}),
		closed:                   make(chan struct{}),
		controllerRunning:        false,
		pendingKeyUpdateResponse: nil, // Will be created when needed
		pendingEKUResponse:       nil, // Will be created when needed
	}
	if !config.UseDTLS {
		if config.RecordLayer == nil {
			c.in = NewRecordLayerTLS(c.conn, DirectionRead)
			c.out = NewRecordLayerTLS(c.conn, DirectionWrite)
		} else {
			c.in = config.RecordLayer.NewLayer(c.conn, DirectionRead)
			c.out = config.RecordLayer.NewLayer(c.conn, DirectionWrite)
		}
		c.hsCtx.hIn = NewHandshakeLayerTLS(c.hsCtx, c.in)
		c.hsCtx.hOut = NewHandshakeLayerTLS(c.hsCtx, c.out)
	} else {
		c.in = NewRecordLayerDTLS(c.conn, DirectionRead)
		c.out = NewRecordLayerDTLS(c.conn, DirectionWrite)
		c.hsCtx.hIn = NewHandshakeLayerDTLS(c.hsCtx, c.in)
		c.hsCtx.hOut = NewHandshakeLayerDTLS(c.hsCtx, c.out)
		c.hsCtx.timeoutMS = initialTimeout
		c.hsCtx.timers = newTimerSet()
		c.hsCtx.waitingNextFlight = true
	}
	c.in.SetLabel(c.label())
	c.out.SetLabel(c.label())
	c.hsCtx.hIn.nonblocking = c.config.NonBlocking
	return c
}

// Read up
func (c *Conn) consumeRecord() error {
	pt, err := c.in.ReadRecord()
	if pt == nil {
		logf(logTypeIO, "extendBuffer returns error %v", err)
		return err
	}

	switch pt.contentType {
	case RecordTypeHandshake:
		logf(logTypeHandshake, "Received post-handshake message")
		// We do not support fragmentation of post-handshake handshake messages.
		// TODO: Factor this more elegantly; coalesce with handshakeLayer.ReadMessage()
		start := 0
		headerLen := handshakeHeaderLenTLS
		if c.config.UseDTLS {
			headerLen = handshakeHeaderLenDTLS
		}
		for start < len(pt.fragment) {
			if len(pt.fragment[start:]) < headerLen {
				return fmt.Errorf("post-handshake handshake message too short for header")
			}

			hm := &HandshakeMessage{}
			hm.msgType = HandshakeType(pt.fragment[start])
			hmLen := (int(pt.fragment[start+1]) << 16) + (int(pt.fragment[start+2]) << 8) + int(pt.fragment[start+3])

			if len(pt.fragment[start+headerLen:]) < hmLen {
				return fmt.Errorf("post-handshake handshake message too short for body")
			}
			hm.body = pt.fragment[start+headerLen : start+headerLen+hmLen]

			// XXX: If we want to support more advanced cases, e.g., post-handshake
			// authentication, we'll need to allow transitions other than
			// Connected -> Connected
			state, actions, alert := c.state.ProcessMessage(hm)
			if alert != AlertNoAlert {
				logf(logTypeHandshake, "Error in state transition: %v", alert)
				c.sendAlert(alert)
				return io.EOF
			}

			for _, action := range actions {
				alert = c.takeAction(action)
				if alert != AlertNoAlert {
					logf(logTypeHandshake, "Error during handshake actions: %v", alert)
					c.sendAlert(alert)
					return io.EOF
				}
			}

			var connected bool
			c.state, connected = state.(stateConnected)
			if !connected {
				logf(logTypeHandshake, "Disconnected after state transition: %v", alert)
				c.sendAlert(alert)
				return io.EOF
			}

			start += headerLen + hmLen
		}
	case RecordTypeAlert:
		logf(logTypeIO, "extended buffer (for alert): [%d] %x", len(c.readBuffer), c.readBuffer)
		if len(pt.fragment) != 2 {
			c.sendAlert(AlertUnexpectedMessage)
			return io.EOF
		}
		if Alert(pt.fragment[1]) == AlertCloseNotify {
			return io.EOF
		}

		switch pt.fragment[0] {
		case AlertLevelWarning:
			// drop on the floor
		case AlertLevelError:
			return Alert(pt.fragment[1])
		default:
			c.sendAlert(AlertUnexpectedMessage)
			return io.EOF
		}

	case RecordTypeAck:
		if !c.hsCtx.hIn.datagram {
			logf(logTypeHandshake, "Received ACK in TLS mode")
			return AlertUnexpectedMessage
		}
		return c.hsCtx.processAck(pt.fragment)

	case RecordTypeApplicationData:
		c.readBuffer = append(c.readBuffer, pt.fragment...)
		logf(logTypeIO, "extended buffer: [%d] %x", len(c.readBuffer), c.readBuffer)

	}

	return err
}

func readPartial(in *[]byte, buffer []byte) int {
	logf(logTypeIO, "conn.Read input buffer now has len %d", len((*in)))
	read := copy(buffer, *in)
	*in = (*in)[read:]

	logf(logTypeVerbose, "Returning %v", string(buffer))
	return read
}

// Read application data up to the size of buffer.  Handshake and alert records
// are consumed by the Conn object directly.
func (c *Conn) Read(buffer []byte) (int, error) {
	if _, connected := c.hState.(stateConnected); !connected {
		// Clients can't call Read prior to handshake completion.
		if c.isClient {
			return 0, errors.New("Read called before the handshake completed")
		}

		// Neither can servers that don't allow early data.
		if !c.config.AllowEarlyData {
			return 0, errors.New("Read called before the handshake completed")
		}

		// If there's no early data, then return WouldBlock
		if len(c.hsCtx.earlyData) == 0 {
			return 0, AlertWouldBlock
		}

		return readPartial(&c.hsCtx.earlyData, buffer), nil
	}

	// The handshake is now connected.
	logf(logTypeHandshake, "conn.Read with buffer = %d", len(buffer))
	
	// DTLS: Read directly from record layer (no controller, no Handshake() call needed)
	if c.config.UseDTLS {
		// Run our timers.
		if err := c.hsCtx.timers.check(time.Now()); err != nil {
			return 0, AlertInternalError
		}
		
		if len(buffer) == 0 {
			return 0, nil
		}
		// Check for buffered data
		if len(c.readBuffer) > 0 {
			n := copy(buffer, c.readBuffer)
			c.readBuffer = c.readBuffer[n:]
			logf(logTypeHandshake, "%s Read() returning buffered data, n=%d", c.label(), n)
			return n, nil
		}

		// Lock the input channel (same as original code)
		c.in.Lock()
		defer c.in.Unlock()

		// Loop calling consumeRecord() until we have data (same pattern as original)
		for len(c.readBuffer) == 0 {
			err := c.consumeRecord()

			// err can be nil if consumeRecord processed a non app-data record
			// err can be AlertWouldBlock if no data is available
			if err != nil {
				if c.config.NonBlocking || err != AlertWouldBlock {
					logf(logTypeIO, "conn.Read returns err=%v", err)
					return 0, err
				}
				// In blocking mode, continue loop (will block on next ReadRecord() call)
				continue
			}
		}

		// We have data in readBuffer, return it
		n := copy(buffer, c.readBuffer)
		c.readBuffer = c.readBuffer[n:]
		return n, nil
	}

	// TLS: Use controller
	// Ensure handshake is complete
	logf(logTypeHandshake, "%s Read() calling Handshake()", c.label())
	if alert := c.Handshake(); alert != AlertNoAlert {
		logf(logTypeHandshake, "%s Read() Handshake() returned alert=%v", c.label(), alert)
		return 0, alert
	}
	logf(logTypeHandshake, "%s Read() Handshake() completed", c.label())

	if len(buffer) == 0 {
		logf(logTypeHandshake, "%s Read() buffer is empty, returning 0", c.label())
		return 0, nil
	}

	// Check for buffered data from before controller started
	if len(c.readBuffer) > 0 {
		n := copy(buffer, c.readBuffer)
		c.readBuffer = c.readBuffer[n:]
		logf(logTypeHandshake, "%s Read() returning buffered data, n=%d", c.label(), n)
		return n, nil
	}

	// Ensure controller is running
	if !c.controllerRunning {
		logf(logTypeHandshake, "%s Read() ERROR: controller not running", c.label())
		return 0, errors.New("read called before controller started")
	}

	logf(logTypeHandshake, "%s Read() BLOCKING: waiting for data from dataToReceive channel", c.label())
	// Wait for data from controller
	// Since application is synchronous, only one Read() can be active at a time
	if c.config.NonBlocking {
		// Non-blocking mode: return immediately if no data available
		select {
		case data := <-c.dataToReceive:
			// Copy data to buffer (may be partial read)
			n := copy(buffer, data)
			// Buffer remainder if data is larger than buffer
			if len(data) > n {
				c.readBuffer = append(c.readBuffer, data[n:]...)
			}
			return n, nil
		case err := <-c.errors:
			return 0, err
		case <-c.closed:
			return 0, io.EOF
		default:
			// No data available
			return 0, AlertWouldBlock
		}
	} else {
		// Blocking mode: wait for data
		select {
		case data := <-c.dataToReceive:
			// Copy data to buffer (may be partial read)
			logf(logTypeHandshake, "%s Read() received data from dataToReceive, len=%d", c.label(), len(data))
			n := copy(buffer, data)
			// Buffer remainder if data is larger than buffer
			if len(data) > n {
				c.readBuffer = append(c.readBuffer, data[n:]...)
				logf(logTypeHandshake, "%s Read() buffered %d remaining bytes", c.label(), len(data)-n)
			}
			logf(logTypeHandshake, "%s Read() returning, n=%d", c.label(), n)
			return n, nil
		case err := <-c.errors:
			return 0, err
		case <-c.closed:
			return 0, io.EOF
		}
	}
}

// Write application data
func (c *Conn) Write(buffer []byte) (int, error) {
	logf(logTypeHandshake, "%s Write() START: called, len=%d", c.label(), len(buffer))
	if !c.Writable() {
		return 0, errors.New("Write called before the handshake completed (and early data not in use)")
	}

	// Handle early data writes (before controller starts)
	if c.isClient && c.out.Epoch() == EpochEarlyData {
		logf(logTypeHandshake, "%s Write() handling early data", c.label())
		// Early data: write directly to record layer (not through controller)
		c.out.Lock()
		defer c.out.Unlock()

		// Send full-size fragments
		var start int
		for start = 0; len(buffer)-start >= maxFragmentLen; start += maxFragmentLen {
			err := c.out.WriteRecord(&TLSPlaintext{
				contentType: RecordTypeApplicationData,
				fragment:    buffer[start : start+maxFragmentLen],
			})
			if err != nil {
				return start, err
			}
		}

		// Send a final partial fragment if necessary
		if start < len(buffer) {
			err := c.out.WriteRecord(&TLSPlaintext{
				contentType: RecordTypeApplicationData,
				fragment:    buffer[start:],
			})
			if err != nil {
				return start, err
			}
		}

		return len(buffer), nil
	}

	// DTLS: Write directly to record layer (no controller)
	if c.config.UseDTLS {
		c.out.Lock()
		defer c.out.Unlock()

		// Send full-size fragments
		var start int
		for start = 0; len(buffer)-start >= maxFragmentLen; start += maxFragmentLen {
			err := c.out.WriteRecord(&TLSPlaintext{
				contentType: RecordTypeApplicationData,
				fragment:    buffer[start : start+maxFragmentLen],
			})
			if err != nil {
				return start, err
			}
		}

		// Send a final partial fragment if necessary
		if start < len(buffer) {
			err := c.out.WriteRecord(&TLSPlaintext{
				contentType: RecordTypeApplicationData,
				fragment:    buffer[start:],
			})
			if err != nil {
				return start, err
			}
		}

		return len(buffer), nil
	}

	// TLS: Use controller
	// Ensure controller is running for post-handshake writes
	if !c.controllerRunning {
		logf(logTypeHandshake, "%s Write() ERROR: controller not running!", c.label())
		return 0, errors.New("write called before controller started")
	}

	logf(logTypeHandshake, "%s Write() TLS: controller is running, about to send to dataToSend channel, len=%d (channel len=%d, cap=%d)", c.label(), len(buffer), len(c.dataToSend), cap(c.dataToSend))
	// Send data to controller
	// Since application is synchronous, only one Write() can be active at a time
	if c.config.NonBlocking {
		logf(logTypeHandshake, "%s Write() NonBlocking mode: attempting to send", c.label())
		// Non-blocking mode: return immediately if channel is full
		select {
		case c.dataToSend <- buffer:
			// Data sent successfully - controller will encrypt and send to socket
			return len(buffer), nil
		case err := <-c.errors:
			// Error from controller
			return 0, err
		case <-c.closed:
			// Connection closed
			return 0, io.EOF
		default:
			// Channel is full
			return 0, AlertWouldBlock
		}
	} else {
		// Blocking mode: wait until controller accepts data
		logf(logTypeHandshake, "%s Write() Blocking mode: BLOCKING on select, waiting for controller to read from dataToSend", c.label())
		select {
		case c.dataToSend <- buffer:
			// Data sent successfully - controller will encrypt and send to socket
			// Note: This blocks until controller reads from channel (or channel has capacity)
			// With 64KB buffer, channel should rarely be full
			logf(logTypeHandshake, "%s Write() Blocking: ✓✓✓ SUCCESS: sent to dataToSend, returning", c.label())
			return len(buffer), nil
		case err := <-c.errors:
			// Error from controller
			return 0, err
		case <-c.closed:
			// Connection closed
			return 0, io.EOF
		}
	}
}

// sendAlert sends a TLS alert message.
// c.out.Mutex <= L.
func (c *Conn) sendAlert(err Alert) error {
	c.handshakeMutex.Lock()
	defer c.handshakeMutex.Unlock()

	var level int
	switch err {
	case AlertNoRenegotiation, AlertCloseNotify:
		level = AlertLevelWarning
	default:
		level = AlertLevelError
	}

	buf := []byte{byte(err), byte(level)}
	c.out.WriteRecord(&TLSPlaintext{
		contentType: RecordTypeAlert,
		fragment:    buf,
	})

	// close_notify and end_of_early_data are not actually errors
	if level == AlertLevelWarning {
		return &net.OpError{Op: "local error", Err: err}
	}

	return c.Close()
}

// Close closes the connection.
func (c *Conn) Close() error {
	if !c.controllerRunning {
		// Controller not running, just close the connection
		return c.conn.Close()
	}

	// Close the closed channel to signal shutdown
	select {
	case <-c.closed:
		// Already closed
	default:
		close(c.closed)
	}

	// Send close command to controller
	resultChan := make(chan commandResult, 1)
	cmd := controllerCommand{
		cmdType: cmdClose,
		result:  resultChan,
	}

	select {
	case c.commands <- cmd:
		// Wait for controller to close
		<-resultChan
		<-c.controllerDone // Wait for goroutine to exit
		return nil
	case <-c.controllerDone:
		// Controller already closed
		return nil
	case <-c.closed:
		// Already closed
		return nil
	}
}

// LocalAddr returns the local network address.
func (c *Conn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

// RemoteAddr returns the remote network address.
func (c *Conn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

// SetDeadline sets the read and write deadlines associated with the connection.
// A zero value for t means Read and Write will not time out.
// After a Write has timed out, the TLS state is corrupt and all future writes will return the same error.
func (c *Conn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

// SetReadDeadline sets the read deadline on the underlying connection.
// A zero value for t means Read will not time out.
func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

// SetWriteDeadline sets the write deadline on the underlying connection.
// A zero value for t means Write will not time out.
// After a Write has timed out, the TLS state is corrupt and all future writes will return the same error.
func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

func (c *Conn) takeAction(actionGeneric HandshakeAction) Alert {
	label := "[server]"
	if c.isClient {
		label = "[client]"
	}

	switch action := actionGeneric.(type) {
	case QueueHandshakeMessage:
		logf(logTypeHandshake, "%s queuing handshake message type=%v", label, action.Message.msgType)
		err := c.hsCtx.hOut.QueueMessage(action.Message)
		if err != nil {
			logf(logTypeHandshake, "%s Error writing handshake message: %v", label, err)
			return AlertInternalError
		}

	case SendQueuedHandshake:
		// Lock output for thread safety (controller goroutine)
		c.out.Lock()
		if outImpl, ok := c.out.(*DefaultRecordLayer); ok {
			logf(logTypeHandshake, "%s SendQueuedHandshake: before send, cipher epoch=%s, seq=%x", label, outImpl.cipher.epoch.label(), outImpl.cipher.seq)
		}
		logf(logTypeHandshake, "%s SendQueuedHandshake: sending queued handshake messages", label)
		_, err := c.hsCtx.hOut.SendQueuedMessages()
		if outImpl, ok := c.out.(*DefaultRecordLayer); ok {
			logf(logTypeHandshake, "%s SendQueuedHandshake: after send, cipher epoch=%s, seq=%x", label, outImpl.cipher.epoch.label(), outImpl.cipher.seq)
		}
		if err != nil {
			logf(logTypeHandshake, "%s SendQueuedHandshake: ERROR sending: %v", label, err)
		} else {
			logf(logTypeHandshake, "%s SendQueuedHandshake: successfully sent queued messages", label)
		}
		c.out.Unlock()
		if err != nil {
			logf(logTypeHandshake, "%s Error writing handshake message: %v", label, err)
			return AlertInternalError
		}
		if c.config.UseDTLS {
			c.hsCtx.timers.start(retransmitTimerLabel,
				c.hsCtx.handshakeRetransmit,
				c.hsCtx.timeoutMS)
		}
	case RekeyIn:
		logf(logTypeHandshake, "%s Rekeying in to %s: %+v", label, action.epoch.label(), action.KeySet)
		if inImpl, ok := c.in.(*DefaultRecordLayer); ok {
			logf(logTypeHandshake, "%s RekeyIn: current cipher epoch=%s, seq=%x", label, inImpl.cipher.epoch.label(), inImpl.cipher.seq)
		}
		// Check that we don't have an input data in the handshake frame parser.
		if len(c.hsCtx.hIn.frame.remainder) > 0 {
			logf(logTypeHandshake, "%s Rekey with data still in handshake buffers", label)
			return AlertDecodeError
		}
		err := c.in.Rekey(action.epoch, action.KeySet.Cipher, &action.KeySet)
		if err != nil {
			logf(logTypeHandshake, "%s Unable to rekey inbound: %v", label, err)
			return AlertInternalError
		}
		if inImpl, ok := c.in.(*DefaultRecordLayer); ok {
			logf(logTypeHandshake, "%s RekeyIn: new cipher epoch=%s, seq=%x", label, inImpl.cipher.epoch.label(), inImpl.cipher.seq)
		}

	case RekeyOut:
		logf(logTypeHandshake, "%s Rekeying out to %s: %+v", label, action.epoch.label(), action.KeySet)
		if outImpl, ok := c.out.(*DefaultRecordLayer); ok {
			logf(logTypeHandshake, "%s RekeyOut: current cipher epoch=%s, seq=%x", label, outImpl.cipher.epoch.label(), outImpl.cipher.seq)
		}
		err := c.out.Rekey(action.epoch, action.KeySet.Cipher, &action.KeySet)
		if err != nil {
			logf(logTypeHandshake, "%s Unable to rekey outbound: %v", label, err)
			return AlertInternalError
		}
		if outImpl, ok := c.out.(*DefaultRecordLayer); ok {
			logf(logTypeHandshake, "%s RekeyOut: new cipher epoch=%s, seq=%x", label, outImpl.cipher.epoch.label(), outImpl.cipher.seq)
		}

	case ResetOut:
		logf(logTypeHandshake, "%s Rekeying out to %s seq=%v", label, EpochClear, action.seq)
		c.out.ResetClear(action.seq)

	case StorePSK:
		logf(logTypeHandshake, "%s Storing new session ticket with identity [%x]", label, action.PSK.Identity)
		if c.isClient {
			// Clients look up PSKs based on server name
			c.config.PSKs.Put(c.config.ServerName, action.PSK)
		} else {
			// Servers look them up based on the identity in the extension
			c.config.PSKs.Put(hex.EncodeToString(action.PSK.Identity), action.PSK)
		}

	default:
		logf(logTypeHandshake, "%s Unknown action type", label)
		assert(false)
		return AlertInternalError
	}

	return AlertNoAlert
}

func (c *Conn) HandshakeSetup() Alert {
	var state HandshakeState
	var actions []HandshakeAction
	var alert Alert

	if err := c.config.Init(c.isClient); err != nil {
		logf(logTypeHandshake, "Error initializing config: %v", err)
		return AlertInternalError
	}

	opts := ConnectionOptions{
		ServerName: c.config.ServerName,
		NextProtos: c.config.NextProtos,
	}

	if c.isClient {
		state, actions, alert = clientStateStart{Config: c.config, Opts: opts, hsCtx: c.hsCtx}.Next(nil)
		if alert != AlertNoAlert {
			logf(logTypeHandshake, "Error initializing client state: %v", alert)
			return alert
		}

		for _, action := range actions {
			alert = c.takeAction(action)
			if alert != AlertNoAlert {
				logf(logTypeHandshake, "Error during handshake actions: %v", alert)
				return alert
			}
		}
	} else {
		if c.config.RequireCookie && c.config.CookieProtector == nil {
			logf(logTypeHandshake, "RequireCookie set, but no CookieProtector provided. Using default cookie protector. Stateless Retry not possible.")
			if c.config.NonBlocking {
				logf(logTypeHandshake, "Not possible in non-blocking mode.")
				return AlertInternalError
			}
			var err error
			c.config.CookieProtector, err = NewDefaultCookieProtector()
			if err != nil {
				logf(logTypeHandshake, "Error initializing cookie source: %v", alert)
				return AlertInternalError
			}
		}
		state = serverStateStart{Config: c.config, conn: c, hsCtx: c.hsCtx}
	}

	c.hState = state
	return AlertNoAlert
}

type handshakeMessageReader interface {
	ReadMessage() (*HandshakeMessage, Alert)
}

type handshakeMessageReaderImpl struct {
	hsCtx *HandshakeContext
}

var _ handshakeMessageReader = &handshakeMessageReaderImpl{}

func (r *handshakeMessageReaderImpl) ReadMessage() (*HandshakeMessage, Alert) {
	var hm *HandshakeMessage
	var err error
	for {
		hm, err = r.hsCtx.hIn.ReadMessage()
		if err == AlertWouldBlock {
			return nil, AlertWouldBlock
		}
		if err != nil {
			logf(logTypeHandshake, "Error reading message: %v", err)
			return nil, AlertCloseNotify
		}
		if hm != nil {
			break
		}
	}

	return hm, AlertNoAlert
}

// Handshake causes a TLS handshake on the connection.  The `isClient` member
// determines whether a client or server handshake is performed.  If a
// handshake has already been performed, then its result will be returned.
func (c *Conn) Handshake() Alert {
	label := "[server]"
	if c.isClient {
		label = "[client]"
	}

	// TODO Lock handshakeMutex
	// TODO Remove CloseNotify hack
	if c.handshakeAlert != AlertNoAlert && c.handshakeAlert != AlertCloseNotify {
		logf(logTypeHandshake, "Pre-existing handshake error: %v", c.handshakeAlert)
		return c.handshakeAlert
	}
	if c.handshakeComplete {
		return AlertNoAlert
	}

	if c.hState == nil {
		logf(logTypeHandshake, "%s First time through handshake (or after stateless retry), setting up", label)
		alert := c.HandshakeSetup()
		if alert != AlertNoAlert || (c.isClient && c.config.NonBlocking) {
			return alert
		}
	}

	logf(logTypeHandshake, "(Re-)entering handshake, state=%v", c.hState)
	state := c.hState
	_, connected := state.(stateConnected)

	hmr := &handshakeMessageReaderImpl{hsCtx: c.hsCtx}
	for !connected {
		var alert Alert
		var actions []HandshakeAction

		// Advance the state machine
		state, actions, alert = state.Next(hmr)
		if alert == AlertWouldBlock {
			logf(logTypeHandshake, "%s Would block reading message: %s", label, alert)
			// If we blocked, then run our timers to see if any have expired.
			if c.hsCtx.hIn.datagram {
				if err := c.hsCtx.timers.check(time.Now()); err != nil {
					return AlertInternalError
				}
			}
			return AlertWouldBlock
		}
		if alert == AlertCloseNotify {
			logf(logTypeHandshake, "%s Error reading message: %s", label, alert)
			c.sendAlert(AlertCloseNotify)
			return AlertCloseNotify
		}
		if alert != AlertNoAlert && alert != AlertStatelessRetry {
			logf(logTypeHandshake, "Error in state transition: %v", alert)
			return alert
		}

		for index, action := range actions {
			logf(logTypeHandshake, "%s taking next action (%d)", label, index)
			if alert := c.takeAction(action); alert != AlertNoAlert {
				logf(logTypeHandshake, "Error during handshake actions: %v", alert)
				c.sendAlert(alert)
				return alert
			}
		}

		c.hState = state
		logf(logTypeHandshake, "state is now %s", c.GetHsState())
		_, connected = state.(stateConnected)
		if connected {
			c.state = state.(stateConnected)
			c.handshakeComplete = true

			// Start the TLS Controller goroutine after handshake completes
			// Only for TLS (not DTLS) - DTLS doesn't use the controller
			if !c.config.UseDTLS {
				c.startController()
			}

			if !c.isClient {
				// Send NewSessionTicket if configured to
				if c.config.SendSessionTickets {
					actions, alert := c.state.NewSessionTicket(
						c.config.TicketLen,
						c.config.TicketLifetime,
						c.config.EarlyDataLifetime)

					for _, action := range actions {
						alert = c.takeAction(action)
						if alert != AlertNoAlert {
							logf(logTypeHandshake, "Error during handshake actions: %v", alert)
							c.sendAlert(alert)
							return alert
						}
					}
				}

				// If there is early data, move it into the main buffer
				if c.hsCtx.earlyData != nil {
					c.readBuffer = c.hsCtx.earlyData
					c.hsCtx.earlyData = nil
				}

			} else {
				assert(c.hsCtx.earlyData == nil)
			}
		}

		if c.config.NonBlocking {
			if alert == AlertStatelessRetry {
				return AlertStatelessRetry
			}
			return AlertNoAlert
		}
	}

	return AlertNoAlert
}

// initiateKeyUpdate initiates a KeyUpdate via the controller
func (c *Conn) initiateKeyUpdate(requestUpdate bool) error {
	logf(logTypeHandshake, "%s initiateKeyUpdate() called, requestUpdate=%v", c.label(), requestUpdate)
	if !c.controllerRunning {
		return errors.New("keyUpdate called before controller started")
	}

	// Create command
	resultChan := make(chan commandResult, 1)
	cmd := controllerCommand{
		cmdType:       cmdKeyUpdate,
		requestUpdate: requestUpdate,
		result:        resultChan,
	}

	logf(logTypeHandshake, "%s initiateKeyUpdate() sending command to controller", c.label())
	// Send command (blocks until controller accepts)
	select {
	case c.commands <- cmd:
		logf(logTypeHandshake, "%s initiateKeyUpdate() command sent, waiting for result", c.label())
		// Wait for result (blocks until complete)
		result := <-resultChan
		logf(logTypeHandshake, "%s initiateKeyUpdate() received result, err=%v", c.label(), result.err)
		return result.err
	case err := <-c.errors:
		return err
	case <-c.closed:
		return io.EOF
	}
}

func (c *Conn) SendKeyUpdate(requestUpdate bool) error {
	// For now, delegate to initiateKeyUpdate
	// TODO: Remove this method once all callers use initiateKeyUpdate
	return c.initiateKeyUpdate(requestUpdate)
}

// SendExtendedKeyUpdate initiates an Extended Key Update (EKU) exchange.
//
// EKU provides post-compromise security by performing a fresh (EC)DHE key exchange
// within an active TLS session. This is more secure than standard KeyUpdate, which
// only derives new keys from existing traffic secrets without fresh entropy.
//
// The EKU exchange consists of 4 messages:
//   1. key_update_request: Initiator sends a KeyShareEntry with a fresh public key
//   2. key_update_response: Responder sends a KeyShareEntry with a fresh public key
//   3. new_key_update: Initiator sends after deriving new keys from the shared secret
//   4. new_key_update: Responder sends after deriving new keys from the shared secret
//
// This method blocks until all 4 messages are exchanged and new keys are activated.
// The method returns an error if:
//   - EKU was not negotiated during the handshake
//   - The handshake is not yet complete
//   - An EKU is already in progress
//   - The connection is closed
//
// For DTLS connections, EKU is handled synchronously without the controller.
// For TLS connections, EKU uses the TLS Controller architecture.
//
// See draft-ietf-tls-extended-key-update-07 for the complete specification.
func (c *Conn) SendExtendedKeyUpdate() error {
	if !c.handshakeComplete {
		return errors.New("cannot update keys until after handshake")
	}

	if !c.state.Params.UsingExtendedKeyUpdate {
		return errors.New("Extended Key Update not negotiated")
	}

	if c.state.ekuInProgress {
		return errors.New("Extended Key Update already in progress")
	}

	// For DTLS, handle EKU synchronously (no controller)
	if c.config.UseDTLS {
		return c.sendExtendedKeyUpdateDTLS()
	}

	// For TLS, use controller
	if !c.controllerRunning {
		return errors.New("Extended Key Update called before controller started")
	}

	// Create command and send to controller
	resultChan := make(chan commandResult, 1)
	cmd := controllerCommand{
		cmdType: cmdExtendedKeyUpdate,
		result:  resultChan,
	}

	logf(logTypeHandshake, "%s SendExtendedKeyUpdate() sending command to controller", c.label())
	// Send command (blocks until controller accepts)
	select {
	case c.commands <- cmd:
		logf(logTypeHandshake, "%s SendExtendedKeyUpdate() command sent, waiting for result", c.label())
		// Wait for result (blocks until complete)
		select {
		case result := <-resultChan:
			logf(logTypeHandshake, "%s SendExtendedKeyUpdate() received result, err=%v", c.label(), result.err)
			return result.err
		case err := <-c.errors:
			return err
		case <-c.closed:
			return io.EOF
		}
	case err := <-c.errors:
		return err
	case <-c.closed:
		return io.EOF
	}
}

// sendExtendedKeyUpdateDTLS handles EKU for DTLS synchronously
func (c *Conn) sendExtendedKeyUpdateDTLS() error {
	logf(logTypeHandshake, "%s sendExtendedKeyUpdateDTLS() called", c.label())

	// Step 1: Send key_update_request (Message 1)
	actions, alert := (&c.state).ExtendedKeyUpdateInitiate()
	if alert != AlertNoAlert {
		c.sendAlert(alert)
		return fmt.Errorf("alert while generating EKU request: %v", alert)
	}

	// Take actions (send key_update_request)
	for _, action := range actions {
		actionAlert := c.takeAction(action)
		if actionAlert != AlertNoAlert {
			c.sendAlert(actionAlert)
			return fmt.Errorf("alert during EKU actions: %v", actionAlert)
		}
	}

	// Step 2: Wait for key_update_response (Message 2)
	// Poll Read() to process incoming messages
	for !c.state.ekuInProgress || c.state.ekuIsInitiator {
		// Check if we've received Message 2 (response)
		// The state machine will have processed it if we're past the response stage
		if c.state.ekuResponseMessage != nil {
			break
		}

		// Read a record to process incoming messages
		c.in.Lock()
		pt, err := c.in.ReadRecord()
		c.in.Unlock()

		if pt == nil {
			if err == io.EOF {
				return io.EOF
			}
			if err == AlertWouldBlock {
				// No data available, continue waiting
				continue
			}
			return err
		}

		// Process the record
		if pt.contentType == RecordTypeHandshake {
			if err := c.consumeRecordDTLS(pt); err != nil {
				return err
			}
		}
	}

	// Step 3: Wait for responder's new_key_update (Message 4)
	// The state machine should have sent our new_key_update (Message 3) automatically
	for c.state.ekuInProgress {
		// Read records to process incoming messages
		c.in.Lock()
		pt, err := c.in.ReadRecord()
		c.in.Unlock()

		if pt == nil {
			if err == io.EOF {
				return io.EOF
			}
			if err == AlertWouldBlock {
				// No data available, continue waiting
				continue
			}
			return err
		}

		// Process the record
		if pt.contentType == RecordTypeHandshake {
			if err := c.consumeRecordDTLS(pt); err != nil {
				return err
			}
		}

		// Check if EKU is complete (state cleared)
		if !c.state.ekuInProgress {
			break
		}
	}

	logf(logTypeHandshake, "%s sendExtendedKeyUpdateDTLS() completed", c.label())
	return nil
}

// consumeRecordDTLS processes a DTLS record for EKU
func (c *Conn) consumeRecordDTLS(pt *TLSPlaintext) error {
	if pt.contentType != RecordTypeHandshake {
		return nil // Not a handshake record
	}

	// Parse handshake message
	start := 0
	headerLen := handshakeHeaderLenDTLS

	for start < len(pt.fragment) {
		if len(pt.fragment[start:]) < headerLen {
			return fmt.Errorf("post-handshake handshake message too short for header")
		}

		hm := &HandshakeMessage{}
		hm.msgType = HandshakeType(pt.fragment[start])
		hmLen := (int(pt.fragment[start+1]) << 16) + (int(pt.fragment[start+2]) << 8) + int(pt.fragment[start+3])

		if len(pt.fragment[start+headerLen:]) < hmLen {
			return fmt.Errorf("post-handshake handshake message too short for body")
		}
		hm.body = pt.fragment[start+headerLen : start+headerLen+hmLen]

		// Reject standard KeyUpdate if EKU is negotiated
		if hm.msgType == HandshakeTypeKeyUpdate && c.state.Params.UsingExtendedKeyUpdate {
			logf(logTypeHandshake, "%s consumeRecordDTLS() ERROR: Received standard KeyUpdate but EKU is negotiated", c.label())
			alert := AlertUnexpectedMessage
			c.sendAlert(alert)
			return fmt.Errorf("unexpected standard KeyUpdate when Extended Key Update is negotiated: %v", alert)
		}

		// Process message using state machine
		state, actions, alert := c.state.ProcessMessage(hm)
		if alert != AlertNoAlert {
			logf(logTypeHandshake, "Error in state transition: %v", alert)
			c.sendAlert(alert)
			return alert
		}

		// Take actions (rekey, send response, etc.)
		for _, action := range actions {
			actionAlert := c.takeAction(action)
			if actionAlert != AlertNoAlert {
				logf(logTypeHandshake, "Error during handshake actions: %v", actionAlert)
				c.sendAlert(actionAlert)
				return actionAlert
			}
		}

		// Update state
		var connected bool
		c.state, connected = state.(stateConnected)
		if !connected {
			logf(logTypeHandshake, "Disconnected after state transition")
			return fmt.Errorf("disconnected after state transition")
		}

		start += headerLen + hmLen
	}

	return nil
}

func (c *Conn) GetHsState() State {
	if c.hState == nil {
		return StateInit
	}
	return c.hState.State()
}

// startController starts the TLS Controller goroutine after handshake completes
func (c *Conn) startController() {
	if c.controllerRunning {
		return // Already running
	}

	c.controllerRunning = true
	go c.controllerLoop()
}

// socketReaderLoop reads records from the socket and sends them to the controller
func (c *Conn) socketReaderLoop() {
	defer logf(logTypeHandshake, "%s socketReaderLoop exiting", c.label())
	logf(logTypeHandshake, "%s socketReaderLoop STARTED", c.label())
	for {
		// Read record from socket (blocking)
		logf(logTypeHandshake, "%s socketReaderLoop: BLOCKING on ReadRecord()", c.label())
		pt, err := c.in.ReadRecord()
		if err != nil {
			logf(logTypeHandshake, "%s socketReaderLoop: ReadRecord() returned error=%v", c.label(), err)
			// AlertWouldBlock means no data available yet
			if err == AlertWouldBlock {
				logf(logTypeHandshake, "%s socketReaderLoop: ReadRecord returned AlertWouldBlock, waiting", c.label())
				// pipeConn.Read() doesn't block, so we need to wait a bit before retrying
				// to avoid busy-looping. Use a very short delay to be responsive.
				// The controller processes writes synchronously, so data should arrive quickly.
				select {
				case <-time.After(1 * time.Millisecond):
					// Retry after very short delay (1ms instead of 10ms for responsiveness)
				case <-c.closed:
					return
				}
				continue
			}
			// Check if this is a DecryptError for application data that might be due to KeyUpdate
			// After KeyUpdate, application data is encrypted with new keys, but we might
			// try to decrypt with old keys before processing the KeyUpdate handshake
			if decryptErr, ok := err.(DecryptError); ok {
				logf(logTypeHandshake, "%s socketReaderLoop: DecryptError received: %v - might be due to KeyUpdate, sending to controller", c.label(), decryptErr)
				// Send a special "decrypt error" record to controller
				// Controller can check if there's a pending KeyUpdate handshake and handle it
				// For now, send error - proper fix would queue record and process KeyUpdate first
				select {
				case c.socketErrors <- err:
				case <-c.closed:
					return
				}
				return
			}
			// Other errors are fatal
			logf(logTypeHandshake, "%s socketReaderLoop: FATAL ReadRecord error: %v", c.label(), err)
			select {
			case c.socketErrors <- err:
			case <-c.closed:
				return
			}
			return
		}

		if pt == nil {
			logf(logTypeHandshake, "%s socketReaderLoop: ReadRecord returned nil pt with no error", c.label())
			return
		}

		logf(logTypeHandshake, "%s socketReaderLoop: ✓✓✓ ReadRecord success, contentType=%v, epoch=%v, fragment_len=%d, sending to controller", c.label(), pt.contentType, pt.epoch, len(pt.fragment))
		if inImpl, ok := c.in.(*DefaultRecordLayer); ok {
			logf(logTypeHandshake, "%s socketReaderLoop: current in.cipher epoch=%s seq=%x", c.label(), inImpl.cipher.epoch.label(), inImpl.cipher.seq)
		}
		// Send record to controller (blocks until controller receives it)
		logf(logTypeHandshake, "%s socketReaderLoop: BLOCKING: sending record to socketRecords channel (len=%d, cap=%d)", c.label(), len(c.socketRecords), cap(c.socketRecords))
		select {
		case c.socketRecords <- pt:
			logf(logTypeHandshake, "%s socketReaderLoop: ✓✓✓✓✓ SUCCESS: sent record to controller, controller should process it now", c.label())
		case <-c.closed:
			logf(logTypeHandshake, "%s socketReaderLoop: connection closed while sending record", c.label())
			return
		}
	}
}

// controllerLoop is the main loop for the TLS Controller goroutine
func (c *Conn) controllerLoop() {
	defer close(c.controllerDone)

	// Start socket reader goroutine
	go c.socketReaderLoop()

	for {
		logf(logTypeHandshake, "%s controllerLoop: waiting on select (dataToSend=%d buffered, socketRecords=%d buffered)", c.label(), len(c.dataToSend), len(c.socketRecords))
		select {
		case data := <-c.dataToSend:
			// Encrypt and send data
			logf(logTypeHandshake, "%s controllerLoop: ✓✓✓ RECEIVED data from dataToSend, len=%d", c.label(), len(data))
			c.handleDataToSend(data)
			logf(logTypeHandshake, "%s controllerLoop: ✓✓✓ finished handling dataToSend, len=%d", c.label(), len(data))

		case pt := <-c.socketRecords:
			// Record received from socket
			logf(logTypeHandshake, "%s controllerLoop: ✓✓✓ RECEIVED record from socketReaderLoop, contentType=%v, epoch=%v, fragment_len=%d", c.label(), pt.contentType, pt.epoch, len(pt.fragment))
			c.handleSocketRecord(pt)
			logf(logTypeHandshake, "%s controllerLoop: ✓✓✓ finished processing record, contentType=%v", c.label(), pt.contentType)

		case err := <-c.socketErrors:
			// Socket error
			logf(logTypeHandshake, "%s controllerLoop: received socket error: %v", c.label(), err)
			// All errors are fatal for now
			// TODO: Handle DecryptError that might be due to KeyUpdate by processing KeyUpdate first
			select {
			case c.errors <- err:
			case <-c.closed:
			}
			return

		case cmd := <-c.commands:
			// Handle command
			logf(logTypeHandshake, "%s controllerLoop: received command, type=%v", c.label(), cmd.cmdType)
			c.handleCommand(cmd)
			logf(logTypeHandshake, "%s controllerLoop: finished handling command", c.label())

		case <-c.closed:
			// Application closed connection
			logf(logTypeHandshake, "%s controllerLoop: closed signal received, checking for pending commands", c.label())
			// Check if there's a pending close command before returning
			select {
			case cmd := <-c.commands:
				if cmd.cmdType == cmdClose {
					logf(logTypeHandshake, "%s controllerLoop: processing pending close command", c.label())
					c.handleCloseCommand(cmd)
				} else {
					// Other command - send error
					cmd.result <- commandResult{err: io.EOF}
				}
			default:
				// No pending commands
			}
			return
		}
	}
}

// handleSocketRecord processes a record received from the socket
func (c *Conn) handleSocketRecord(pt *TLSPlaintext) {
	logf(logTypeHandshake, "%s handleSocketRecord() called: contentType=%v, len=%d, epoch=%v", c.label(), pt.contentType, len(pt.fragment), pt.epoch)
	if inImpl, ok := c.in.(*DefaultRecordLayer); ok {
		logf(logTypeHandshake, "%s handleSocketRecord() current in.cipher epoch=%s seq=%x", c.label(), inImpl.cipher.epoch.label(), inImpl.cipher.seq)
	}
	switch pt.contentType {
	case RecordTypeHandshake:
		// Process handshake message (KeyUpdate, etc.)
		logf(logTypeHandshake, "%s handleSocketRecord() processing handshake record, fragment_len=%d", c.label(), len(pt.fragment))
		c.processHandshakeRecord(pt)
		logf(logTypeHandshake, "%s handleSocketRecord() finished processing handshake record", c.label())

	case RecordTypeApplicationData:
		// Decrypt and send to application
		logf(logTypeHandshake, "%s handleSocketRecord() ✓✓✓ processing application data, len=%d, epoch=%v", c.label(), len(pt.fragment), pt.epoch)
		if inImpl, ok := c.in.(*DefaultRecordLayer); ok {
			logf(logTypeHandshake, "%s handleSocketRecord() current in.cipher epoch=%s seq=%x (before decryptRecord)", c.label(), inImpl.cipher.epoch.label(), inImpl.cipher.seq)
		}
		decrypted := c.decryptRecord(pt)
		logf(logTypeHandshake, "%s handleSocketRecord() ✓✓✓ decrypted, len=%d, about to send to dataToReceive (channel len=%d, cap=%d)", c.label(), len(decrypted), len(c.dataToReceive), cap(c.dataToReceive))
		select {
		case c.dataToReceive <- decrypted:
			// Successfully queued for application
			logf(logTypeHandshake, "%s handleSocketRecord() ✓✓✓✓✓ SUCCESS: sent application data to dataToReceive channel, len=%d", c.label(), len(decrypted))
		case <-c.closed:
			// Connection closed, discard data
			logf(logTypeHandshake, "%s handleSocketRecord() connection closed, discarding data", c.label())
		default:
			// Channel is full - should not happen in normal operation with 64KB buffer
			// Send error to application
			logf(logTypeHandshake, "%s handleSocketRecord() ⚠⚠⚠ WARNING: dataToReceive channel full! len=%d, cap=%d", c.label(), len(c.dataToReceive), cap(c.dataToReceive))
			select {
			case c.errors <- errors.New("dataToReceive channel full"):
			case <-c.closed:
			}
		}

	case RecordTypeAlert:
		// Handle alert
		logf(logTypeHandshake, "%s Processing alert record", c.label())
		c.handleAlert(pt)
	}
}

// handleDataToSend encrypts and sends data to the socket
func (c *Conn) handleDataToSend(data []byte) {
	logf(logTypeHandshake, "%s handleDataToSend() START: called, len=%d", c.label(), len(data))
	if outImpl, ok := c.out.(*DefaultRecordLayer); ok {
		logf(logTypeHandshake, "%s handleDataToSend() current out.cipher epoch=%s seq=%x", c.label(), outImpl.cipher.epoch.label(), outImpl.cipher.seq)
	}
	// Lock the output channel for thread safety
	c.out.Lock()
	defer c.out.Unlock()

	// Send full-size fragments
	var start int
	for start = 0; len(data)-start >= maxFragmentLen; start += maxFragmentLen {
		logf(logTypeHandshake, "%s handleDataToSend() writing fragment [%d:%d], len=%d", c.label(), start, start+maxFragmentLen, maxFragmentLen)
		err := c.out.WriteRecord(&TLSPlaintext{
			contentType: RecordTypeApplicationData,
			fragment:    data[start : start+maxFragmentLen],
		})
		if err != nil {
			logf(logTypeHandshake, "%s handleDataToSend() ERROR writing fragment: %v", c.label(), err)
			select {
			case c.errors <- err:
			case <-c.closed:
			}
			return
		}
		logf(logTypeHandshake, "%s handleDataToSend() ✓ wrote fragment [%d:%d]", c.label(), start, start+maxFragmentLen)
	}

	// Send a final partial fragment if necessary
	if start < len(data) {
		logf(logTypeHandshake, "%s handleDataToSend() writing final fragment [%d:%d], len=%d", c.label(), start, len(data), len(data)-start)
		err := c.out.WriteRecord(&TLSPlaintext{
			contentType: RecordTypeApplicationData,
			fragment:    data[start:],
		})
		if err != nil {
			logf(logTypeHandshake, "%s handleDataToSend() ERROR writing final fragment: %v", c.label(), err)
			select {
			case c.errors <- err:
			case <-c.closed:
			}
			return
		}
		logf(logTypeHandshake, "%s handleDataToSend() ✓ wrote final fragment [%d:%d]", c.label(), start, len(data))
	}

	logf(logTypeHandshake, "%s handleDataToSend() COMPLETE: sent all %d bytes to socket", c.label(), len(data))
	return
}

// handleCommand processes a command from the application
func (c *Conn) handleCommand(cmd controllerCommand) {
	logf(logTypeHandshake, "%s handleCommand() called, cmdType=%v", c.label(), cmd.cmdType)
	switch cmd.cmdType {
	case cmdKeyUpdate:
		c.handleKeyUpdateCommand(cmd)
	case cmdExtendedKeyUpdate:
		c.handleExtendedKeyUpdateCommand(cmd)
	case cmdClose:
		c.handleCloseCommand(cmd)
	default:
		cmd.result <- commandResult{err: errors.New("unknown command")}
	}
	logf(logTypeHandshake, "%s handleCommand() returning", c.label())
}

// handleKeyUpdateCommand processes a KeyUpdate command
func (c *Conn) handleKeyUpdateCommand(cmd controllerCommand) {
	logf(logTypeHandshake, "%s handleKeyUpdateCommand() called, requestUpdate=%v", c.label(), cmd.requestUpdate)
	if !c.handshakeComplete {
		cmd.result <- commandResult{err: errors.New("cannot update keys until after handshake")}
		return
	}

	// Standard KeyUpdate is not allowed when EKU is negotiated (mutually exclusive)
	if c.state.Params.UsingExtendedKeyUpdate {
		logf(logTypeHandshake, "%s handleKeyUpdateCommand() ERROR: Standard KeyUpdate not allowed when EKU is negotiated", c.label())
		cmd.result <- commandResult{err: errors.New("standard KeyUpdate not allowed when Extended Key Update is negotiated")}
		return
	}

	request := KeyUpdateNotRequested
	if cmd.requestUpdate {
		request = KeyUpdateRequested
	}

	logf(logTypeHandshake, "%s handleKeyUpdateCommand() calling state.KeyUpdate()", c.label())
	// Create the key update and update state
	actions, alert := (&c.state).KeyUpdate(request)
	if alert != AlertNoAlert {
		c.sendAlert(alert)
		cmd.result <- commandResult{err: fmt.Errorf("alert while generating key update: %v", alert)}
		return
	}

	logf(logTypeHandshake, "%s handleKeyUpdateCommand() taking %d actions", c.label(), len(actions))
	if inImpl, ok := c.in.(*DefaultRecordLayer); ok {
		if outImpl, ok2 := c.out.(*DefaultRecordLayer); ok2 {
			logf(logTypeHandshake, "%s handleKeyUpdateCommand() BEFORE actions: in.epoch=%s in.seq=%x, out.epoch=%s out.seq=%x",
				c.label(), inImpl.cipher.epoch.label(), inImpl.cipher.seq, outImpl.cipher.epoch.label(), outImpl.cipher.seq)
		}
	}
	// Take actions (send key update and rekey)
	for i, action := range actions {
		logf(logTypeHandshake, "%s handleKeyUpdateCommand() taking action %d/%d: %T", c.label(), i+1, len(actions), action)
		actionAlert := c.takeAction(action)
		if actionAlert != AlertNoAlert {
			c.sendAlert(actionAlert)
			cmd.result <- commandResult{err: fmt.Errorf("alert during key update actions: %v", actionAlert)}
			return
		}
		if inImpl, ok := c.in.(*DefaultRecordLayer); ok {
			if outImpl, ok2 := c.out.(*DefaultRecordLayer); ok2 {
				logf(logTypeHandshake, "%s handleKeyUpdateCommand() after action %d: in.epoch=%s in.seq=%x, out.epoch=%s out.seq=%x",
					c.label(), i+1, inImpl.cipher.epoch.label(), inImpl.cipher.seq, outImpl.cipher.epoch.label(), outImpl.cipher.seq)
			}
		}
	}
	logf(logTypeHandshake, "%s handleKeyUpdateCommand() finished taking actions", c.label())
	if inImpl, ok := c.in.(*DefaultRecordLayer); ok {
		if outImpl, ok2 := c.out.(*DefaultRecordLayer); ok2 {
			logf(logTypeHandshake, "%s handleKeyUpdateCommand() AFTER actions: in.epoch=%s in.seq=%x, out.epoch=%s out.seq=%x",
				c.label(), inImpl.cipher.epoch.label(), inImpl.cipher.seq, outImpl.cipher.epoch.label(), outImpl.cipher.seq)
		}
	}

	// If requestUpdate=true, we need to wait for peer's KeyUpdate response
	if cmd.requestUpdate {
		logf(logTypeHandshake, "%s handleKeyUpdateCommand() setting up wait for peer response", c.label())
		// Create channel to wait for peer's KeyUpdate response
		// Note: No mutex needed - controller is single-threaded and API is synchronous
		if c.pendingKeyUpdateResponse != nil {
			// Already waiting for a KeyUpdate response - error
			logf(logTypeHandshake, "%s handleKeyUpdateCommand() ERROR: already waiting for KeyUpdate response", c.label())
			cmd.result <- commandResult{err: errors.New("KeyUpdate already in progress")}
			return
		}
		c.pendingKeyUpdateResponse = make(chan struct{})
		logf(logTypeHandshake, "%s handleKeyUpdateCommand() created pendingKeyUpdateResponse channel, KeyUpdate sent, waiting for peer response", c.label())

		// Spawn a goroutine to wait for the response so we don't block the controller loop
		// The controller loop must continue to process incoming socket records (including the KeyUpdate response)
		go func() {
			logf(logTypeHandshake, "%s handleKeyUpdateCommand() goroutine started, waiting for KeyUpdate response", c.label())
			// Wait for peer's KeyUpdate response
			// This will be signaled by processHandshakeRecord when it receives the KeyUpdate message
			select {
			case <-c.pendingKeyUpdateResponse:
				// Peer's KeyUpdate response received and processed
				logf(logTypeHandshake, "%s handleKeyUpdateCommand() goroutine: received KeyUpdate response signal!", c.label())
				c.pendingKeyUpdateResponse = nil
				cmd.result <- commandResult{err: nil}
			case err := <-c.errors:
				// Error occurred while waiting
				logf(logTypeHandshake, "%s handleKeyUpdateCommand() goroutine: error while waiting: %v", c.label(), err)
				c.pendingKeyUpdateResponse = nil
				cmd.result <- commandResult{err: err}
			case <-c.closed:
				// Connection closed
				logf(logTypeHandshake, "%s handleKeyUpdateCommand() goroutine: connection closed while waiting", c.label())
				c.pendingKeyUpdateResponse = nil
				cmd.result <- commandResult{err: io.EOF}
			}
		}()
		logf(logTypeHandshake, "%s handleKeyUpdateCommand() returning, controller can continue processing", c.label())
		return
	}

	cmd.result <- commandResult{err: nil}
}

// handleExtendedKeyUpdateCommand processes an Extended Key Update command
// This handles the 4-message EKU exchange: request -> response -> new_key_update (initiator) -> new_key_update (responder)
func (c *Conn) handleExtendedKeyUpdateCommand(cmd controllerCommand) {
	logf(logTypeHandshake, "%s handleExtendedKeyUpdateCommand() called", c.label())
	if !c.handshakeComplete {
		cmd.result <- commandResult{err: errors.New("cannot update keys until after handshake")}
		return
	}

	if !c.state.Params.UsingExtendedKeyUpdate {
		cmd.result <- commandResult{err: errors.New("Extended Key Update not negotiated")}
		return
	}

	if c.state.ekuInProgress {
		cmd.result <- commandResult{err: errors.New("Extended Key Update already in progress")}
		return
	}

	logf(logTypeHandshake, "%s handleExtendedKeyUpdateCommand() calling state.ExtendedKeyUpdateInitiate()", c.label())
	// Create the EKU request (Message 1) and update state
	actions, alert := (&c.state).ExtendedKeyUpdateInitiate()
	if alert != AlertNoAlert {
		c.sendAlert(alert)
		cmd.result <- commandResult{err: fmt.Errorf("alert while generating EKU request: %v", alert)}
		return
	}

	logf(logTypeHandshake, "%s handleExtendedKeyUpdateCommand() taking %d actions", c.label(), len(actions))
	// Take actions (send key_update_request)
	for i, action := range actions {
		logf(logTypeHandshake, "%s handleExtendedKeyUpdateCommand() taking action %d/%d: %T", c.label(), i+1, len(actions), action)
		actionAlert := c.takeAction(action)
		if actionAlert != AlertNoAlert {
			c.sendAlert(actionAlert)
			cmd.result <- commandResult{err: fmt.Errorf("alert during EKU actions: %v", actionAlert)}
			return
		}
	}

	logf(logTypeHandshake, "%s handleExtendedKeyUpdateCommand() setting up wait for EKU response (Message 2)", c.label())
	// Create channel to wait for peer's EKU response (Message 2)
	// Note: No mutex needed - controller is single-threaded and API is synchronous
	if c.pendingEKUResponse != nil {
		logf(logTypeHandshake, "%s handleExtendedKeyUpdateCommand() ERROR: already waiting for EKU response", c.label())
		cmd.result <- commandResult{err: errors.New("Extended Key Update already in progress")}
		return
	}
	c.pendingEKUResponse = make(chan struct{})
	logf(logTypeHandshake, "%s handleExtendedKeyUpdateCommand() created pendingEKUResponse channel, EKU request sent, waiting for response", c.label())

	// Spawn a goroutine to wait for the 4-message exchange to complete
	// The controller loop must continue to process incoming socket records
	go func() {
		logf(logTypeHandshake, "%s handleExtendedKeyUpdateCommand() goroutine started, waiting for EKU response (Message 2)", c.label())
		// Wait for peer's EKU response (Message 2)
		select {
		case <-c.pendingEKUResponse:
			// Message 2 received and processed (state machine handled it)
			// Now wait for Message 4 (responder's new_key_update)
			logf(logTypeHandshake, "%s handleExtendedKeyUpdateCommand() goroutine: received EKU response (Message 2) signal, waiting for new_key_update (Message 4)", c.label())
			// Recreate channel for Message 4
			c.pendingEKUResponse = make(chan struct{})
			select {
			case <-c.pendingEKUResponse:
				// Message 4 received and processed
				logf(logTypeHandshake, "%s handleExtendedKeyUpdateCommand() goroutine: received new_key_update (Message 4) signal, EKU complete!", c.label())
				c.pendingEKUResponse = nil
				cmd.result <- commandResult{err: nil}
			case err := <-c.errors:
				logf(logTypeHandshake, "%s handleExtendedKeyUpdateCommand() goroutine: error while waiting for Message 4: %v", c.label(), err)
				c.pendingEKUResponse = nil
				cmd.result <- commandResult{err: err}
			case <-c.closed:
				logf(logTypeHandshake, "%s handleExtendedKeyUpdateCommand() goroutine: connection closed while waiting for Message 4", c.label())
				c.pendingEKUResponse = nil
				cmd.result <- commandResult{err: io.EOF}
			}
		case err := <-c.errors:
			logf(logTypeHandshake, "%s handleExtendedKeyUpdateCommand() goroutine: error while waiting for Message 2: %v", c.label(), err)
			c.pendingEKUResponse = nil
			cmd.result <- commandResult{err: err}
		case <-c.closed:
			logf(logTypeHandshake, "%s handleExtendedKeyUpdateCommand() goroutine: connection closed while waiting for Message 2", c.label())
			c.pendingEKUResponse = nil
			cmd.result <- commandResult{err: io.EOF}
		}
	}()
	logf(logTypeHandshake, "%s handleExtendedKeyUpdateCommand() returning, controller can continue processing", c.label())
}

// handleCloseCommand processes a Close command
func (c *Conn) handleCloseCommand(cmd controllerCommand) {
	// Close the closed channel to signal shutdown
	select {
	case <-c.closed:
		// Already closed
	default:
		close(c.closed)
	}

	// Send close_notify alert (lock output for thread safety)
	c.out.Lock()
	c.sendAlert(AlertCloseNotify)
	c.out.Unlock()

	// Close socket
	c.conn.Close()
	// Signal completion
	cmd.result <- commandResult{err: nil}
}

// processHandshakeRecord processes a handshake record
func (c *Conn) processHandshakeRecord(pt *TLSPlaintext) {
	// Parse handshake message from record fragment
	// We do not support fragmentation of post-handshake handshake messages
	start := 0
	headerLen := handshakeHeaderLenTLS
	if c.config.UseDTLS {
		headerLen = handshakeHeaderLenDTLS
	}

	for start < len(pt.fragment) {
		if len(pt.fragment[start:]) < headerLen {
			select {
			case c.errors <- fmt.Errorf("post-handshake handshake message too short for header"):
			case <-c.closed:
			}
			return
		}

		hm := &HandshakeMessage{}
		hm.msgType = HandshakeType(pt.fragment[start])
		hmLen := (int(pt.fragment[start+1]) << 16) + (int(pt.fragment[start+2]) << 8) + int(pt.fragment[start+3])

		if len(pt.fragment[start+headerLen:]) < hmLen {
			select {
			case c.errors <- fmt.Errorf("post-handshake handshake message too short for body"):
			case <-c.closed:
			}
			return
		}
		hm.body = pt.fragment[start+headerLen : start+headerLen+hmLen]

		// Reject standard KeyUpdate if EKU is negotiated (mutually exclusive)
		if hm.msgType == HandshakeTypeKeyUpdate && c.state.Params.UsingExtendedKeyUpdate {
			logf(logTypeHandshake, "%s processHandshakeRecord() ERROR: Received standard KeyUpdate but EKU is negotiated", c.label())
			alert := AlertUnexpectedMessage
			c.sendAlert(alert)
			select {
			case c.errors <- fmt.Errorf("unexpected standard KeyUpdate when Extended Key Update is negotiated: %v", alert):
			case <-c.closed:
			}
			return
		}

		// Check if this is a KeyUpdate or ExtendedKeyUpdate message we're waiting for
		isKeyUpdateResponse := false
		isEKUResponse := false
		logf(logTypeHandshake, "%s processHandshakeRecord() calling ToBody() for msgType=%v", c.label(), hm.msgType)
		bodyGeneric, err := hm.ToBody()
		if err != nil {
			logf(logTypeHandshake, "%s processHandshakeRecord() ERROR: ToBody() failed: %v", c.label(), err)
			// Continue to ProcessMessage which will handle the error
		} else {
			logf(logTypeHandshake, "%s processHandshakeRecord() ToBody() succeeded, body type=%T", c.label(), bodyGeneric)
			if keyUpdateBody, ok := bodyGeneric.(*KeyUpdateBody); ok {
				// This is a KeyUpdate message
				logf(logTypeHandshake, "%s processHandshakeRecord() received KeyUpdate message, requestUpdate=%v, pendingKeyUpdateResponse=%v", 
					c.label(), keyUpdateBody.KeyUpdateRequest, c.pendingKeyUpdateResponse != nil)
				// If we're waiting for a response, this is it (peer responds to our requestUpdate=true)
				// Note: No mutex needed - controller is single-threaded
				if c.pendingKeyUpdateResponse != nil {
					isKeyUpdateResponse = true
					logf(logTypeHandshake, "%s processHandshakeRecord() this is the KeyUpdate response we're waiting for!", c.label())
				}
			} else if ekuBody, ok := bodyGeneric.(*ExtendedKeyUpdateBody); ok {
				// This is an ExtendedKeyUpdate message
				logf(logTypeHandshake, "%s processHandshakeRecord() RECEIVED ExtendedKeyUpdate message: type=%v, pendingEKUResponse=%v, ekuInProgress=%v, ekuIsInitiator=%v",
					c.label(), ekuBody.EKUType, c.pendingEKUResponse != nil, c.state.ekuInProgress, c.state.ekuIsInitiator)
				// If we're waiting for EKU response and we're the initiator:
				// - Message 2 (Response): Signal after processing
				// - Message 4 (NewKeyUpdate from responder): Signal after processing
				if c.pendingEKUResponse != nil {
					logf(logTypeHandshake, "%s processHandshakeRecord() checking if this EKU message matches what we're waiting for: type=%v, ekuInProgress=%v, ekuIsInitiator=%v",
						c.label(), ekuBody.EKUType, c.state.ekuInProgress, c.state.ekuIsInitiator)
					if ekuBody.EKUType == ExtendedKeyUpdateTypeResponse && c.state.ekuInProgress && c.state.ekuIsInitiator {
						// Message 2: Response to our request
						isEKUResponse = true
						logf(logTypeHandshake, "%s processHandshakeRecord() ✓ MATCH: This is Message 2 (Response) we're waiting for!", c.label())
					} else if ekuBody.EKUType == ExtendedKeyUpdateTypeNewKeyUpdate && c.state.ekuInProgress && c.state.ekuIsInitiator {
						// Message 4: Responder's new_key_update
						isEKUResponse = true
						logf(logTypeHandshake, "%s processHandshakeRecord() ✓ MATCH: This is Message 4 (NewKeyUpdate) we're waiting for!", c.label())
					} else {
						logf(logTypeHandshake, "%s processHandshakeRecord() ✗ NO MATCH: EKU message conditions not met: type=%v, pendingEKUResponse=%v, ekuInProgress=%v, ekuIsInitiator=%v", 
							c.label(), ekuBody.EKUType, c.pendingEKUResponse != nil, c.state.ekuInProgress, c.state.ekuIsInitiator)
					}
				} else {
					logf(logTypeHandshake, "%s processHandshakeRecord() received EKU message but pendingEKUResponse is nil (not waiting for response)", c.label())
				}
			}
		}

		// Process message using state machine
		logf(logTypeHandshake, "%s processHandshakeRecord() calling ProcessMessage() for msgType=%v", c.label(), hm.msgType)
		state, actions, alert := (&c.state).ProcessMessage(hm)
		if alert != AlertNoAlert {
			logf(logTypeHandshake, "%s processHandshakeRecord() ERROR in state transition: %v", c.label(), alert)
			c.sendAlert(alert)
			select {
			case c.errors <- alert:
			case <-c.closed:
			}
			return
		}
		logf(logTypeHandshake, "%s processHandshakeRecord() ProcessMessage() succeeded, actions count=%d", c.label(), len(actions))

		// Take actions (rekey, send response, etc.)
		for i, action := range actions {
			logf(logTypeHandshake, "%s processHandshakeRecord() executing action[%d]=%T", c.label(), i, action)
			actionAlert := c.takeAction(action)
			if actionAlert != AlertNoAlert {
				logf(logTypeHandshake, "%s processHandshakeRecord() ERROR during handshake action[%d]: %v", c.label(), i, actionAlert)
				c.sendAlert(actionAlert)
				select {
				case c.errors <- actionAlert:
				case <-c.closed:
				}
				return
			}
			logf(logTypeHandshake, "%s processHandshakeRecord() action[%d]=%T completed successfully", c.label(), i, action)
		}

		// Update state
		var connected bool
		c.state, connected = state.(stateConnected)
		if !connected {
			logf(logTypeHandshake, "Disconnected after state transition: state type=%T, alert=%v", state, alert)
			// Log more details about what went wrong
			if state == nil {
				logf(logTypeHandshake, "State is nil - ProcessMessage returned nil state")
			} else {
				logf(logTypeHandshake, "State is not stateConnected: %T", state)
			}
			select {
			case c.errors <- fmt.Errorf("disconnected after state transition: state type=%T", state):
			case <-c.closed:
			}
			return
		}

		// If this was a KeyUpdate response we were waiting for, signal completion
		if isKeyUpdateResponse {
			// Note: No mutex needed - controller is single-threaded
			if c.pendingKeyUpdateResponse != nil {
				logf(logTypeHandshake, "%s processHandshakeRecord() signaling KeyUpdate response completion", c.label())
				close(c.pendingKeyUpdateResponse)
				c.pendingKeyUpdateResponse = nil
				logf(logTypeHandshake, "%s processHandshakeRecord() KeyUpdate response signal sent", c.label())
			} else {
				logf(logTypeHandshake, "%s processHandshakeRecord() WARNING: isKeyUpdateResponse=true but pendingKeyUpdateResponse is nil!", c.label())
			}
		}

		// If this was an EKU message we were waiting for, signal completion
		if isEKUResponse {
			// Note: No mutex needed - controller is single-threaded
			if c.pendingEKUResponse != nil {
				logf(logTypeHandshake, "%s processHandshakeRecord() ✓ SIGNALING EKU response completion (closing channel)", c.label())
				close(c.pendingEKUResponse)
				// Don't set to nil here - the goroutine will recreate it for Message 4 or set to nil when complete
				logf(logTypeHandshake, "%s processHandshakeRecord() ✓ EKU response signal sent (channel closed)", c.label())
			} else {
				logf(logTypeHandshake, "%s processHandshakeRecord() ⚠ WARNING: isEKUResponse=true but pendingEKUResponse is nil!", c.label())
			}
		}

		start += headerLen + hmLen
	}
}

// decryptRecord decrypts an application data record
// Note: RecordLayer.ReadRecord() already decrypts, so pt.fragment is already decrypted
func (c *Conn) decryptRecord(pt *TLSPlaintext) []byte {
	logf(logTypeHandshake, "%s decryptRecord() START: contentType=%v, len=%d, epoch=%v", c.label(), pt.contentType, len(pt.fragment), pt.epoch)
	result := pt.fragment
	logf(logTypeHandshake, "%s decryptRecord() RETURN: len=%d", c.label(), len(result))
	return result
}

// handleAlert processes an alert record
func (c *Conn) handleAlert(pt *TLSPlaintext) {
	if len(pt.fragment) != 2 {
		c.sendAlert(AlertUnexpectedMessage)
		select {
		case c.errors <- errors.New("alert record has invalid length"):
		case <-c.closed:
		}
		return
	}

	alertLevel := pt.fragment[0]
	alertType := Alert(pt.fragment[1])

	if alertType == AlertCloseNotify {
		// Peer closed connection gracefully
		select {
		case <-c.closed:
			// Already closed
		default:
			close(c.closed)
		}
		return
	}

	switch alertLevel {
	case AlertLevelWarning:
		// Drop warning alerts on the floor
		logf(logTypeIO, "Received warning alert: %v", alertType)
	case AlertLevelError:
		// Fatal error - close connection
		logf(logTypeIO, "Received error alert: %v", alertType)
		select {
		case c.errors <- alertType:
		case <-c.closed:
		}
		select {
		case <-c.closed:
			// Already closed
		default:
			close(c.closed)
		}
	default:
		c.sendAlert(AlertUnexpectedMessage)
		select {
		case c.errors <- errors.New("invalid alert level"):
		case <-c.closed:
		}
	}
}

func (c *Conn) ComputeExporter(label string, context []byte, keyLength int) ([]byte, error) {
	_, connected := c.hState.(stateConnected)
	if !connected {
		return nil, fmt.Errorf("Cannot compute exporter when state is not connected")
	}

	if c.state.exporterSecret == nil {
		return nil, fmt.Errorf("Internal error: no exporter secret")
	}

	h0 := c.state.cryptoParams.Hash.New().Sum(nil)
	tmpSecret := deriveSecret(c.state.cryptoParams, c.state.exporterSecret, label, h0)

	hc := c.state.cryptoParams.Hash.New().Sum(context)
	return HkdfExpandLabel(c.state.cryptoParams.Hash, tmpSecret, "exporter", hc, keyLength), nil
}

func (c *Conn) ConnectionState() ConnectionState {
	state := ConnectionState{
		HandshakeState: c.GetHsState(),
	}

	if c.handshakeComplete {
		state.CipherSuite = cipherSuiteMap[c.state.Params.CipherSuite]
		state.NextProto = c.state.Params.NextProto
		state.VerifiedChains = c.state.verifiedChains
		state.PeerCertificates = c.state.peerCertificates
		state.UsingPSK = c.state.Params.UsingPSK
		state.UsingEarlyData = c.state.Params.UsingEarlyData
	}

	return state
}

func (c *Conn) Writable() bool {
	// If we're connected, we're writable.
	if _, connected := c.hState.(stateConnected); connected {
		return true
	}

	// If we're a client in 0-RTT, then we're writable.
	if c.isClient && c.out.Epoch() == EpochEarlyData {
		return true
	}

	return false
}

func (c *Conn) label() string {
	if c.isClient {
		return "client"
	}
	return "server"
}
