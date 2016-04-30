package mint

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

type Certificate struct {
	Chain      []*x509.Certificate
	PrivateKey crypto.Signer
}

type PreSharedKey struct {
	Identity []byte
	Key      []byte
}

// Config is the struct used to pass configuration settings to a TLS client or
// server instance.  The settings for client and server are pretty different,
// but we just throw them all in here.
type Config struct {
	// Only in crypto/tls:
	// SessionTicketsDisabled   bool               // TODO(#6) -> Both
	// SessionTicketKey         [32]byte           // TODO(#6) -> Server
	// Rand                     io.Reader          // TODO(#23) -> Both
	// PreferServerCipherSuites bool               // TODO(#22) -> Server
	// NextProtos               []string           // TODO(#21) -> Both
	// ClientAuth               ClientAuthType     // TODO(#20)
	// NameToCertificate        map[string]*Certificate // Unused (simplicity)
	// GetCertificate           func(clientHello *ClientHelloInfo) (*Certificate, error) // Unused (simplicity)
	// ClientCAs                *x509.CertPool     // Unused (no PKI)
	// RootCAs                  *x509.CertPool     // Unused (no PKI)
	// InsecureSkipVerify       bool               // Unused (no PKI)
	// MinVersion               uint16             // Unused (only 1.3)
	// MaxVersion               uint16             // Unused (only 1.3)
	// Time                     func() time.Time   // Unused (no time in 1.3)
	// ClientSessionCache       ClientSessionCache // Unused (PSKs only in 1.3)

	// Only here:
	// AuthCertificate          func(chain []*x509.Certificate) error
	// ClientPSKs               map[string]PreSharedKey
	// ServerPSKs               []PreSharedKey

	// ---------------------------------------

	// Client fields
	ServerName      string
	AuthCertificate func(chain []*x509.Certificate) error // TODO(#20) -> Both
	ClientPSKs      map[string]PreSharedKey

	// Server fields
	Certificates       []*Certificate
	ServerPSKs         []PreSharedKey
	SendSessionTickets bool
	TicketLifetime     uint32
	TicketLen          int

	// Shared fields
	CipherSuites        []cipherSuite
	Groups              []namedGroup
	SignatureAlgorithms []signatureAndHashAlgorithm

	// Ticket pinning (shared)
	PinningEnabled        bool
	PinningDB             string
	PinningTicketLifetime int

	// Hidden fields (used for caching in convenient form)
	enabledSuite map[cipherSuite]bool
	enabledGroup map[namedGroup]bool
	certsByName  map[string]*Certificate

	// The same config object can be shared among different connections, so it
	// needs its own mutex
	mutex sync.RWMutex
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
	if len(c.SignatureAlgorithms) == 0 {
		c.SignatureAlgorithms = defaultSignatureAlgorithms
	}
	if c.TicketLen == 0 {
		c.TicketLen = defaultTicketLen
	}
	if c.ClientPSKs == nil {
		c.ClientPSKs = map[string]PreSharedKey{}
	}

	if c.PinningTicketLifetime == 0 {
		c.PinningTicketLifetime = int(defaultPinningTicketLifetime)
	}

	// If there is no certificate, generate one
	if !isClient && len(c.Certificates) == 0 {
		priv, err := newSigningKey(signatureAlgorithmRSA)
		if err != nil {
			return err
		}

		cert, err := newSelfSigned(c.ServerName,
			signatureAndHashAlgorithm{
				hashAlgorithmSHA256,
				signatureAlgorithmRSA,
			},
			priv)
		if err != nil {
			return err
		}

		c.Certificates = []*Certificate{
			&Certificate{
				Chain:      []*x509.Certificate{cert},
				PrivateKey: priv,
			},
		}
	}

	// Build caches
	c.enabledSuite = map[cipherSuite]bool{}
	c.enabledGroup = map[namedGroup]bool{}
	c.certsByName = map[string]*Certificate{}

	for _, group := range c.Groups {
		c.enabledGroup[group] = true
	}
	for _, cert := range c.Certificates {
		if len(cert.Chain) == 0 {
			continue
		}
		for _, name := range cert.Chain[0].DNSNames {
			c.certsByName[name] = cert
		}
		for _, suite := range c.CipherSuites {
			if cipherSuiteMap[suite].sig == signatureAlgorithmRSA {
				if cert.Chain[0].PublicKeyAlgorithm == x509.RSA {
					c.enabledSuite[suite] = true
				}
			} else if cipherSuiteMap[suite].sig == signatureAlgorithmECDSA {
				if cert.Chain[0].PublicKeyAlgorithm == x509.ECDSA {
					c.enabledSuite[suite] = true
				}
			} else {
				// PSK modes work for every handshake signature type
				c.enabledSuite[suite] = true
			}
		}
	}
	logf(logTypeCrypto, "Enabled suites [%v]", c.enabledSuite)

	return nil
}

func (c Config) validForServer() bool {
	return len(c.Certificates) > 0 &&
		len(c.Certificates[0].Chain) > 0 &&
		c.Certificates[0].PrivateKey != nil
}

func (c Config) validForClient() bool {
	return len(c.ServerName) > 0
}

var (
	defaultSupportedCipherSuites = []cipherSuite{
		TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		TLS_PSK_WITH_AES_128_GCM_SHA256,
		TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256,
	}

	defaultSupportedGroups = []namedGroup{
		namedGroupP256,
		namedGroupP384,
		namedGroupP521,
	}

	defaultSignatureAlgorithms = []signatureAndHashAlgorithm{
		signatureAndHashAlgorithm{hashAlgorithmSHA256, signatureAlgorithmRSA},
		signatureAndHashAlgorithm{hashAlgorithmSHA256, signatureAlgorithmECDSA},
		signatureAndHashAlgorithm{hashAlgorithmSHA384, signatureAlgorithmRSA},
		signatureAndHashAlgorithm{hashAlgorithmSHA384, signatureAlgorithmECDSA},
		signatureAndHashAlgorithm{hashAlgorithmSHA512, signatureAlgorithmRSA},
		signatureAndHashAlgorithm{hashAlgorithmSHA512, signatureAlgorithmECDSA},
	}

	defaultTicketLen = 16

	defaultPinningTicketLifetime = 30 * 24 * time.Hour // 1 month (default not specified in draft)
)

// Conn implements the net.Conn interface, as with "crypto/tls"
// * Read, Write, and Close are provided locally
// * LocalAddr, RemoteAddr, and Set*Deadline are forwarded to the inner Conn
type Conn struct {
	config   *Config
	conn     net.Conn
	isClient bool

	earlyData        []byte
	earlyCipherSuite cipherSuite

	handshakeMutex    sync.Mutex
	handshakeErr      error
	handshakeComplete bool

	readBuffer        []byte
	in, out           *recordLayer
	inMutex, outMutex sync.Mutex
	context           cryptoContext

	// pinning
	pinningSecret, newPinningSecret []byte // client and server
}

func newConn(conn net.Conn, config *Config, isClient bool) *Conn {
	c := &Conn{conn: conn, config: config, isClient: isClient}
	c.in = newRecordLayer(c.conn)
	c.out = newRecordLayer(c.conn)
	return c
}

func (c *Conn) extendBuffer(n int) error {
	// XXX: crypto/tls bounds the number of empty records that can be read.  Should we?
	// if there's no more data left, stop reading
	if len(c.in.nextData) == 0 && len(c.readBuffer) > 0 {
		return nil
	}

	for len(c.readBuffer) <= n {
		pt, err := c.in.ReadRecord()

		if pt == nil {
			return err
		}

		switch pt.contentType {
		case recordTypeHandshake:
			// We do not support fragmentation of post-handshake handshake messages
			// TODO: Factor this more elegantly; coalesce with handshakeLayer.ReadMessage()
			start := 0
			for start < len(pt.fragment) {
				if len(pt.fragment[start:]) < handshakeHeaderLen {
					return fmt.Errorf("Post-handshake handshake message too short for header")
				}

				hm := &handshakeMessage{}
				hm.msgType = handshakeType(pt.fragment[start])
				hmLen := (int(pt.fragment[start+1]) << 16) + (int(pt.fragment[start+2]) << 8) + int(pt.fragment[start+3])

				if len(pt.fragment[start+handshakeHeaderLen:]) < hmLen {
					return fmt.Errorf("Post-handshake handshake message too short for body")
				}
				hm.body = pt.fragment[start+handshakeHeaderLen : start+handshakeHeaderLen+hmLen]

				switch hm.msgType {
				case handshakeTypeNewSessionTicket:
					var tkt newSessionTicketBody
					read, err := tkt.Unmarshal(hm.body)
					if err != nil {
						return err
					}
					if read != len(hm.body) {
						return fmt.Errorf("Malformed handshake message [%v] != [%v]", read, len(hm.body))
					}

					logf(logTypeHandshake, "Storing new session ticket with identity [%v]", tkt.ticket)
					psk := PreSharedKey{
						Identity: tkt.ticket,
						Key:      c.context.resumptionSecret,
					}
					c.config.ClientPSKs[c.config.ServerName] = psk

				case handshakeTypeKeyUpdate:
					// TODO: Support KeyUpdate
					fallthrough
				default:
					c.sendAlert(alertUnexpectedMessage)
					return fmt.Errorf("Unsupported post-handshake handshake message [%v]", hm.msgType)
				}

				start += handshakeHeaderLen + hmLen
			}
		case recordTypeAlert:
			logf(logTypeIO, "extended buffer (for alert): [%d] %x", len(c.readBuffer), c.readBuffer)
			if len(pt.fragment) != 2 {
				c.sendAlert(alertUnexpectedMessage)
				return io.EOF
			}
			if alert(pt.fragment[1]) == alertCloseNotify {
				return io.EOF
			}

			switch pt.fragment[0] {
			case alertLevelWarning:
				// drop on the floor
			case alertLevelError:
				return alert(pt.fragment[1])
			default:
				c.sendAlert(alertUnexpectedMessage)
				return io.EOF
			}

		case recordTypeApplicationData:
			c.readBuffer = append(c.readBuffer, pt.fragment...)
			logf(logTypeIO, "extended buffer: [%d] %x", len(c.readBuffer), c.readBuffer)
		}

		if err != nil {
			return err
		}

		// if there's no more data left, stop reading
		if len(c.in.nextData) == 0 {
			return nil
		}

		// if we're over the limit and the next record is not an alert, exit
		if len(c.readBuffer) == n && recordType(c.in.nextData[0]) != recordTypeAlert {
			return nil
		}
	}
	return nil
}

// Read application data until the buffer is full.  Handshake and alert records
// are consumed by the Conn object directly.
func (c *Conn) Read(buffer []byte) (int, error) {
	if err := c.Handshake(); err != nil {
		return 0, err
	}

	// Lock the input channel
	c.in.Lock()
	defer c.in.Unlock()

	n := len(buffer)
	err := c.extendBuffer(n)
	var read int
	if len(c.readBuffer) < n {
		buffer = buffer[:len(c.readBuffer)]
		copy(buffer, c.readBuffer)
		read = len(c.readBuffer)
		c.readBuffer = c.readBuffer[:0]
	} else {
		logf(logTypeIO, "read buffer larger than than input buffer")
		copy(buffer[:n], c.readBuffer[:n])
		c.readBuffer = c.readBuffer[n:]
		read = n
	}

	return read, err
}

// Write application data
func (c *Conn) Write(buffer []byte) (int, error) {
	// Lock the output channel
	c.out.Lock()
	defer c.out.Unlock()

	// Send full-size fragments
	var start int
	sent := 0
	for start = 0; len(buffer)-start >= maxFragmentLen; start += maxFragmentLen {
		err := c.out.WriteRecord(&tlsPlaintext{
			contentType: recordTypeApplicationData,
			fragment:    buffer[start : start+maxFragmentLen],
		})

		if err != nil {
			return sent, err
		}
		sent += maxFragmentLen
	}

	// Send a final partial fragment if necessary
	if start < len(buffer) {
		err := c.out.WriteRecord(&tlsPlaintext{
			contentType: recordTypeApplicationData,
			fragment:    buffer[start:],
		})

		if err != nil {
			return sent, err
		}
		sent += len(buffer[start:])
	}
	return sent, nil
}

// sendAlert sends a TLS alert message.
// c.out.Mutex <= L.
func (c *Conn) sendAlert(err alert) error {
	c.handshakeMutex.Lock()
	defer c.handshakeMutex.Unlock()

	tmp := make([]byte, 2)
	switch err {
	case alertNoRenegotiation, alertCloseNotify:
		tmp[0] = alertLevelWarning
	default:
		tmp[0] = alertLevelError
	}
	tmp[1] = byte(err)
	c.out.WriteRecord(&tlsPlaintext{
		contentType: recordTypeAlert,
		fragment:    tmp},
	)

	// close_notify and end_of_early_data are not actually errors
	if err != alertCloseNotify && err != alertEndOfEarlyData {
		return &net.OpError{Op: "local error", Err: err}
	}
	return nil
}

// Close closes the connection.
func (c *Conn) Close() error {
	// XXX crypto/tls has an interlock with Write here.  Do we need that?

	c.sendAlert(alertCloseNotify)
	return c.conn.Close()
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

// Handshake causes a TLS handshake on the connection.  The `isClient` member
// determines whether a client or server handshake is performed.  If a
// handshake has already been performed, then its result will be returned.
func (c *Conn) Handshake() error {
	// TODO Lock handshakeMutex
	if err := c.handshakeErr; err != nil {
		return err
	}
	if c.handshakeComplete {
		return nil
	}

	if err := c.config.Init(c.isClient); err != nil {
		return err
	}

	if c.isClient {
		c.handshakeErr = c.clientHandshake()
	} else {
		c.handshakeErr = c.serverHandshake()
	}
	c.handshakeComplete = (c.handshakeErr == nil)

	if c.handshakeErr != nil {
		logf(logTypeHandshake, "Handshake failed: %v", c.handshakeErr)
		c.sendAlert(alertHandshakeFailure)
		c.conn.Close()
	}

	return c.handshakeErr
}

func (c *Conn) clientHandshake() error {
	logf(logTypeHandshake, "Starting clientHandshake")

	hIn := newHandshakeLayer(c.in)
	hOut := newHandshakeLayer(c.out)

	// Construct some extensions
	logf(logTypeHandshake, "Constructing ClientHello")
	privateKeys := map[namedGroup][]byte{}
	ks := keyShareExtension{
		roleIsServer: false,
		shares:       make([]keyShare, len(c.config.Groups)),
	}
	for i, group := range c.config.Groups {
		pub, priv, err := newKeyShare(group)
		if err != nil {
			return err
		}

		ks.shares[i].group = group
		ks.shares[i].keyExchange = pub
		privateKeys[group] = priv
	}
	sni := serverNameExtension(c.config.ServerName)
	sg := supportedGroupsExtension{groups: c.config.Groups}
	sa := signatureAlgorithmsExtension{algorithms: c.config.SignatureAlgorithms}
	dv := draftVersionExtension{version: draftVersionImplemented}

	var psk *preSharedKeyExtension
	if key, ok := c.config.ClientPSKs[c.config.ServerName]; ok {
		logf(logTypeHandshake, "Sending PSK")
		psk = &preSharedKeyExtension{
			roleIsServer: false,
			identities:   [][]byte{key.Identity},
		}
	} else {
		logf(logTypeHandshake, "No PSK found for [%v] in %+v", c.config.ServerName, c.config.ClientPSKs)
	}

	var pt *pinningTicketExtension
	var sendPinning bool // sent extension
	var sendPinningTicket bool // sent a ticket for that server
	var origin string

	if c.config.PinningEnabled && (psk == nil) {
		sendPinning = true
		origin = c.config.ServerName // TODO: add scheme (protocol) and port, RFC 6454 (or change the draft)
		opaque, secret, _, found := ps.readTicket(origin)
		if !found {
			pt = &pinningTicketExtension{roleIsServer: false} // send empty extension
			logf(logTypeTicketPinning, "Client: will send an empty PTE")
		} else {
			sendPinningTicket = true
			c.pinningSecret = secret
			pt = &pinningTicketExtension{
				roleIsServer:  false,
				pinningTicket: opaque,
			}
			logf(logTypeTicketPinning, "Client: found ticket for %v", origin)
		}
	} else {
		logf(logTypeTicketPinning, "Client: will not send PTE")
	}

	var ed *earlyDataExtension
	if c.earlyData != nil {
		if psk == nil {
			return fmt.Errorf("tls.client: Can't send early data without a PSK")
		}

		ed = &earlyDataExtension{
			cipherSuite: c.earlyCipherSuite,
		}
	}

	// Construct and write ClientHello
	ch := &clientHelloBody{
		cipherSuites: c.config.CipherSuites,
	}
	_, err := prng.Read(ch.random[:])
	if err != nil {
		return err
	}
	for _, ext := range []extensionBody{&sni, &ks, &sg, &sa, &dv} {
		err := ch.extensions.Add(ext)
		if err != nil {
			return err
		}
	}
	if psk != nil {
		err := ch.extensions.Add(psk)
		if err != nil {
			return err
		}
	}
	if ed != nil {
		err := ch.extensions.Add(ed)
		if err != nil {
			return err
		}
	}

	if pt != nil {
		err := ch.extensions.Add(pt)
		logf(logTypeTicketPinning, "Client sending PTE")
		if err != nil {
			return err
		}
	}

	chm, err := hOut.WriteMessageBody(ch)
	if err != nil {
		return err
	}
	logf(logTypeHandshake, "Sent ClientHello")

	// Send early data
	if ed != nil {
		logf(logTypeHandshake, "[client] Processing early data...")
		// We will only get here if we sent exactly one PSK, and this is it
		pskSecret := c.config.ClientPSKs[c.config.ServerName].Key
		ctx := cryptoContext{}
		ctx.Init(c.earlyCipherSuite)
		ctx.ComputeEarlySecrets(pskSecret, chm)

		// Rekey output to early handshake keys
		logf(logTypeHandshake, "[client] Rekey -> handshake...")
		err = c.out.Rekey(ctx.suite, ctx.earlyHandshakeKeys.clientWriteKey, ctx.earlyHandshakeKeys.clientWriteIV)
		if err != nil {
			return err
		}

		// Send early finished message
		logf(logTypeHandshake, "[client] Sending Finished...")
		_, err = hOut.WriteMessageBody(ctx.earlyFinished)
		if err != nil {
			return err
		}

		// Rekey output to early data keys
		logf(logTypeHandshake, "[client] Rekey -> application...")
		err = c.out.Rekey(ctx.suite, ctx.earlyApplicationKeys.clientWriteKey, ctx.earlyApplicationKeys.clientWriteIV)
		if err != nil {
			return err
		}

		// Send early application data
		logf(logTypeHandshake, "[client] Sending data...")
		_, err = c.Write(c.earlyData)
		if err != nil {
			return err
		}

		// Send end_of_earlyData
		logf(logTypeHandshake, "[client] Sending end_of_early_data...")
		err = c.sendAlert(alertEndOfEarlyData)
		if err != nil {
			return err
		}
	}

	// Read ServerHello
	sh := new(serverHelloBody)
	shm, err := hIn.ReadMessageBody(sh)
	if err != nil {
		logf(logTypeHandshake, "Error reading ServerHello")
		return err
	}
	logf(logTypeHandshake, "Received ServerHello")

	// Do PSK or key agreement depending on the ciphersuite
	serverPSK := preSharedKeyExtension{roleIsServer: true}
	foundPSK := sh.extensions.Find(&serverPSK)
	serverKeyShare := keyShareExtension{roleIsServer: true}
	foundKeyShare := sh.extensions.Find(&serverKeyShare)

	var pskSecret, dhSecret []byte
	if foundPSK && psk.HasIdentity(serverPSK.identities[0]) {
		pskSecret = c.config.ClientPSKs[c.config.ServerName].Key
	}
	if foundKeyShare {
		sks := serverKeyShare.shares[0]
		priv, ok := privateKeys[sks.group]
		if ok {
			// XXX: Ignore error; ctx.Init() will error on dhSecret being nil
			dhSecret, _ = keyAgreement(sks.group, sks.keyExchange, priv)
		}
	}

	// Init crypto context
	ctx := cryptoContext{}
	err = ctx.Init(sh.cipherSuite)
	if err != nil {
		return err
	}
	err = ctx.ComputeBaseSecrets(dhSecret, pskSecret)
	if err != nil {
		return err
	}
	err = ctx.UpdateWithHellos(chm, shm)
	if err != nil {
		return err
	}

	// Rekey to handshake keys
	err = c.in.Rekey(ctx.suite, ctx.handshakeKeys.serverWriteKey, ctx.handshakeKeys.serverWriteIV)
	if err != nil {
		logf(logTypeHandshake, "Unable to rekey inbound")
		return err
	}
	err = c.out.Rekey(ctx.suite, ctx.handshakeKeys.clientWriteKey, ctx.handshakeKeys.clientWriteIV)
	if err != nil {
		logf(logTypeHandshake, "Unable to rekey outbound")
		return err
	}
	logf(logTypeHandshake, "Completed rekey")

	// Read to Finished
	transcript := []*handshakeMessage{}
	var cert *certificateBody
	var certVerify *certificateVerifyBody
	var encryptedExtensions *encryptedExtensionsBody
	var finishedMessage *handshakeMessage
	for {
		hm, err := hIn.ReadMessage()
		if err != nil {
			logf(logTypeHandshake, "Error reading message: %v", err)
			return err
		}
		logf(logTypeHandshake, "Read message with type: %v", hm.msgType)

		if hm.msgType == handshakeTypeFinished {
			finishedMessage = hm
			break
		} else {
			if hm.msgType == handshakeTypeCertificate {
				cert = new(certificateBody)
				_, err = cert.Unmarshal(hm.body)
			} else if hm.msgType == handshakeTypeCertificateVerify {
				certVerify = new(certificateVerifyBody)
				_, err = certVerify.Unmarshal(hm.body)
			} else if hm.msgType == handshakeTypeEncryptedExtensions {
				encryptedExtensions = new(encryptedExtensionsBody)
				_, err = encryptedExtensions.Unmarshal(hm.body)
			}
			transcript = append(transcript, hm)
		}

		if err != nil {
			logf(logTypeHandshake, "Error processing handshake message: %v", err)
			return err
		}
	}
	logf(logTypeHandshake, "Done reading server's first flight")

	// Find server's pinning proof if it is expected
	var foundPinning bool
	var serverPinning pinningTicketExtension
	var serverTicket []byte

	if sendPinning {
		serverPinning = pinningTicketExtension{roleIsServer: true}
		foundPinning = (encryptedExtensions != nil) && extensionList(*encryptedExtensions).Find(&serverPinning)
		if sendPinningTicket && !foundPinning {
			return fmt.Errorf("Ticket pinning: server received its ticket and did not respond with extension")
		}
	}

	// Verify the server's certificate if required
	if ctx.params.mode != handshakeModePSK && ctx.params.mode != handshakeModePSKAndDH {
		if cert == nil || certVerify == nil {
			return fmt.Errorf("tls.client: No server auth data provided")
		}

		transcriptForCertVerify := append([]*handshakeMessage{chm, shm}, transcript[:len(transcript)-1]...)
		logf(logTypeHandshake, "Transcript for certVerify")
		for _, hm := range transcriptForCertVerify {
			logf(logTypeHandshake, "  [%d] %x", hm.msgType, hm.body)
		}
		logf(logTypeHandshake, "===")

		serverPublicKey := cert.certificateList[0].PublicKey
		if err = certVerify.Verify(serverPublicKey, transcriptForCertVerify); err != nil {
			return err
		}

		if c.config.AuthCertificate != nil {
			err = c.config.AuthCertificate(cert.certificateList)
			if err != nil {
				return err
			}
		}
		// validate the server's pinning proof
		if foundPinning {
			logf(logTypeTicketPinning, "Client received PTE")
			if sendPinningTicket {
				// sent a ticket, expect to get back a proof
				pinningProof, err := newPinningProof(ctx.params.hash, c.pinningSecret, ch.random[:], sh.random[:], serverPublicKey)
				if err != nil {
					return fmt.Errorf("Ticket pinning: failed to create proof")
				}
				if bytes.Compare(serverPinning.pinningProof, pinningProof) != 0 {
					return fmt.Errorf("Ticket pinning: server sent invalid proof")
				}
			}
			serverTicket = serverPinning.pinningTicket
			if serverTicket == nil {
				return fmt.Errorf("Server did not send a ticket, and we don't do rampdown yet")
			}
		}
	}

	// Update the crypto context with all but the Finished
	ctx.Update(transcript)

	// Verify server finished
	sfin := new(finishedBody)
	sfin.verifyDataLen = ctx.serverFinished.verifyDataLen
	_, err = sfin.Unmarshal(finishedMessage.body)
	if err != nil {
		return err
	}
	if !bytes.Equal(sfin.verifyData, ctx.serverFinished.verifyData) {
		return fmt.Errorf("tls.client: Server's Finished failed to verify")
	}

	if serverTicket != nil { // Now store the incoming ticket
		newSecret := newTicketSecret(ctx.params.hash, ctx.xSS, ctx.xES)
		ps.storeTicket(origin, serverTicket, newSecret, int(serverPinning.lifetime))
		logf(logTypeTicketPinning, "Client: stored new ticket for %v", origin)
	}

	// Send client Finished
	_, err = hOut.WriteMessageBody(ctx.clientFinished)
	if err != nil {
		return err
	}

	// Rekey to application keys
	err = c.in.Rekey(ctx.suite, ctx.applicationKeys.serverWriteKey, ctx.applicationKeys.serverWriteIV)
	if err != nil {
		return err
	}
	err = c.out.Rekey(ctx.suite, ctx.applicationKeys.clientWriteKey, ctx.applicationKeys.clientWriteIV)
	if err != nil {
		return err
	}

	c.context = ctx
	return nil
}

func (c *Conn) selectCertificate(serverName *serverNameExtension) (privateKey crypto.Signer, chain []*x509.Certificate, err error) {
	for _, cert := range c.config.Certificates {
		for _, name := range cert.Chain[0].DNSNames {
			if name == string(*serverName) {
				chain = cert.Chain
				privateKey = cert.PrivateKey
			}
		}
	}

	// If there's no name match, use the first in the list or fail
	if chain == nil {
		if len(c.config.Certificates) > 0 {
			chain = c.config.Certificates[0].Chain
			privateKey = c.config.Certificates[0].PrivateKey
		} else {
			err = fmt.Errorf("No certificate found for %s", string(*serverName))
		}
	}
	return
}

func (c *Conn) serverHandshake() error {
	logf(logTypeHandshake, "Starting serverHandshake")

	hIn := newHandshakeLayer(c.in)
	hOut := newHandshakeLayer(c.out)

	// Read ClientHello and extract extensions
	ch := new(clientHelloBody)
	chm, err := hIn.ReadMessageBody(ch)
	if err != nil {
		logf(logTypeHandshake, "Unable to read ClientHello: %v", err)
		return err
	}
	logf(logTypeHandshake, "Read ClientHello")

	serverName := new(serverNameExtension)
	supportedGroups := new(supportedGroupsExtension)
	signatureAlgorithms := new(signatureAlgorithmsExtension)
	clientKeyShares := &keyShareExtension{roleIsServer: false}
	clientPSK := &preSharedKeyExtension{roleIsServer: false}
	clientEarlyData := &earlyDataExtension{roleIsServer: false}
	pinningTicketExt := &pinningTicketExtension{roleIsServer: false}

	gotServerName := ch.extensions.Find(serverName)
	gotSupportedGroups := ch.extensions.Find(supportedGroups)
	gotSignatureAlgorithms := ch.extensions.Find(signatureAlgorithms)
	gotKeyShares := ch.extensions.Find(clientKeyShares)
	gotPSK := ch.extensions.Find(clientPSK)
	gotEarlyData := ch.extensions.Find(clientEarlyData)
	gotPinning := ch.extensions.Find(pinningTicketExt)
	logf(logTypeTicketPinning, "Server gotPinning: %v", gotPinning)
	if !gotServerName || !gotSupportedGroups || !gotSignatureAlgorithms {
		logf(logTypeHandshake, "Insufficient extensions")
		return fmt.Errorf("tls.server: Missing extension in ClientHello (%v %v %v %v)",
			gotServerName, gotSupportedGroups, gotSignatureAlgorithms, gotKeyShares)
	}

	// Handle received ticket pinning extension, if any
	var sendPinning bool
	if c.config.PinningEnabled {
		if gotPinning {
			if gotPSK {
				logf(logTypeTicketPinning, "Pinning ticket: not supported with PSK - ignored")
			} else {
				sendPinning = true
				if pinningTicketExt.pinningTicket != nil {
					protectionKeyID, err := readProtectionKeyID(pinningTicketExt.pinningTicket)
					if err != nil {
						return err
					}
					protectionKey, found := ps.readProtectionKey(protectionKeyID)
					if !found {
						return fmt.Errorf("Ticket pinning: protection key not found")
					}
					receivedTicket, err := validate(pinningTicketExt.pinningTicket, protectionKey)
					if err != nil {
						logf(logTypeTicketPinning, "Server: got invalid ticket: %v", err)
						return err
					}
					c.pinningSecret = receivedTicket.ticketSecret
				}
			}
		}
	}

	// Find pre_shared_key extension and look it up
	var serverPSK *preSharedKeyExtension
	var pskSecret []byte
	if gotPSK {
		logf(logTypeHandshake, "Got PSK extension; processing")
		for _, id := range clientPSK.identities {
			logf(logTypeHandshake, "Client provided PSK identity %x", id)
		}

		for _, key := range c.config.ServerPSKs {
			logf(logTypeHandshake, "Checking for %x", key.Identity)
			if clientPSK.HasIdentity(key.Identity) {
				logf(logTypeHandshake, "Matched %x")
				pskSecret = make([]byte, len(key.Key))
				copy(pskSecret, key.Key)

				serverPSK = &preSharedKeyExtension{
					roleIsServer: true,
					identities:   [][]byte{key.Identity},
				}
			}
		}
	}

	// Find key_share extension and do key agreement
	var serverKeyShare *keyShareExtension
	var dhSecret []byte
	if gotKeyShares {
		logf(logTypeHandshake, "Got KeyShare extension; processing")
		for _, share := range clientKeyShares.shares {
			if c.config.enabledGroup[share.group] {
				pub, priv, err := newKeyShare(share.group)
				if err != nil {
					return err
				}

				dhSecret, err = keyAgreement(share.group, share.keyExchange, priv)
				serverKeyShare = &keyShareExtension{
					roleIsServer: true,
					shares:       []keyShare{keyShare{group: share.group, keyExchange: pub}},
				}
				if err != nil {
					return err
				}
				break
			}
		}
	}

	// Find early_data extension and handle early data
	if gotEarlyData {
		logf(logTypeHandshake, "[server] Processing early data")

		// Can't do early data if we don't have a PSK
		// TODO Handle this more elegantly
		if pskSecret == nil {
			return fmt.Errorf("tls.server: EarlyData with no PSK")
		}
		if !c.config.enabledSuite[clientEarlyData.cipherSuite] {
			return fmt.Errorf("tls.server: EarlyData with an unsupported ciphersuite")
		}

		// Compute early handshake / traffic keys from pskSecret
		logf(logTypeHandshake, "[server] Computing early secrets...")
		ctx := cryptoContext{}
		ctx.Init(clientEarlyData.cipherSuite)
		ctx.ComputeEarlySecrets(pskSecret, chm)

		// Rekey read channel to early handshake keys
		logf(logTypeHandshake, "[server] Rekey -> handshake...")
		err = c.in.Rekey(ctx.suite, ctx.earlyHandshakeKeys.clientWriteKey, ctx.earlyHandshakeKeys.clientWriteIV)
		if err != nil {
			return err
		}

		// Read finished message and verify
		logf(logTypeHandshake, "[server] Reading finished...")
		earlyFin := new(finishedBody)
		earlyFin.verifyDataLen = ctx.earlyFinished.verifyDataLen
		_, err = hIn.ReadMessageBody(earlyFin)
		if err != nil {
			return err
		}
		if !bytes.Equal(earlyFin.verifyData, ctx.earlyFinished.verifyData) {
			return fmt.Errorf("tls.client: Client's early Finished failed to verify")
		}

		// Rekey read channel to early traffic keys
		logf(logTypeHandshake, "[server] Rekey -> application...")
		err = c.in.Rekey(ctx.suite, ctx.earlyApplicationKeys.clientWriteKey, ctx.earlyApplicationKeys.clientWriteIV)
		if err != nil {
			return err
		}

		// Read to end of early data
		logf(logTypeHandshake, "[server] Reading early data...")
		done := false
		for !done {
			logf(logTypeHandshake, "  Record!")
			pt, err := c.in.ReadRecord()
			if err != nil {
				return err
			}

			switch pt.contentType {
			case recordTypeAlert:
				alertType := alert(pt.fragment[1])
				if alertType == alertEndOfEarlyData {
					done = true
				} else {
					return fmt.Errorf("tls.server: Unexpected alert in early data [%v]", alertType)
				}
			case recordTypeApplicationData:
				// XXX: Should expose early data differently
				c.readBuffer = append(c.readBuffer, pt.fragment...)
			default:
				return fmt.Errorf("tls.server: Unexpected content type in early data [%v] %x", pt.contentType, pt.fragment)
			}
		}

		logf(logTypeHandshake, "[server] Done reading early data [%d] %x", len(c.readBuffer), c.readBuffer)
	}

	// Pick a ciphersuite
	var chosenSuite cipherSuite
	foundCipherSuite := false
	for _, suite := range ch.cipherSuites {
		// Only use PSK modes if we got a PSK
		mode := cipherSuiteMap[suite].mode
		if gotPSK && (mode != handshakeModePSK) && (mode != handshakeModePSKAndDH) {
			continue
		}

		if c.config.enabledSuite[suite] {
			chosenSuite = suite
			foundCipherSuite = true
			break
		}
	}

	// If there are no matching suites and PSK is present, check non-PSK
	if !foundCipherSuite {
		for _, suite := range ch.cipherSuites {
			if c.config.enabledSuite[suite] {
				chosenSuite = suite
				foundCipherSuite = true
				break
			}
		}
	}

	logf(logTypeCrypto, "Supported Client suites [%v]", ch.cipherSuites)
	if !foundCipherSuite {
		logf(logTypeHandshake, "No acceptable ciphersuites")
		return fmt.Errorf("tls.server: No acceptable ciphersuites")
	}
	logf(logTypeHandshake, "Chose CipherSuite %x", chosenSuite)

	// Init context and decide whether to send KeyShare/PreSharedKey
	ctx := cryptoContext{}
	err = ctx.Init(chosenSuite)
	if err != nil {
		return err
	}
	sendKeyShare := (ctx.params.mode == handshakeModePSKAndDH) || (ctx.params.mode == handshakeModeDH)
	sendPSK := (ctx.params.mode == handshakeModePSK) || (ctx.params.mode == handshakeModePSKAndDH)
	logf(logTypeHandshake, "Initialized context %v %v", sendKeyShare, sendPSK)

	err = ctx.ComputeBaseSecrets(dhSecret, pskSecret)
	if err != nil {
		logf(logTypeHandshake, "Unable to compute base secrets %v", err)
		return err
	}
	logf(logTypeHandshake, "Computed base secrets")

	// Create the ServerHello
	sh := &serverHelloBody{
		cipherSuite: chosenSuite,
	}
	_, err = prng.Read(sh.random[:])
	if err != nil {
		return err
	}
	if sendKeyShare {
		sh.extensions.Add(serverKeyShare)
	}
	if sendPSK {
		sh.extensions.Add(serverPSK)
	}
	logf(logTypeHandshake, "Done creating ServerHello")

	// Write ServerHello and update the crypto context
	shm, err := hOut.WriteMessageBody(sh)
	if err != nil {
		logf(logTypeHandshake, "Unable to send ServerHello %v", err)
		return err
	}
	logf(logTypeHandshake, "Wrote ServerHello")
	err = ctx.UpdateWithHellos(chm, shm)
	if err != nil {
		return err
	}

	// Rekey to handshake keys
	err = c.in.Rekey(ctx.suite, ctx.handshakeKeys.clientWriteKey, ctx.handshakeKeys.clientWriteIV)
	if err != nil {
		return err
	}
	err = c.out.Rekey(ctx.suite, ctx.handshakeKeys.serverWriteKey, ctx.handshakeKeys.serverWriteIV)
	if err != nil {
		return err
	}

	// Moved cert selection up so that the pinning ticket can use the correct public key in the proof
	var privateKey crypto.Signer
	var chain []*x509.Certificate
	if !sendPSK {
		// Select a certificate
		privateKey, chain, err = c.selectCertificate(serverName)
		if err != nil {
			return err
		}
	}

	// Ticket pinning: prepare returned ticket extension
	var pExt extension
	if sendPinning {
		var pinningProof []byte
		if pinningTicketExt.pinningTicket != nil { // got a ticket, respond with proof
			pinningProof, err = newPinningProof(ctx.params.hash, c.pinningSecret, ch.random[:], sh.random[:], privateKey.Public())
			if err != nil {
				return fmt.Errorf("Pinning ticket: failed to create proof")
			}
		}
		newTicketSecret := newTicketSecret(ctx.params.hash, ctx.xSS, ctx.xES)
		protectionKey, keyID, found := ps.readCurrentProtectionKey()
		if !found {
			return fmt.Errorf("Pinning ticket: could not find a currently valid protection key")
		}
		newTicket := pinningTicket{protectionKeyID: keyID, ticketSecret: newTicketSecret}
		sealedPinningTicket := newTicket.protect(protectionKey)
		pinningTicketExt = &pinningTicketExtension{
			roleIsServer:  true,
			pinningTicket: sealedPinningTicket,
			pinningProof:  pinningProof,
			lifetime:      uint32(c.config.PinningTicketLifetime),
		}
		pExtBody, err := pinningTicketExt.Marshal()
		if err != nil {
			return fmt.Errorf("Pinning ticket: failed to marshal extension")
		}
		pExt = extension{extensionType: pinningTicketExt.Type(), extensionData: pExtBody}
		logf(logTypeTicketPinning, "Server sending PTE")
	}

	// Send an EncryptedExtensions message (even if it's empty)
	var ee *encryptedExtensionsBody
	if !sendPinning {
		ee = &encryptedExtensionsBody{}
	} else {
		ee = &encryptedExtensionsBody{pExt}
	}

	eem, err := hOut.WriteMessageBody(ee)
	if err != nil {
		return err
	}
	transcript := []*handshakeMessage{eem}

	// Authenticate with a certificate if required
	if !sendPSK {
		// Create and send Certificate, CertificateVerify
		// TODO Certificate selection based on ClientHello
		certificate := &certificateBody{
			certificateList: chain,
		}
		certm, err := hOut.WriteMessageBody(certificate)
		if err != nil {
			return err
		}

		certificateVerify := &certificateVerifyBody{
			alg: signatureAndHashAlgorithm{hashAlgorithmSHA256, signatureAlgorithmRSA},
		}
		err = certificateVerify.Sign(privateKey, []*handshakeMessage{chm, shm, eem, certm})
		if err != nil {
			return err
		}
		certvm, err := hOut.WriteMessageBody(certificateVerify)
		if err != nil {
			return err
		}

		transcript = append(transcript, []*handshakeMessage{certm, certvm}...)
	}

	// Update the crypto context
	ctx.Update(transcript)

	// Create and write server Finished
	_, err = hOut.WriteMessageBody(ctx.serverFinished)
	if err != nil {
		return err
	}

	// Read and verify client Finished
	cfin := new(finishedBody)
	cfin.verifyDataLen = ctx.clientFinished.verifyDataLen
	_, err = hIn.ReadMessageBody(cfin)
	if err != nil {
		return err
	}
	if !bytes.Equal(cfin.verifyData, ctx.clientFinished.verifyData) {
		return fmt.Errorf("tls.client: Client's Finished failed to verify")
	}

	// Rekey to application keys
	err = c.in.Rekey(ctx.suite, ctx.applicationKeys.clientWriteKey, ctx.applicationKeys.clientWriteIV)
	if err != nil {
		return err
	}
	err = c.out.Rekey(ctx.suite, ctx.applicationKeys.serverWriteKey, ctx.applicationKeys.serverWriteIV)
	if err != nil {
		return err
	}

	// Send a new session ticket
	tkt, err := newSessionTicket(c.config.TicketLifetime, c.config.TicketLen)
	if err != nil {
		return err
	}

	if c.config.SendSessionTickets {
		newPSK := PreSharedKey{
			Identity: tkt.ticket,
			Key:      ctx.resumptionSecret,
		}
		c.config.ServerPSKs = append(c.config.ServerPSKs, newPSK)

		logf(logTypeHandshake, "About to write NewSessionTicket %v", tkt.ticket)
		_, err = hOut.WriteMessageBody(tkt)
		logf(logTypeHandshake, "Wrote NewSessionTicket %v", tkt.ticket)
		if err != nil {
			logf(logTypeHandshake, "Returning error: %v", err)
			return err
		}
	}

	c.context = ctx
	return nil
}
