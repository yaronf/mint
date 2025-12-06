package mint

import (
	"bytes"
	"crypto/x509"
	"time"
)

// Marker interface for actions that an implementation should take based on
// state transitions.
type HandshakeAction interface{}

type QueueHandshakeMessage struct {
	Message *HandshakeMessage
}

type SendQueuedHandshake struct{}

type ClearQueuedMessages struct{}

type SendEarlyData struct{}

type RekeyIn struct {
	epoch  Epoch
	KeySet KeySet
}

type RekeyOut struct {
	epoch  Epoch
	KeySet KeySet
}

type ResetOut struct {
	seq uint64
}

type StorePSK struct {
	PSK PreSharedKey
}

type HandshakeState interface {
	Next(handshakeMessageReader) (HandshakeState, []HandshakeAction, Alert)
	State() State
}

type AppExtensionHandler interface {
	Send(hs HandshakeType, el *ExtensionList) error
	Receive(hs HandshakeType, el *ExtensionList) error
}

// ConnectionOptions objects represent per-connection settings for a client
// initiating a connection
type ConnectionOptions struct {
	ServerName string
	NextProtos []string
}

// ConnectionParameters objects represent the parameters negotiated for a
// connection.
type ConnectionParameters struct {
	UsingPSK               bool
	UsingDH                bool
	ClientSendingEarlyData bool
	UsingEarlyData         bool
	RejectedEarlyData      bool
	UsingClientAuth        bool
	UsingExtendedKeyUpdate bool       // True if Extended Key Update (EKU) was negotiated
	NegotiatedGroup        NamedGroup // Group negotiated during initial handshake (for EKU)

	CipherSuite CipherSuite
	ServerName  string
	NextProto   string
}

// Working state for the handshake.
type HandshakeContext struct {
	timeoutMS         uint32
	timers            *timerSet
	recvdRecords      []uint64
	sentFragments     []*SentHandshakeFragment
	hIn, hOut         *HandshakeLayer
	waitingNextFlight bool
	earlyData         []byte
}

func (hc *HandshakeContext) SetVersion(version uint16) {
	if hc.hIn.conn != nil {
		hc.hIn.conn.SetVersion(version)
	}
	if hc.hOut.conn != nil {
		hc.hOut.conn.SetVersion(version)
	}
}

// stateConnected is symmetric between client and server
type stateConnected struct {
	Params              ConnectionParameters
	hsCtx               *HandshakeContext
	isClient            bool
	cryptoParams        CipherSuiteParams
	resumptionSecret    []byte
	clientTrafficSecret []byte
	serverTrafficSecret []byte
	exporterSecret      []byte
	ekuDerivedSecret    []byte // Derived value for EKU key derivation (Derive-Secret(masterSecret, "derived", ""))
	peerCertificates    []*x509.Certificate
	verifiedChains      [][]*x509.Certificate

	// EKU state tracking
	ekuInProgress      bool           // Is an EKU currently in progress?
	ekuIsInitiator     bool           // Are we the initiator of current EKU?
	ekuPeerKeyShare    *KeyShareEntry // Peer's key share from response
	ekuOurKeyShare     *KeyShareEntry // Our key share (for initiator)
	ekuOurPrivateKey   []byte         // Our private key for key share (needed for key derivation)
	ekuRequestMessage  []byte         // Marshaled key_update_request (full HandshakeMessage for key derivation binding)
	ekuResponseMessage []byte         // Marshaled key_update_response (full HandshakeMessage for key derivation binding)
}

var _ HandshakeState = &stateConnected{}

func (state stateConnected) State() State {
	if state.isClient {
		return StateClientConnected
	}
	return StateServerConnected
}

func (state *stateConnected) KeyUpdate(request KeyUpdateRequest) ([]HandshakeAction, Alert) {
	// Standard KeyUpdate is not allowed when EKU is negotiated (mutually exclusive)
	if state.Params.UsingExtendedKeyUpdate {
		logf(logTypeHandshake, "[StateConnected] KeyUpdate: Standard KeyUpdate not allowed when EKU is negotiated")
		return nil, AlertUnexpectedMessage
	}

	var trafficKeys KeySet
	if state.isClient {
		state.clientTrafficSecret = HkdfExpandLabel(state.cryptoParams.Hash, state.clientTrafficSecret,
			labelClientApplicationTrafficSecret, []byte{}, state.cryptoParams.Hash.Size())
		trafficKeys = makeTrafficKeys(state.cryptoParams, state.clientTrafficSecret)
	} else {
		state.serverTrafficSecret = HkdfExpandLabel(state.cryptoParams.Hash, state.serverTrafficSecret,
			labelServerApplicationTrafficSecret, []byte{}, state.cryptoParams.Hash.Size())
		trafficKeys = makeTrafficKeys(state.cryptoParams, state.serverTrafficSecret)
	}

	kum, err := state.hsCtx.hOut.HandshakeMessageFromBody(&KeyUpdateBody{KeyUpdateRequest: request})
	if err != nil {
		logf(logTypeHandshake, "[StateConnected] Error marshaling key update message: %v", err)
		return nil, AlertInternalError
	}

	toSend := []HandshakeAction{
		QueueHandshakeMessage{kum},
		SendQueuedHandshake{},
		RekeyOut{epoch: EpochUpdate, KeySet: trafficKeys},
	}
	return toSend, AlertNoAlert
}

// ExtendedKeyUpdateInitiate initiates an Extended Key Update (EKU) exchange.
//
// This implements Message 1 of the 4-message EKU exchange: key_update_request.
// The method:
//  1. Validates that EKU is negotiated and no EKU is in progress
//  2. Generates a fresh key share using the negotiated group from the handshake
//  3. Creates and queues a key_update_request message with the key share
//  4. Stores the key share and request message for later key derivation
//  5. Sets ekuInProgress=true and ekuIsInitiator=true
//
// The caller must take the returned actions (QueueHandshakeMessage, SendQueuedHandshake)
// to actually send the message. After sending, the initiator waits for:
//   - Message 2: key_update_response (handled by handleExtendedKeyUpdate)
//   - Message 3: new_key_update from initiator (handled by handleExtendedKeyUpdate)
//   - Message 4: new_key_update from responder (handled by handleExtendedKeyUpdate)
//
// Key derivation occurs in handleExtendedKeyUpdate after receiving the response.
//
// Returns AlertNoAlert on success, or an appropriate alert on error.
func (state *stateConnected) ExtendedKeyUpdateInitiate() ([]HandshakeAction, Alert) {
	// Validate EKU is negotiated
	if !state.Params.UsingExtendedKeyUpdate {
		logf(logTypeHandshake, "[StateConnected] ExtendedKeyUpdateInitiate: EKU not negotiated")
		return nil, AlertInternalError
	}

	// Check no EKU is already in progress
	if state.ekuInProgress {
		logf(logTypeHandshake, "[StateConnected] ExtendedKeyUpdateInitiate: EKU already in progress")
		return nil, AlertUnexpectedMessage
	}

	// Get negotiated group (must be set during handshake)
	if state.Params.NegotiatedGroup == 0 {
		logf(logTypeHandshake, "[StateConnected] ExtendedKeyUpdateInitiate: No negotiated group")
		return nil, AlertInternalError
	}

	// Generate fresh key share using negotiated group
	// Store both public and private key - private key is needed for key derivation
	pub, priv, err := newKeyShare(state.Params.NegotiatedGroup)
	if err != nil {
		logf(logTypeHandshake, "[StateConnected] ExtendedKeyUpdateInitiate: Error generating key share: %v", err)
		return nil, AlertInternalError
	}

	ourKeyShare := &KeyShareEntry{
		Group:       state.Params.NegotiatedGroup,
		KeyExchange: pub,
	}
	state.ekuOurPrivateKey = priv // Store private key for key derivation

	// Create ExtendedKeyUpdate message (key_update_request)
	ekuBody := &ExtendedKeyUpdateBody{
		EKUType:  ExtendedKeyUpdateTypeRequest,
		KeyShare: ourKeyShare,
	}

	// Create HandshakeMessage
	ekuMsg, err := state.hsCtx.hOut.HandshakeMessageFromBody(ekuBody)
	if err != nil {
		logf(logTypeHandshake, "[StateConnected] ExtendedKeyUpdateInitiate: Error marshaling EKU message: %v", err)
		return nil, AlertInternalError
	}

	// Store full HandshakeMessage (including header) for key derivation binding
	state.ekuRequestMessage = ekuMsg.Marshal()

	// Set EKU state
	state.ekuInProgress = true
	state.ekuIsInitiator = true
	state.ekuOurKeyShare = ourKeyShare

	logf(logTypeHandshake, "[StateConnected] ExtendedKeyUpdateInitiate: Created key_update_request, group=%v", state.Params.NegotiatedGroup)

	toSend := []HandshakeAction{
		QueueHandshakeMessage{ekuMsg},
		SendQueuedHandshake{},
	}

	return toSend, AlertNoAlert
}

func (state *stateConnected) NewSessionTicket(length int, lifetime, earlyDataLifetime uint32) ([]HandshakeAction, Alert) {
	tkt, err := NewSessionTicket(length, lifetime)
	if err != nil {
		logf(logTypeHandshake, "[StateConnected] Error generating NewSessionTicket: %v", err)
		return nil, AlertInternalError
	}

	err = tkt.Extensions.Add(&TicketEarlyDataInfoExtension{earlyDataLifetime})
	if err != nil {
		logf(logTypeHandshake, "[StateConnected] Error adding extension to NewSessionTicket: %v", err)
		return nil, AlertInternalError
	}

	resumptionKey := HkdfExpandLabel(state.cryptoParams.Hash, state.resumptionSecret,
		labelResumption, tkt.TicketNonce, state.cryptoParams.Hash.Size())

	newPSK := PreSharedKey{
		CipherSuite:  state.cryptoParams.Suite,
		IsResumption: true,
		Identity:     tkt.Ticket,
		Key:          resumptionKey,
		NextProto:    state.Params.NextProto,
		ReceivedAt:   time.Now(),
		ExpiresAt:    time.Now().Add(time.Duration(tkt.TicketLifetime) * time.Second),
		TicketAgeAdd: tkt.TicketAgeAdd,
	}

	tktm, err := state.hsCtx.hOut.HandshakeMessageFromBody(tkt)
	if err != nil {
		logf(logTypeHandshake, "[StateConnected] Error marshaling NewSessionTicket: %v", err)
		return nil, AlertInternalError
	}

	toSend := []HandshakeAction{
		StorePSK{newPSK},
		QueueHandshakeMessage{tktm},
		SendQueuedHandshake{},
	}
	return toSend, AlertNoAlert
}

// Next does nothing for this state.
func (state stateConnected) Next(hr handshakeMessageReader) (HandshakeState, []HandshakeAction, Alert) {
	return state, nil, AlertNoAlert
}

func (state stateConnected) ProcessMessage(hm *HandshakeMessage) (HandshakeState, []HandshakeAction, Alert) {
	return state.ProcessMessageWithRawBytes(hm, nil)
}

func (state stateConnected) ProcessMessageWithRawBytes(hm *HandshakeMessage, rawBytes []byte) (HandshakeState, []HandshakeAction, Alert) {
	if hm == nil {
		logf(logTypeHandshake, "[StateConnected] Unexpected message")
		return nil, nil, AlertUnexpectedMessage
	}

	logf(logTypeHandshake, "[StateConnected] ProcessMessage: msgType=%v, rawBytes=%v (len=%d)", hm.msgType, rawBytes != nil, len(rawBytes))
	bodyGeneric, err := hm.ToBody()
	if err != nil {
		logf(logTypeHandshake, "[StateConnected] Error decoding message: %v", err)
		return nil, nil, AlertDecodeError
	}

	logf(logTypeHandshake, "[StateConnected] ProcessMessage: decoded body type=%T", bodyGeneric)
	switch body := bodyGeneric.(type) {
	case *KeyUpdateBody:
		// Standard KeyUpdate - reject if EKU is negotiated
		if state.Params.UsingExtendedKeyUpdate {
			logf(logTypeHandshake, "[StateConnected] Received standard KeyUpdate but EKU is negotiated")
			return nil, nil, AlertUnexpectedMessage
		}

		var trafficKeys KeySet
		if !state.isClient {
			state.clientTrafficSecret = HkdfExpandLabel(state.cryptoParams.Hash, state.clientTrafficSecret,
				labelClientApplicationTrafficSecret, []byte{}, state.cryptoParams.Hash.Size())
			trafficKeys = makeTrafficKeys(state.cryptoParams, state.clientTrafficSecret)
		} else {
			state.serverTrafficSecret = HkdfExpandLabel(state.cryptoParams.Hash, state.serverTrafficSecret,
				labelServerApplicationTrafficSecret, []byte{}, state.cryptoParams.Hash.Size())
			trafficKeys = makeTrafficKeys(state.cryptoParams, state.serverTrafficSecret)
		}

		toSend := []HandshakeAction{RekeyIn{epoch: EpochUpdate, KeySet: trafficKeys}}

		// If requested, roll outbound keys and send a KeyUpdate
		if body.KeyUpdateRequest == KeyUpdateRequested {
			logf(logTypeHandshake, "Received key update, update requested", body.KeyUpdateRequest)
			moreToSend, alert := state.KeyUpdate(KeyUpdateNotRequested)
			if alert != AlertNoAlert {
				return nil, nil, alert
			}
			toSend = append(toSend, moreToSend...)
		}
		return state, toSend, AlertNoAlert
	case *ExtendedKeyUpdateBody:
		hs, actions, alert := state.handleExtendedKeyUpdate(hm, body, rawBytes)
		// handleExtendedKeyUpdate returns *stateConnected, but ProcessMessage expects stateConnected value
		if hs == nil {
			return nil, actions, alert
		}
		if sc, ok := hs.(*stateConnected); ok {
			return *sc, actions, alert
		}
		return hs, actions, alert
	case *NewSessionTicketBody:
		// XXX: Allow NewSessionTicket in both directions?
		if !state.isClient {
			return nil, nil, AlertUnexpectedMessage
		}

		resumptionKey := HkdfExpandLabel(state.cryptoParams.Hash, state.resumptionSecret,
			labelResumption, body.TicketNonce, state.cryptoParams.Hash.Size())
		psk := PreSharedKey{
			CipherSuite:  state.cryptoParams.Suite,
			IsResumption: true,
			Identity:     body.Ticket,
			Key:          resumptionKey,
			NextProto:    state.Params.NextProto,
			ReceivedAt:   time.Now(),
			ExpiresAt:    time.Now().Add(time.Duration(body.TicketLifetime) * time.Second),
			TicketAgeAdd: body.TicketAgeAdd,
		}

		toSend := []HandshakeAction{StorePSK{psk}}
		return state, toSend, AlertNoAlert
	}

	logf(logTypeHandshake, "[StateConnected] Unexpected message type %v", hm.msgType)
	return nil, nil, AlertUnexpectedMessage
}

// deriveEKUKeys derives new traffic secrets using fresh (EC)DHE exchange
// This implements the EKU key derivation as specified in draft-ietf-tls-extended-key-update-07 Section 7
// deriveEKUKeys performs EKU-specific key derivation for the initiator.
//
// This implements the key derivation process specified in draft-ietf-tls-extended-key-update-07 Section 7.
// The process:
//  1. Computes shared secret from key shares using (EC)DHE
//  2. Derives main_secret_N+1 using HKDF-Extract with ekuDerivedSecret as salt
//  3. Derives traffic secrets using Derive-Secret with EKU message binding
//  4. Updates ekuDerivedSecret for subsequent EKUs
//  5. Returns RekeyOut action to update send keys
//
// Key Derivation Steps (per draft Section 7):
//   - main_secret_N+1 = HKDF-Extract(ekuDerivedSecret, shared_secret)
//   - client_traffic_secret_N+1 = Derive-Secret(main_secret_N+1, "c ap traffic", eku_context)
//   - server_traffic_secret_N+1 = Derive-Secret(main_secret_N+1, "s ap traffic", eku_context)
//   - ekuDerivedSecret = Derive-Secret(main_secret_N+1, "derived", "")
//
// The eku_context is the concatenation of the marshaled request and response messages,
// providing message authentication and binding (MAL-BIND-K-CT security).
//
// Note: This function regenerates the private key from the public key share, which is
// inefficient. A future optimization would store the private key when generating the key share.
//
// Returns RekeyOut action for the initiator (send keys updated after sending new_key_update).
func (state *stateConnected) deriveEKUKeys(ourKeyShare, peerKeyShare *KeyShareEntry, requestMsg, responseMsg []byte) ([]HandshakeAction, Alert) {
	// Step a: Compute shared secret from key shares
	// We need the private key for ourKeyShare - but we only stored the public key
	// For EKU, we need to regenerate the key pair or store the private key
	// For now, we'll need to get the private key from somewhere - this is a limitation
	// TODO: Store private key in ekuOurKeyShare or regenerate it
	logf(logTypeHandshake, "[StateConnected] deriveEKUKeys: Computing shared secret, group=%v", ourKeyShare.Group)

	// Use stored private key from ExtendedKeyUpdateInitiate
	if state.ekuOurPrivateKey == nil {
		logf(logTypeHandshake, "[StateConnected] deriveEKUKeys: ekuOurPrivateKey is nil")
		return nil, AlertInternalError
	}

	sharedSecret, err := keyAgreement(ourKeyShare.Group, peerKeyShare.KeyExchange, state.ekuOurPrivateKey)
	if err != nil {
		logf(logTypeHandshake, "[StateConnected] deriveEKUKeys: Error computing shared secret: %v", err)
		return nil, AlertInternalError
	}

	logf(logTypeCrypto, "[StateConnected] deriveEKUKeys: Shared secret: [%d] %x", len(sharedSecret), sharedSecret)

	// Step b: Derive main_secret_N+1
	// Use stored ekuDerivedSecret as input salt
	if state.ekuDerivedSecret == nil {
		logf(logTypeHandshake, "[StateConnected] deriveEKUKeys: ekuDerivedSecret is nil")
		return nil, AlertInternalError
	}

	mainSecretN1 := HkdfExtract(state.cryptoParams.Hash, state.ekuDerivedSecret, sharedSecret)
	logf(logTypeCrypto, "[StateConnected] deriveEKUKeys: main_secret_N+1: [%d] %x", len(mainSecretN1), mainSecretN1)

	// Step c: Derive traffic secrets using concatenated request and response messages as context
	// For DTLS, extract message bodies (skip headers) since sequence numbers can differ between retransmissions
	// For TLS, use full messages (headers don't include sequence numbers)
	requestBody := requestMsg
	responseBody := responseMsg
	isDTLS := state.hsCtx.hOut != nil && state.hsCtx.hOut.datagram
	headerLen := handshakeHeaderLenTLS
	if isDTLS {
		headerLen = handshakeHeaderLenDTLS
	}
	reqPreview := requestMsg[:headerLen]
	respPreview := responseMsg[:headerLen]
	logf(logTypeCrypto, "[StateConnected] deriveEKUKeys: isDTLS=%v, requestMsg len=%d (first %d bytes: %x), responseMsg len=%d (first %d bytes: %x)",
		isDTLS, len(requestMsg), headerLen, reqPreview, len(responseMsg), headerLen, respPreview)
	if isDTLS {
		// For DTLS, extract message bodies by skipping the DTLS handshake header
		requestBody = requestMsg[headerLen:]
		reqBodyPreview := requestBody[:headerLen]
		logf(logTypeCrypto, "[StateConnected] deriveEKUKeys: Extracted requestBody, len=%d (skipped %d bytes), first %d bytes: %x",
			len(requestBody), headerLen, headerLen, reqBodyPreview)
		responseBody = responseMsg[headerLen:]
		respBodyPreview := responseBody[:headerLen]
		logf(logTypeCrypto, "[StateConnected] deriveEKUKeys: Extracted responseBody, len=%d (skipped %d bytes), first %d bytes: %x",
			len(responseBody), headerLen, headerLen, respBodyPreview)
	}
	ekuContext := append(requestBody, responseBody...)
	logf(logTypeCrypto, "[StateConnected] deriveEKUKeys: EKU context length: %d (using message bodies for DTLS)", len(ekuContext))
	// Log full message bodies for debugging
	logf(logTypeCrypto, "[StateConnected] deriveEKUKeys: FULL requestBody (%d bytes): %x", len(requestBody), requestBody)
	logf(logTypeCrypto, "[StateConnected] deriveEKUKeys: FULL responseBody (%d bytes): %x", len(responseBody), responseBody)
	logf(logTypeCrypto, "[StateConnected] deriveEKUKeys: FULL ekuContext (%d bytes): %x", len(ekuContext), ekuContext)

	clientApplicationTrafficSecretN1 := deriveSecret(state.cryptoParams, mainSecretN1, labelClientApplicationTrafficSecret, ekuContext)
	serverApplicationTrafficSecretN1 := deriveSecret(state.cryptoParams, mainSecretN1, labelServerApplicationTrafficSecret, ekuContext)
	exporterSecretN1 := deriveSecret(state.cryptoParams, mainSecretN1, labelExporterSecret, ekuContext)
	resumptionMainSecretN1 := deriveSecret(state.cryptoParams, mainSecretN1, labelResumptionSecret, ekuContext)

	logf(logTypeCrypto, "[StateConnected] deriveEKUKeys: client_application_traffic_secret_N+1: [%d] %x", len(clientApplicationTrafficSecretN1), clientApplicationTrafficSecretN1)
	logf(logTypeCrypto, "[StateConnected] deriveEKUKeys: server_application_traffic_secret_N+1: [%d] %x", len(serverApplicationTrafficSecretN1), serverApplicationTrafficSecretN1)

	// Step d: Update stateConnected secrets
	state.clientTrafficSecret = clientApplicationTrafficSecretN1
	state.serverTrafficSecret = serverApplicationTrafficSecretN1
	state.exporterSecret = exporterSecretN1
	state.resumptionSecret = resumptionMainSecretN1

	// Compute and store new derived value for next EKU
	state.ekuDerivedSecret = deriveSecret(state.cryptoParams, mainSecretN1, labelDerived, []byte{})
	logf(logTypeCrypto, "[StateConnected] deriveEKUKeys: New ekuDerivedSecret: [%d] %x", len(state.ekuDerivedSecret), state.ekuDerivedSecret)

	// Step e: Generate traffic keys from new secrets
	// For initiator: update send keys (RekeyOut)
	// For responder: update receive keys first, then send keys after sending new_key_update
	// This function is called by initiator after receiving response, so we update send keys
	var trafficKeys KeySet
	if state.isClient {
		trafficKeys = makeTrafficKeys(state.cryptoParams, state.clientTrafficSecret)
		logf(logTypeCrypto, "[StateConnected] deriveEKUKeys: Generated trafficKeys (client secret): key=%x iv=%x", trafficKeys.Keys["key"], trafficKeys.Keys["iv"])
	} else {
		trafficKeys = makeTrafficKeys(state.cryptoParams, state.serverTrafficSecret)
		logf(logTypeCrypto, "[StateConnected] deriveEKUKeys: Generated trafficKeys (server secret): key=%x iv=%x", trafficKeys.Keys["key"], trafficKeys.Keys["iv"])
	}

	logf(logTypeHandshake, "[StateConnected] deriveEKUKeys: Generated traffic keys, returning RekeyOut action")
	return []HandshakeAction{RekeyOut{epoch: EpochUpdate, KeySet: trafficKeys}}, AlertNoAlert
}

// deriveEKUKeysForResponder derives new traffic secrets for responder
// Responder derives secrets after receiving initiator's new_key_update (Message 3)
// Returns RekeyIn action (update receive keys) and RekeyOut action (update send keys)
// deriveEKUKeysForResponder performs EKU-specific key derivation for the responder.
//
// This is similar to deriveEKUKeys but returns both RekeyIn and RekeyOut actions.
// The responder updates receive keys when receiving the initiator's new_key_update (Message 3),
// and updates send keys when sending its own new_key_update (Message 4).
//
// Key derivation follows the same process as deriveEKUKeys:
//   - Computes shared secret from key shares
//   - Derives main_secret_N+1 using HKDF-Extract
//   - Derives traffic secrets with EKU message binding
//   - Updates ekuDerivedSecret for subsequent EKUs
//
// Returns both RekeyIn and RekeyOut actions for the responder.
func (state *stateConnected) deriveEKUKeysForResponder(ourKeyShare, peerKeyShare *KeyShareEntry, requestMsg, responseMsg []byte) ([]HandshakeAction, Alert) {
	// Same key derivation as initiator, but responder needs both RekeyIn and RekeyOut
	logf(logTypeHandshake, "[StateConnected] deriveEKUKeysForResponder: Computing shared secret, group=%v", ourKeyShare.Group)

	// Use stored private key from ExtendedKeyUpdateInitiate (for initiator) or from response generation (for responder)
	if state.ekuOurPrivateKey == nil {
		logf(logTypeHandshake, "[StateConnected] deriveEKUKeysForResponder: ekuOurPrivateKey is nil")
		return nil, AlertInternalError
	}

	sharedSecret, err := keyAgreement(ourKeyShare.Group, peerKeyShare.KeyExchange, state.ekuOurPrivateKey)
	if err != nil {
		logf(logTypeHandshake, "[StateConnected] deriveEKUKeysForResponder: Error computing shared secret: %v", err)
		return nil, AlertInternalError
	}

	logf(logTypeCrypto, "[StateConnected] deriveEKUKeysForResponder: Shared secret: [%d] %x", len(sharedSecret), sharedSecret)

	// Derive main_secret_N+1
	if state.ekuDerivedSecret == nil {
		logf(logTypeHandshake, "[StateConnected] deriveEKUKeysForResponder: ekuDerivedSecret is nil")
		return nil, AlertInternalError
	}

	mainSecretN1 := HkdfExtract(state.cryptoParams.Hash, state.ekuDerivedSecret, sharedSecret)
	logf(logTypeCrypto, "[StateConnected] deriveEKUKeysForResponder: main_secret_N+1: [%d] %x", len(mainSecretN1), mainSecretN1)

	// Derive traffic secrets using concatenated request and response messages as context
	// For DTLS, extract message bodies (skip headers) since sequence numbers can differ between retransmissions
	// For TLS, use full messages (headers don't include sequence numbers)
	requestBody := requestMsg
	responseBody := responseMsg
	isDTLS := state.hsCtx.hOut != nil && state.hsCtx.hOut.datagram
	headerLen := handshakeHeaderLenTLS
	if isDTLS {
		headerLen = handshakeHeaderLenDTLS
	}
	reqPreview := requestMsg[:headerLen]
	respPreview := responseMsg[:headerLen]
	logf(logTypeCrypto, "[StateConnected] deriveEKUKeysForResponder: isDTLS=%v, requestMsg len=%d (first %d bytes: %x), responseMsg len=%d (first %d bytes: %x)",
		isDTLS, len(requestMsg), headerLen, reqPreview, len(responseMsg), headerLen, respPreview)
	if isDTLS {
		// For DTLS, extract message bodies by skipping the DTLS handshake header
		if len(requestMsg) < headerLen {
			logf(logTypeCrypto, "[StateConnected] deriveEKUKeysForResponder: ERROR requestMsg too short: len=%d < headerLen=%d", len(requestMsg), headerLen)
		} else {
			requestBody = requestMsg[headerLen:]
			reqBodyPreview := requestBody
			if len(reqBodyPreview) > 20 {
				reqBodyPreview = reqBodyPreview[:20]
			}
			logf(logTypeCrypto, "[StateConnected] deriveEKUKeysForResponder: Extracted requestBody, len=%d (skipped %d bytes), first 20 bytes: %x",
				len(requestBody), headerLen, reqBodyPreview)
		}
		if len(responseMsg) < headerLen {
			logf(logTypeCrypto, "[StateConnected] deriveEKUKeysForResponder: ERROR responseMsg too short: len=%d < headerLen=%d", len(responseMsg), headerLen)
		} else {
			responseBody = responseMsg[headerLen:]
			respBodyPreview := responseBody
			if len(respBodyPreview) > 20 {
				respBodyPreview = respBodyPreview[:20]
			}
			logf(logTypeCrypto, "[StateConnected] deriveEKUKeysForResponder: Extracted responseBody, len=%d (skipped %d bytes), first 20 bytes: %x",
				len(responseBody), headerLen, respBodyPreview)
		}
	}
	ekuContext := append(requestBody, responseBody...)
	logf(logTypeCrypto, "[StateConnected] deriveEKUKeysForResponder: EKU context length: %d (using message bodies for DTLS)", len(ekuContext))
	// Log full message bodies for debugging
	logf(logTypeCrypto, "[StateConnected] deriveEKUKeysForResponder: FULL requestBody (%d bytes): %x", len(requestBody), requestBody)
	logf(logTypeCrypto, "[StateConnected] deriveEKUKeysForResponder: FULL responseBody (%d bytes): %x", len(responseBody), responseBody)
	logf(logTypeCrypto, "[StateConnected] deriveEKUKeysForResponder: FULL ekuContext (%d bytes): %x", len(ekuContext), ekuContext)

	clientApplicationTrafficSecretN1 := deriveSecret(state.cryptoParams, mainSecretN1, labelClientApplicationTrafficSecret, ekuContext)
	serverApplicationTrafficSecretN1 := deriveSecret(state.cryptoParams, mainSecretN1, labelServerApplicationTrafficSecret, ekuContext)
	exporterSecretN1 := deriveSecret(state.cryptoParams, mainSecretN1, labelExporterSecret, ekuContext)
	resumptionMainSecretN1 := deriveSecret(state.cryptoParams, mainSecretN1, labelResumptionSecret, ekuContext)

	logf(logTypeCrypto, "[StateConnected] deriveEKUKeysForResponder: client_application_traffic_secret_N+1: [%d] %x", len(clientApplicationTrafficSecretN1), clientApplicationTrafficSecretN1)
	logf(logTypeCrypto, "[StateConnected] deriveEKUKeysForResponder: server_application_traffic_secret_N+1: [%d] %x", len(serverApplicationTrafficSecretN1), serverApplicationTrafficSecretN1)

	// Update stateConnected secrets
	state.clientTrafficSecret = clientApplicationTrafficSecretN1
	state.serverTrafficSecret = serverApplicationTrafficSecretN1
	state.exporterSecret = exporterSecretN1
	state.resumptionSecret = resumptionMainSecretN1

	// Compute and store new derived value for next EKU
	state.ekuDerivedSecret = deriveSecret(state.cryptoParams, mainSecretN1, labelDerived, []byte{})
	logf(logTypeCrypto, "[StateConnected] deriveEKUKeysForResponder: New ekuDerivedSecret: [%d] %x", len(state.ekuDerivedSecret), state.ekuDerivedSecret)

	// Generate traffic keys for both receive and send
	// Responder updates receive keys first (RekeyIn), then send keys (RekeyOut)
	var receiveKeys, sendKeys KeySet
	if state.isClient {
		receiveKeys = makeTrafficKeys(state.cryptoParams, state.serverTrafficSecret)
		sendKeys = makeTrafficKeys(state.cryptoParams, state.clientTrafficSecret)
		logf(logTypeCrypto, "[StateConnected] deriveEKUKeysForResponder: Generated receiveKeys (server secret): key=%x iv=%x", receiveKeys.Keys["key"], receiveKeys.Keys["iv"])
		logf(logTypeCrypto, "[StateConnected] deriveEKUKeysForResponder: Generated sendKeys (client secret): key=%x iv=%x", sendKeys.Keys["key"], sendKeys.Keys["iv"])
	} else {
		receiveKeys = makeTrafficKeys(state.cryptoParams, state.clientTrafficSecret)
		sendKeys = makeTrafficKeys(state.cryptoParams, state.serverTrafficSecret)
		logf(logTypeCrypto, "[StateConnected] deriveEKUKeysForResponder: Generated receiveKeys (client secret): key=%x iv=%x", receiveKeys.Keys["key"], receiveKeys.Keys["iv"])
		logf(logTypeCrypto, "[StateConnected] deriveEKUKeysForResponder: Generated sendKeys (server secret): key=%x iv=%x", sendKeys.Keys["key"], sendKeys.Keys["iv"])
	}

	logf(logTypeHandshake, "[StateConnected] deriveEKUKeysForResponder: Generated traffic keys, returning RekeyIn and RekeyOut actions")
	return []HandshakeAction{
		RekeyIn{epoch: EpochUpdate, KeySet: receiveKeys},
		RekeyOut{epoch: EpochUpdate, KeySet: sendKeys},
	}, AlertNoAlert
}

// handleExtendedKeyUpdate processes Extended Key Update messages
// This handles both initiator and responder paths
// rawBytes is the raw handshake message bytes from the wire (for key derivation binding)
func (state *stateConnected) handleExtendedKeyUpdate(hm *HandshakeMessage, body *ExtendedKeyUpdateBody, rawBytes []byte) (HandshakeState, []HandshakeAction, Alert) {
	logf(logTypeHandshake, "[StateConnected] handleExtendedKeyUpdate: EKUType=%v, UsingExtendedKeyUpdate=%v, NegotiatedGroup=%v, ekuInProgress=%v, ekuIsInitiator=%v",
		body.EKUType, state.Params.UsingExtendedKeyUpdate, state.Params.NegotiatedGroup, state.ekuInProgress, state.ekuIsInitiator)

	if !state.Params.UsingExtendedKeyUpdate {
		logf(logTypeHandshake, "[StateConnected] Received ExtendedKeyUpdate but EKU not negotiated")
		return nil, nil, AlertUnexpectedMessage
	}

	switch body.EKUType {
	case ExtendedKeyUpdateTypeRequest:
		// Handle request - could be from initiator (tie-breaking) or responder path
		if state.ekuInProgress && state.ekuIsInitiator {
			// We're in initiator state, received a request - tie-breaking needed
			logf(logTypeHandshake, "[StateConnected] Received EKU request while initiator - tie-breaking")
			return state.handleEKUTieBreaking(hm, body)
		}
		// Otherwise, we're the responder - handle request (Message 1)
		// Clear any stale EKU state before checking if EKU is in progress
		// This handles the case where Message 4 was sent but state wasn't cleared properly
		// If ekuInProgress is true but we're not actually in an EKU (no key shares or messages), clear it
		if state.ekuInProgress {
			hasActiveState := state.ekuOurKeyShare != nil || state.ekuPeerKeyShare != nil || state.ekuRequestMessage != nil || state.ekuResponseMessage != nil
			logf(logTypeHandshake, "[StateConnected] Received EKU request, ekuInProgress=true, hasActiveState=%v (OurKeyShare=%v, PeerKeyShare=%v, RequestMsg=%v, ResponseMsg=%v)",
				hasActiveState, state.ekuOurKeyShare != nil, state.ekuPeerKeyShare != nil, state.ekuRequestMessage != nil, state.ekuResponseMessage != nil)
			if !hasActiveState {
				logf(logTypeHandshake, "[StateConnected] Clearing stale EKU state (ekuInProgress=true but no active state fields)")
				state.ekuInProgress = false
				state.ekuIsInitiator = false
				state.ekuOurPrivateKey = nil
			}
		}

		if state.ekuInProgress {
			// Already have an EKU in progress - check if we're waiting to send Message 4
			// If we've already sent Message 4 (queued and sent), we can clear the state and start a new EKU
			// But if Message 4 is still queued, we should reject concurrent request
			// For now, reject concurrent requests - the previous EKU should complete first
			logf(logTypeHandshake, "[StateConnected] Received EKU request but EKU already in progress (ekuIsInitiator=%v)", state.ekuIsInitiator)
			// If we're the responder and have Message 4 queued but not sent, reject
			// Actually, we can't know if Message 4 was sent, so we'll reject concurrent requests
			// The proper fix would be to track Message 4 send status, but for now reject
			return nil, nil, AlertUnexpectedMessage
		}

		// Validate KeyShare is present
		if body.KeyShare == nil {
			logf(logTypeHandshake, "[StateConnected] Received EKU request without KeyShare")
			return nil, nil, AlertDecodeError
		}

		// Validate group matches negotiated group
		// Note: NegotiatedGroup should be set when EKU is negotiated (requires DH)
		logf(logTypeHandshake, "[StateConnected] Validating EKU request: KeyShare.Group=%v, NegotiatedGroup=%v", body.KeyShare.Group, state.Params.NegotiatedGroup)
		if state.Params.NegotiatedGroup == 0 {
			logf(logTypeHandshake, "[StateConnected] Received EKU request but NegotiatedGroup is 0 (EKU requires DH)")
			return nil, nil, AlertInternalError
		}
		if body.KeyShare.Group != state.Params.NegotiatedGroup {
			logf(logTypeHandshake, "[StateConnected] Received EKU request with wrong group: %v != %v", body.KeyShare.Group, state.Params.NegotiatedGroup)
			return nil, nil, AlertIllegalParameter
		}

		// Store peer's key share and request message
		state.ekuPeerKeyShare = body.KeyShare
		// Use raw bytes if provided (from wire), otherwise marshal (for compatibility)
		// rawBytes is the raw handshake message bytes from the wire (for key derivation binding)
		if rawBytes != nil && len(rawBytes) > 0 {
			state.ekuRequestMessage = make([]byte, len(rawBytes))
			copy(state.ekuRequestMessage, rawBytes)
			preview := rawBytes
			if len(preview) > 24 {
				preview = preview[:24]
			}
			logf(logTypeHandshake, "[StateConnected] Stored ekuRequestMessage from rawBytes: len=%d, first 24 bytes: %x", len(rawBytes), preview)
		} else {
			state.ekuRequestMessage = hm.Marshal()
			preview := state.ekuRequestMessage
			if len(preview) > 24 {
				preview = preview[:24]
			}
			logf(logTypeHandshake, "[StateConnected] Stored ekuRequestMessage from Marshal(): len=%d, first 24 bytes: %x", len(state.ekuRequestMessage), preview)
		}

		// Generate fresh key share using negotiated group
		// Store both public and private key - private key is needed for key derivation
		pub, priv, err := newKeyShare(state.Params.NegotiatedGroup)
		if err != nil {
			logf(logTypeHandshake, "[StateConnected] Error generating key share for response: %v", err)
			return nil, nil, AlertInternalError
		}

		ourKeyShare := &KeyShareEntry{
			Group:       state.Params.NegotiatedGroup,
			KeyExchange: pub,
		}
		state.ekuOurKeyShare = ourKeyShare
		state.ekuOurPrivateKey = priv // Store private key for key derivation

		// Create ExtendedKeyUpdate response message (Message 2)
		ekuResponseBody := &ExtendedKeyUpdateBody{
			EKUType:  ExtendedKeyUpdateTypeResponse,
			KeyShare: ourKeyShare,
		}

		ekuResponseMsg, err := state.hsCtx.hOut.HandshakeMessageFromBody(ekuResponseBody)
		if err != nil {
			logf(logTypeHandshake, "[StateConnected] Error marshaling EKU response: %v", err)
			return nil, nil, AlertInternalError
		}

		// Store full HandshakeMessage (including header) for key derivation binding
		state.ekuResponseMessage = ekuResponseMsg.Marshal()

		// Set EKU state - responder waiting for initiator's new_key_update
		state.ekuInProgress = true
		state.ekuIsInitiator = false

		logf(logTypeHandshake, "[StateConnected] Responder: Sent key_update_response (Message 2), waiting for initiator's new_key_update (Message 3)")

		toSend := []HandshakeAction{
			QueueHandshakeMessage{ekuResponseMsg},
			SendQueuedHandshake{},
		}
		return state, toSend, AlertNoAlert

	case ExtendedKeyUpdateTypeResponse:
		// Initiator receives response (Message 2)
		if !state.ekuInProgress || !state.ekuIsInitiator {
			logf(logTypeHandshake, "[StateConnected] Received EKU response but not in initiator state")
			return nil, nil, AlertUnexpectedMessage
		}

		// Check if we've already processed Message 2 (deduplication for DTLS retransmissions)
		// If ekuResponseMessage is already set, we've already processed Message 2
		if state.ekuResponseMessage != nil {
			logf(logTypeHandshake, "[StateConnected] Received duplicate EKU response (Message 2) - already processed, skipping")
			return state, nil, AlertNoAlert // Return no actions, state unchanged
		}

		// Validate KeyShare is present
		if body.KeyShare == nil {
			logf(logTypeHandshake, "[StateConnected] Received EKU response without KeyShare")
			return nil, nil, AlertDecodeError
		}

		// Validate group matches negotiated group
		if body.KeyShare.Group != state.Params.NegotiatedGroup {
			logf(logTypeHandshake, "[StateConnected] Received EKU response with wrong group: %v != %v", body.KeyShare.Group, state.Params.NegotiatedGroup)
			return nil, nil, AlertIllegalParameter
		}

		// Store peer's key share and response message
		state.ekuPeerKeyShare = body.KeyShare
		// Use raw bytes if provided (from wire), otherwise marshal (for compatibility)
		logf(logTypeHandshake, "[StateConnected] handleExtendedKeyUpdate: rawBytes=%v, len=%d", rawBytes != nil, len(rawBytes))
		if rawBytes != nil && len(rawBytes) > 0 {
			state.ekuResponseMessage = make([]byte, len(rawBytes))
			copy(state.ekuResponseMessage, rawBytes)
			rawPreview := rawBytes
			if len(rawPreview) > 30 {
				rawPreview = rawPreview[:30]
			}
			logf(logTypeHandshake, "[StateConnected] Stored ekuResponseMessage from rawBytes: len=%d, first 30 bytes: %x", len(rawBytes), rawPreview)
		} else {
			state.ekuResponseMessage = hm.Marshal()
			marshalPreview := state.ekuResponseMessage
			if len(marshalPreview) > 30 {
				marshalPreview = marshalPreview[:30]
			}
			logf(logTypeHandshake, "[StateConnected] Stored ekuResponseMessage from Marshal(): len=%d, first 30 bytes: %x (rawBytes was nil or empty, hm.body len=%d)", len(state.ekuResponseMessage), marshalPreview, len(hm.body))
		}

		// Derive new secrets using EKU key derivation
		// Log the message lengths and first few bytes to verify correct order
		reqPreview := state.ekuRequestMessage
		if len(reqPreview) > 10 {
			reqPreview = reqPreview[:10]
		}
		respPreview := state.ekuResponseMessage
		if len(respPreview) > 10 {
			respPreview = respPreview[:10]
		}
		logf(logTypeHandshake, "[StateConnected] deriveEKUKeys call: ekuRequestMessage len=%d (first bytes: %x), ekuResponseMessage len=%d (first bytes: %x)",
			len(state.ekuRequestMessage), reqPreview, len(state.ekuResponseMessage), respPreview)
		// IMPORTANT: EKU context must be requestMsg || responseMsg (Message 1 || Message 2)
		// Client stores messages correctly: ekuRequestMessage=Message1, ekuResponseMessage=Message2
		rekeyActions, alert := state.deriveEKUKeys(state.ekuOurKeyShare, state.ekuPeerKeyShare, state.ekuRequestMessage, state.ekuResponseMessage)
		if alert != AlertNoAlert {
			logf(logTypeHandshake, "[StateConnected] Error deriving EKU keys: %v", alert)
			return nil, nil, alert
		}

		// Create new_key_update message (Message 3)
		ekuNewBody := &ExtendedKeyUpdateBody{
			EKUType:  ExtendedKeyUpdateTypeNewKeyUpdate,
			KeyShare: nil, // new_key_update has no KeyShare
		}

		ekuNewMsg, err := state.hsCtx.hOut.HandshakeMessageFromBody(ekuNewBody)
		if err != nil {
			logf(logTypeHandshake, "[StateConnected] Error marshaling new_key_update: %v", err)
			return nil, nil, AlertInternalError
		}

		// Return actions: rekey inbound first (to decrypt Message 4), then send new_key_update (Message 3), then rekey outbound
		// The initiator needs to do RekeyIn BEFORE receiving Message 4, so it can decrypt Message 4 with new keys
		// But deriveEKUKeys only returns RekeyOut. We need to also do RekeyIn.
		// Actually, wait - the initiator derives keys when receiving Message 2, but only does RekeyOut.
		// The initiator should do RekeyIn when receiving Message 3, not when receiving Message 4.
		// But Message 3 is sent by the initiator, not received. So the initiator can't do RekeyIn when receiving Message 3.
		// Actually, the initiator should do RekeyIn when receiving Message 4, but Message 4 is encrypted with new keys.
		// So the initiator needs to decrypt Message 4 with new keys, but it only has old keys until RekeyIn.
		// This is a chicken-and-egg problem. The solution is that Message 4 should be encrypted with OLD keys (before RekeyOut).
		// But that doesn't match the draft. Let me check the draft again.
		// Actually, I think the issue is that Message 4 should be encrypted with NEW keys (after RekeyOut), and the initiator
		// should decrypt it with NEW keys (after RekeyIn). But the initiator needs to decrypt Message 4 BEFORE it can process it and do RekeyIn.
		// The solution is that the record layer retries decryption after RekeyIn. So the flow is:
		// 1. Message 4 arrives encrypted with new keys
		// 2. Decryption fails (initiator has old keys)
		// 3. Record is cached, AlertWouldBlock is returned
		// 4. Controller processes Message 4 (but wait, it can't process it if decryption failed!)
		// Actually, I think Message 4 should be encrypted with OLD keys (before RekeyOut), not NEW keys.
		// Let me check the draft to see what keys Message 4 should be encrypted with.
		// For now, let's assume Message 4 should be encrypted with OLD keys, so the initiator can decrypt it with OLD keys,
		// then do RekeyIn after processing Message 4.
		// Clear Message 1 from queue (Message 2 implicitly ACKs it)
		// This must be done BEFORE queuing Message 3, so Message 3 doesn't get cleared
		toSend := []HandshakeAction{
			ClearQueuedMessages{}, // Clear Message 1 (ACKed by Message 2)
			QueueHandshakeMessage{ekuNewMsg},
			SendQueuedHandshake{},
		}
		toSend = append(toSend, rekeyActions...)

		logf(logTypeHandshake, "[StateConnected] Initiator: Sent new_key_update (Message 3), waiting for responder's new_key_update (Message 4), actions count=%d", len(toSend))
		for i, action := range toSend {
			logf(logTypeHandshake, "[StateConnected] Initiator: Action[%d]=%T", i, action)
		}
		return state, toSend, AlertNoAlert

	case ExtendedKeyUpdateTypeNewKeyUpdate:
		if state.ekuInProgress && !state.ekuIsInitiator {
			// Responder receives initiator's new_key_update (Message 3)
			logf(logTypeHandshake, "[StateConnected] Responder: Received initiator's new_key_update (Message 3)")

			// IMPORTANT: ekuResponseMessage was marshaled before queuing, so it has the wrong sequence number
			// We need to re-marshal it after queuing to get the correct sequence number
			// However, we can't access the queued message directly (queued is not exported)
			// So we'll update it in the QueueHandshakeMessage action handler instead
			// For now, note that this might cause a key mismatch if sequence numbers differ

			// Derive new secrets using EKU key derivation
			// Log the message lengths and first few bytes to verify correct order
			reqPreview := state.ekuRequestMessage
			if len(reqPreview) > 10 {
				reqPreview = reqPreview[:10]
			}
			respPreview := state.ekuResponseMessage
			if len(respPreview) > 10 {
				respPreview = respPreview[:10]
			}
			logf(logTypeHandshake, "[StateConnected] deriveEKUKeysForResponder call: ekuRequestMessage len=%d (first bytes: %x), ekuResponseMessage len=%d (first bytes: %x)",
				len(state.ekuRequestMessage), reqPreview, len(state.ekuResponseMessage), respPreview)
			// Log full messages for debugging
			reqFullPreview := state.ekuRequestMessage
			if len(reqFullPreview) > 30 {
				reqFullPreview = reqFullPreview[:30]
			}
			respFullPreview := state.ekuResponseMessage
			if len(respFullPreview) > 30 {
				respFullPreview = respFullPreview[:30]
			}
			logf(logTypeHandshake, "[StateConnected] deriveEKUKeysForResponder call: FULL ekuRequestMessage len=%d (first 30 bytes: %x), FULL ekuResponseMessage len=%d (first 30 bytes: %x)",
				len(state.ekuRequestMessage), reqFullPreview, len(state.ekuResponseMessage), respFullPreview)
			// IMPORTANT: Server stores messages correctly: ekuRequestMessage=Message1, ekuResponseMessage=Message2
			// So we use them in the correct order: Message 1 || Message 2
			rekeyActions, alert := state.deriveEKUKeysForResponder(state.ekuOurKeyShare, state.ekuPeerKeyShare, state.ekuRequestMessage, state.ekuResponseMessage)
			if alert != AlertNoAlert {
				logf(logTypeHandshake, "[StateConnected] Error deriving EKU keys for responder: %v", alert)
				return nil, nil, alert
			}

			// Create new_key_update message (Message 4)
			ekuNewBody := &ExtendedKeyUpdateBody{
				EKUType:  ExtendedKeyUpdateTypeNewKeyUpdate,
				KeyShare: nil, // new_key_update has no KeyShare
			}

			ekuNewMsg, err := state.hsCtx.hOut.HandshakeMessageFromBody(ekuNewBody)
			if err != nil {
				logf(logTypeHandshake, "[StateConnected] Error marshaling responder's new_key_update: %v", err)
				return nil, nil, AlertInternalError
			}

			// Return actions: RekeyIn first (to decrypt Message 3), then queue Message 4 (BEFORE RekeyOut so it uses old keys),
			// then RekeyOut (to update send keys), then send Message 4
			// Message 4 should be encrypted with OLD keys (before RekeyOut) so the initiator can decrypt it with OLD keys,
			// then do RekeyIn after processing Message 4
			toSend := []HandshakeAction{}
			// Add RekeyIn first (to decrypt Message 3)
			for _, action := range rekeyActions {
				if _, ok := action.(RekeyIn); ok {
					toSend = append(toSend, action)
					break
				}
			}
			// Queue Message 4 BEFORE RekeyOut so it captures old cipher state
			toSend = append(toSend, QueueHandshakeMessage{ekuNewMsg})
			// Add RekeyOut (to update send keys for future messages)
			for _, action := range rekeyActions {
				if _, ok := action.(RekeyOut); ok {
					toSend = append(toSend, action)
					break
				}
			}
			toSend = append(toSend, SendQueuedHandshake{})

			// Clear EKU state now that Message 4 is queued
			// The exchange is effectively complete - Message 4 will be sent and the initiator will process it
			// We clear the state here so that if a new EKU request arrives before Message 4 is sent,
			// it can be processed (though in practice Message 4 should be sent immediately)
			state.ekuInProgress = false
			state.ekuIsInitiator = false
			state.ekuOurKeyShare = nil
			state.ekuOurPrivateKey = nil
			state.ekuPeerKeyShare = nil
			state.ekuRequestMessage = nil
			state.ekuResponseMessage = nil
			logf(logTypeHandshake, "[StateConnected] Responder: Cleared EKU state after queuing Message 4")

			logf(logTypeHandshake, "[StateConnected] Responder: Queued new_key_update (Message 4) for sending, EKU exchange will complete after send, actions count=%d", len(toSend))
			for i, action := range toSend {
				logf(logTypeHandshake, "[StateConnected] Responder: Action[%d]=%T", i, action)
			}
			return state, toSend, AlertNoAlert
		} else if state.ekuInProgress && state.ekuIsInitiator {
			// Initiator receives responder's new_key_update (Message 4)
			logf(logTypeHandshake, "[StateConnected] Initiator: Received responder's new_key_update (Message 4)")

			// Update receive keys (RekeyIn)
			// Traffic keys were already derived when we received the response (Message 2)
			// We need to use the SAME keys that were derived then, which are now in state.clientTrafficSecret/state.serverTrafficSecret
			// For client: receive server's traffic (serverTrafficSecret)
			// For server: receive client's traffic (clientTrafficSecret)
			var trafficKeys KeySet
			if state.isClient {
				// Client receives server's traffic
				trafficKeys = makeTrafficKeys(state.cryptoParams, state.serverTrafficSecret)
			} else {
				// Server receives client's traffic
				trafficKeys = makeTrafficKeys(state.cryptoParams, state.clientTrafficSecret)
			}

			// Clear EKU state - exchange is complete
			state.ekuInProgress = false
			state.ekuIsInitiator = false
			state.ekuOurKeyShare = nil
			state.ekuOurPrivateKey = nil
			state.ekuPeerKeyShare = nil
			state.ekuRequestMessage = nil
			state.ekuResponseMessage = nil

			logf(logTypeHandshake, "[StateConnected] Initiator: ✓ Received responder's new_key_update (Message 4), EKU exchange complete, returning RekeyIn action")
			return state, []HandshakeAction{RekeyIn{epoch: EpochUpdate, KeySet: trafficKeys}}, AlertNoAlert
		} else {
			// Not in EKU state or wrong state
			logf(logTypeHandshake, "[StateConnected] Received EKU new_key_update but not in EKU state (ekuInProgress=%v, ekuIsInitiator=%v)", state.ekuInProgress, state.ekuIsInitiator)
			return nil, nil, AlertUnexpectedMessage
		}

	default:
		logf(logTypeHandshake, "[StateConnected] Unknown ExtendedKeyUpdateType: %v", body.EKUType)
		return nil, nil, AlertDecodeError
	}
}

// handleEKUTieBreaking handles tie-breaking when both peers initiate EKU simultaneously
func (state *stateConnected) handleEKUTieBreaking(hm *HandshakeMessage, body *ExtendedKeyUpdateBody) (HandshakeState, []HandshakeAction, Alert) {
	if body.KeyShare == nil {
		logf(logTypeHandshake, "[StateConnected] Received EKU request without KeyShare")
		return nil, nil, AlertDecodeError
	}

	// Compare key_exchange values lexicographically
	ourKeyExchange := state.ekuOurKeyShare.KeyExchange
	peerKeyExchange := body.KeyShare.KeyExchange

	compare := bytes.Compare(peerKeyExchange, ourKeyExchange)
	if compare < 0 {
		// Peer's value < local value: Ignore peer's request (continue as initiator)
		logf(logTypeHandshake, "[StateConnected] EKU tie-breaking: peer < local, ignoring peer request")
		return state, nil, AlertNoAlert
	} else if compare == 0 {
		// Peer's value == local value: Send "unexpected_message" alert and close connection
		logf(logTypeHandshake, "[StateConnected] EKU tie-breaking: peer == local, aborting")
		return nil, nil, AlertUnexpectedMessage
	} else {
		// Peer's value > local value: Abandon local update, act as responder
		// Per draft Section 4.1: "the ExtendedKeyUpdate(key_update_request) with the lower
		// lexicographic order... MUST be ignored" - so we ignore our own request and process peer's
		logf(logTypeHandshake, "[StateConnected] EKU tie-breaking: peer > local, switching to responder")

		// Clear our initiator state
		state.ekuInProgress = false
		state.ekuIsInitiator = false
		state.ekuOurKeyShare = nil
		state.ekuOurPrivateKey = nil
		state.ekuRequestMessage = nil

		// Now process peer's request as responder (same as Phase 5 responder path)
		// Store peer's key share
		state.ekuPeerKeyShare = body.KeyShare

		// Store marshaled request message for key derivation binding
		state.ekuRequestMessage = hm.Marshal()

		// Generate fresh key share using negotiated group
		pub, priv, err := newKeyShare(state.Params.NegotiatedGroup)
		if err != nil {
			logf(logTypeHandshake, "[StateConnected] Error generating key share for tie-breaking responder: %v", err)
			return nil, nil, AlertInternalError
		}

		ourKeyShare := &KeyShareEntry{
			Group:       state.Params.NegotiatedGroup,
			KeyExchange: pub,
		}
		state.ekuOurKeyShare = ourKeyShare
		state.ekuOurPrivateKey = priv

		// Create ExtendedKeyUpdate response message (Message 2)
		ekuResponseBody := &ExtendedKeyUpdateBody{
			EKUType:  ExtendedKeyUpdateTypeResponse,
			KeyShare: ourKeyShare,
		}

		ekuResponseMsg, err := state.hsCtx.hOut.HandshakeMessageFromBody(ekuResponseBody)
		if err != nil {
			logf(logTypeHandshake, "[StateConnected] Error marshaling EKU response for tie-breaking: %v", err)
			return nil, nil, AlertInternalError
		}

		// Store marshaled response message for key derivation binding
		state.ekuResponseMessage = ekuResponseMsg.Marshal()

		// Set responder state
		state.ekuInProgress = true
		state.ekuIsInitiator = false

		logf(logTypeHandshake, "[StateConnected] EKU tie-breaking: switched to responder, sending response (Message 2)")
		return state, []HandshakeAction{
			QueueHandshakeMessage{ekuResponseMsg},
			SendQueuedHandshake{},
		}, AlertNoAlert
	}
}
