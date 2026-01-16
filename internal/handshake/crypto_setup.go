package handshake

import (
	"context"
	tls "github.com/sardanioss/utls"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/sardanioss/quic-go/internal/protocol"
	"github.com/sardanioss/quic-go/internal/qerr"
	"github.com/sardanioss/quic-go/internal/utils"
	"github.com/sardanioss/quic-go/internal/wire"
	"github.com/sardanioss/quic-go/qlog"
	"github.com/sardanioss/quic-go/qlogwriter"
	"github.com/sardanioss/quic-go/quicvarint"
	utls "github.com/sardanioss/utls"
)

type quicVersionContextKey struct{}

var QUICVersionContextKey = &quicVersionContextKey{}

const clientSessionStateRevision = 5

// quicConn is an interface for QUIC TLS connections
// Both *tls.QUICConn and *uquicWrapper implement this interface
type quicConn interface {
	Start(ctx context.Context) error
	NextEvent() tls.QUICEvent
	HandleData(level tls.QUICEncryptionLevel, data []byte) error
	SetTransportParameters(params []byte)
	SendSessionTicket(opts tls.QUICSessionTicketOptions) error
	StoreSession(session *tls.SessionState) error
	Close() error
	ConnectionState() tls.ConnectionState
}

// uquicWrapper wraps utls.UQUICConn to implement the quicConn interface
// by converting between utls and standard tls types
type uquicWrapper struct {
	conn *utls.UQUICConn
}

func (w *uquicWrapper) Start(ctx context.Context) error {
	return w.conn.Start(ctx)
}

func (w *uquicWrapper) NextEvent() tls.QUICEvent {
	ev := w.conn.NextEvent()
	return tls.QUICEvent{
		Kind:         tls.QUICEventKind(ev.Kind),
		Level:        tls.QUICEncryptionLevel(ev.Level),
		Data:         ev.Data,
		Suite:        ev.Suite,
		SessionState: ev.SessionState, // Preserve SessionState for QUICStoreSession/QUICResumeSession events
	}
}

func (w *uquicWrapper) HandleData(level tls.QUICEncryptionLevel, data []byte) error {
	return w.conn.HandleData(utls.QUICEncryptionLevel(level), data)
}

func (w *uquicWrapper) SetTransportParameters(params []byte) {
	w.conn.SetTransportParameters(params)
}

func (w *uquicWrapper) SendSessionTicket(opts tls.QUICSessionTicketOptions) error {
	return w.conn.SendSessionTicket(utls.QUICSessionTicketOptions{
		EarlyData: opts.EarlyData,
		Extra:     opts.Extra,
	})
}

func (w *uquicWrapper) StoreSession(session *tls.SessionState) error {
	// tls and utls are both aliased to github.com/sardanioss/utls
	// so *tls.SessionState and *utls.SessionState are the same type
	return w.conn.StoreSession(session)
}

func (w *uquicWrapper) Close() error {
	return w.conn.Close()
}

func (w *uquicWrapper) ConnectionState() tls.ConnectionState {
	ucs := w.conn.ConnectionState()
	return tls.ConnectionState{
		Version:                     ucs.Version,
		HandshakeComplete:           ucs.HandshakeComplete,
		DidResume:                   ucs.DidResume,
		CipherSuite:                 ucs.CipherSuite,
		NegotiatedProtocol:          ucs.NegotiatedProtocol,
		NegotiatedProtocolIsMutual:  ucs.NegotiatedProtocolIsMutual,
		ServerName:                  ucs.ServerName,
		PeerCertificates:            ucs.PeerCertificates,
		VerifiedChains:              ucs.VerifiedChains,
		SignedCertificateTimestamps: ucs.SignedCertificateTimestamps,
		OCSPResponse:                ucs.OCSPResponse,
		TLSUnique:                   ucs.TLSUnique,
		ECHAccepted:                 ucs.ECHAccepted,
	}
}

// tlsConfigToUtls converts tls.Config to utls.Config for uTLS usage
func tlsConfigToUtls(cfg *tls.Config, echConfigList []byte) *utls.Config {
	fmt.Printf("[DEBUG crypto_setup] tlsConfigToUtls: echConfigList len=%d, serverName=%s\n", len(echConfigList), cfg.ServerName)
	ucfg := &utls.Config{
		Rand:                           cfg.Rand,
		Time:                           cfg.Time,
		RootCAs:                        cfg.RootCAs,
		NextProtos:                     cfg.NextProtos,
		ServerName:                     cfg.ServerName,
		InsecureSkipVerify:             cfg.InsecureSkipVerify,
		CipherSuites:                   cfg.CipherSuites,
		SessionTicketsDisabled:         cfg.SessionTicketsDisabled,
		ClientSessionCache:             cfg.ClientSessionCache, // Enable session resumption
		MinVersion:                     cfg.MinVersion,
		MaxVersion:                     cfg.MaxVersion,
		Renegotiation:                  utls.RenegotiationSupport(cfg.Renegotiation),
		OmitEmptyPsk:                   true, // Required for QUIC presets without session resumption
		EncryptedClientHelloConfigList: echConfigList,
	}
	return ucfg
}

type cryptoSetup struct {
	tlsConf *tls.Config
	conn    quicConn

	events []Event

	version protocol.Version

	ourParams  *wire.TransportParameters
	peerParams *wire.TransportParameters

	zeroRTTParameters *wire.TransportParameters
	allow0RTT         bool

	rttStats *utils.RTTStats

	qlogger qlogwriter.Recorder
	logger  utils.Logger

	perspective protocol.Perspective

	handshakeCompleteTime time.Time

	zeroRTTOpener LongHeaderOpener // only set for the server
	zeroRTTSealer LongHeaderSealer // only set for the client

	initialOpener LongHeaderOpener
	initialSealer LongHeaderSealer

	handshakeOpener LongHeaderOpener
	handshakeSealer LongHeaderSealer

	used0RTT atomic.Bool

	aead          *updatableAEAD
	has1RTTSealer bool
	has1RTTOpener bool
}

var _ CryptoSetup = &cryptoSetup{}

// NewCryptoSetupClient creates a new crypto setup for the client
// If cachedClientHelloSpec is non-nil, it is used for TLS fingerprinting (preserves shuffled extension order).
// If clientHelloID is non-nil (and cachedClientHelloSpec is nil), uTLS is used with that ID.
func NewCryptoSetupClient(
	connID protocol.ConnectionID,
	tp *wire.TransportParameters,
	tlsConf *tls.Config,
	enable0RTT bool,
	rttStats *utils.RTTStats,
	qlogger qlogwriter.Recorder,
	logger utils.Logger,
	version protocol.Version,
	clientHelloID *utls.ClientHelloID,
	cachedClientHelloSpec *utls.ClientHelloSpec,
	echConfigList []byte,
) CryptoSetup {
	fmt.Printf("[DEBUG crypto_setup] NewCryptoSetupClient: cachedSpec=%v, clientHelloID=%v, echConfigList len=%d\n",
		cachedClientHelloSpec != nil, clientHelloID != nil, len(echConfigList))
	cs := newCryptoSetup(
		connID,
		tp,
		rttStats,
		qlogger,
		logger,
		protocol.PerspectiveClient,
		version,
	)

	tlsConf = tlsConf.Clone()
	tlsConf.MinVersion = tls.VersionTLS13
	cs.tlsConf = tlsConf
	cs.allow0RTT = enable0RTT

	if cachedClientHelloSpec != nil {
		// Use the cached spec directly (ApplyPreset does shallow copy internally)
		// This ensures ALL extensions including GREASE are shared across connections
		// KeyShare keys will still be regenerated by utls during handshake
		utlsConf := tlsConfigToUtls(tlsConf, echConfigList)

		uconn := utls.UQUICClient(&utls.QUICConfig{
			TLSConfig:           utlsConf,
			EnableSessionEvents: true,
		}, utls.HelloCustom)

		// Check if GREASESeed is empty (first connection)
		greaseSeedEmpty := true
		for _, v := range cachedClientHelloSpec.GREASESeed {
			if v != 0 {
				greaseSeedEmpty = false
				break
			}
		}

		// Apply cached spec directly - utls will handle key regeneration internally
		if err := uconn.ApplyPreset(cachedClientHelloSpec); err != nil {
			// Fallback to clientHelloID if ApplyPreset fails
			if clientHelloID != nil {
				uconn = utls.UQUICClient(&utls.QUICConfig{
					TLSConfig:           utlsConf,
					EnableSessionEvents: true,
				}, *clientHelloID)
			}
		} else if greaseSeedEmpty {
			// After first ApplyPreset, capture the generated GREASE seed
			// and store it in the cached spec for subsequent connections
			cachedClientHelloSpec.GREASESeed = uconn.GetGREASESeed()
		}
		cs.conn = &uquicWrapper{conn: uconn}
	} else if clientHelloID != nil {
		// Use uTLS UQUICClient for TLS fingerprinting (no cached spec)
		utlsConf := tlsConfigToUtls(tlsConf, echConfigList)
		uconn := utls.UQUICClient(&utls.QUICConfig{
			TLSConfig:           utlsConf,
			EnableSessionEvents: true,
		}, *clientHelloID)
		cs.conn = &uquicWrapper{conn: uconn}
	} else {
		// Use standard crypto/tls QUICClient
		cs.conn = tls.QUICClient(&tls.QUICConfig{
			TLSConfig:           tlsConf,
			EnableSessionEvents: true,
		})
	}
	cs.conn.SetTransportParameters(cs.ourParams.Marshal(protocol.PerspectiveClient))

	return cs
}

// NewCryptoSetupServer creates a new crypto setup for the server
func NewCryptoSetupServer(
	connID protocol.ConnectionID,
	localAddr, remoteAddr net.Addr,
	tp *wire.TransportParameters,
	tlsConf *tls.Config,
	allow0RTT bool,
	rttStats *utils.RTTStats,
	qlogger qlogwriter.Recorder,
	logger utils.Logger,
	version protocol.Version,
) CryptoSetup {
	cs := newCryptoSetup(
		connID,
		tp,
		rttStats,
		qlogger,
		logger,
		protocol.PerspectiveServer,
		version,
	)
	cs.allow0RTT = allow0RTT

	tlsConf = setupConfigForServer(tlsConf, localAddr, remoteAddr)

	cs.tlsConf = tlsConf
	cs.conn = tls.QUICServer(&tls.QUICConfig{
		TLSConfig:           tlsConf,
		EnableSessionEvents: true,
	})
	return cs
}

func newCryptoSetup(
	connID protocol.ConnectionID,
	tp *wire.TransportParameters,
	rttStats *utils.RTTStats,
	qlogger qlogwriter.Recorder,
	logger utils.Logger,
	perspective protocol.Perspective,
	version protocol.Version,
) *cryptoSetup {
	initialSealer, initialOpener := NewInitialAEAD(connID, perspective, version)
	if qlogger != nil {
		qlogger.RecordEvent(qlog.KeyUpdated{
			Trigger: qlog.KeyUpdateTLS,
			KeyType: encLevelToKeyType(protocol.EncryptionInitial, protocol.PerspectiveClient),
		})
		qlogger.RecordEvent(qlog.KeyUpdated{
			Trigger: qlog.KeyUpdateTLS,
			KeyType: encLevelToKeyType(protocol.EncryptionInitial, protocol.PerspectiveServer),
		})
	}
	return &cryptoSetup{
		initialSealer: initialSealer,
		initialOpener: initialOpener,
		aead:          newUpdatableAEAD(rttStats, qlogger, logger, version),
		events:        make([]Event, 0, 16),
		ourParams:     tp,
		rttStats:      rttStats,
		qlogger:       qlogger,
		logger:        logger,
		perspective:   perspective,
		version:       version,
	}
}

func (h *cryptoSetup) ChangeConnectionID(id protocol.ConnectionID) {
	initialSealer, initialOpener := NewInitialAEAD(id, h.perspective, h.version)
	h.initialSealer = initialSealer
	h.initialOpener = initialOpener
	if h.qlogger != nil {
		h.qlogger.RecordEvent(qlog.KeyUpdated{
			Trigger: qlog.KeyUpdateTLS,
			KeyType: encLevelToKeyType(protocol.EncryptionInitial, protocol.PerspectiveClient),
		})
		h.qlogger.RecordEvent(qlog.KeyUpdated{
			Trigger: qlog.KeyUpdateTLS,
			KeyType: encLevelToKeyType(protocol.EncryptionInitial, protocol.PerspectiveServer),
		})
	}
}

func (h *cryptoSetup) SetLargest1RTTAcked(pn protocol.PacketNumber) error {
	return h.aead.SetLargestAcked(pn)
}

func (h *cryptoSetup) StartHandshake(ctx context.Context) error {
	err := h.conn.Start(context.WithValue(ctx, QUICVersionContextKey, h.version))
	if err != nil {
		return wrapError(err)
	}
	for {
		ev := h.conn.NextEvent()
		if err := h.handleEvent(ev); err != nil {
			return wrapError(err)
		}
		if ev.Kind == tls.QUICNoEvent {
			break
		}
	}
	if h.perspective == protocol.PerspectiveClient {
		if h.zeroRTTSealer != nil && h.zeroRTTParameters != nil {
			fmt.Printf("[DEBUG 0RTT] Doing 0-RTT! zeroRTTSealer=%v, zeroRTTParameters=%v\n", h.zeroRTTSealer != nil, h.zeroRTTParameters != nil)
			h.logger.Debugf("Doing 0-RTT.")
			h.events = append(h.events, Event{Kind: EventRestoredTransportParameters, TransportParameters: h.zeroRTTParameters})
		} else {
			fmt.Printf("[DEBUG 0RTT] Not doing 0-RTT. Has sealer: %t, has params: %t\n", h.zeroRTTSealer != nil, h.zeroRTTParameters != nil)
			h.logger.Debugf("Not doing 0-RTT. Has sealer: %t, has params: %t", h.zeroRTTSealer != nil, h.zeroRTTParameters != nil)
		}
	}
	return nil
}

// Close closes the crypto setup.
// It aborts the handshake, if it is still running.
func (h *cryptoSetup) Close() error {
	return h.conn.Close()
}

// HandleMessage handles a TLS handshake message.
// It is called by the crypto streams when a new message is available.
func (h *cryptoSetup) HandleMessage(data []byte, encLevel protocol.EncryptionLevel) error {
	if err := h.handleMessage(data, encLevel); err != nil {
		return wrapError(err)
	}
	return nil
}

func (h *cryptoSetup) handleMessage(data []byte, encLevel protocol.EncryptionLevel) error {
	if err := h.conn.HandleData(encLevel.ToTLSEncryptionLevel(), data); err != nil {
		return err
	}
	for {
		ev := h.conn.NextEvent()
		if err := h.handleEvent(ev); err != nil {
			return err
		}
		if ev.Kind == tls.QUICNoEvent {
			return nil
		}
	}
}

func (h *cryptoSetup) handleEvent(ev tls.QUICEvent) (err error) {
	fmt.Printf("[DEBUG quic] handleEvent: kind=%d\n", ev.Kind)
	switch ev.Kind {
	case tls.QUICNoEvent:
		return nil
	case tls.QUICSetReadSecret:
		h.setReadKey(ev.Level, ev.Suite, ev.Data)
		return nil
	case tls.QUICSetWriteSecret:
		h.setWriteKey(ev.Level, ev.Suite, ev.Data)
		return nil
	case tls.QUICTransportParameters:
		return h.handleTransportParameters(ev.Data)
	case tls.QUICTransportParametersRequired:
		h.conn.SetTransportParameters(h.ourParams.Marshal(h.perspective))
		return nil
	case tls.QUICRejectedEarlyData:
		h.rejected0RTT()
		return nil
	case tls.QUICWriteData:
		h.writeRecord(ev.Level, ev.Data)
		return nil
	case tls.QUICHandshakeDone:
		h.handshakeComplete()
		return nil
	case tls.QUICStoreSession:
		if ev.SessionState == nil {
			fmt.Printf("[DEBUG quic] QUICStoreSession event received, but SessionState is nil!\n")
			return nil
		}
		fmt.Printf("[DEBUG quic] QUICStoreSession event received, earlyData=%v\n", ev.SessionState.EarlyData)
		if h.perspective == protocol.PerspectiveServer {
			panic("cryptoSetup BUG: unexpected QUICStoreSession event for the server")
		}
		ev.SessionState.Extra = append(
			ev.SessionState.Extra,
			addSessionStateExtraPrefix(h.marshalDataForSessionState(ev.SessionState.EarlyData)),
		)
		return h.conn.StoreSession(ev.SessionState)
	case tls.QUICResumeSession:
		fmt.Printf("[DEBUG quic] QUICResumeSession event received, earlyData=%v\n", ev.SessionState.EarlyData)
		var allowEarlyData bool
		switch h.perspective {
		case protocol.PerspectiveClient:
			// for clients, this event occurs when a session ticket is selected
			allowEarlyData = h.handleDataFromSessionState(
				findSessionStateExtraData(ev.SessionState.Extra),
				ev.SessionState.EarlyData,
			)
		case protocol.PerspectiveServer:
			// for servers, this event occurs when receiving the client's session ticket
			allowEarlyData = h.handleSessionTicket(
				findSessionStateExtraData(ev.SessionState.Extra),
				ev.SessionState.EarlyData,
			)
		}
		if ev.SessionState.EarlyData {
			ev.SessionState.EarlyData = allowEarlyData
		}
		return nil
	default:
		// Unknown events should be ignored.
		// crypto/tls will ensure that this is safe to do.
		// See the discussion following https://github.com/golang/go/issues/68124#issuecomment-2187042510 for details.
		return nil
	}
}

func (h *cryptoSetup) NextEvent() Event {
	if len(h.events) == 0 {
		return Event{Kind: EventNoEvent}
	}
	ev := h.events[0]
	h.events = h.events[1:]
	return ev
}

func (h *cryptoSetup) handleTransportParameters(data []byte) error {
	var tp wire.TransportParameters
	if err := tp.Unmarshal(data, h.perspective.Opposite()); err != nil {
		return err
	}
	h.peerParams = &tp
	h.events = append(h.events, Event{Kind: EventReceivedTransportParameters, TransportParameters: h.peerParams})
	return nil
}

// must be called after receiving the transport parameters
func (h *cryptoSetup) marshalDataForSessionState(earlyData bool) []byte {
	b := make([]byte, 0, 256)
	b = quicvarint.Append(b, clientSessionStateRevision)
	if earlyData {
		// only save the transport parameters for 0-RTT enabled session tickets
		return h.peerParams.MarshalForSessionTicket(b)
	}
	return b
}

func (h *cryptoSetup) handleDataFromSessionState(data []byte, earlyData bool) (allowEarlyData bool) {
	fmt.Printf("[DEBUG 0RTT] handleDataFromSessionState: earlyData=%v, allow0RTT=%v, data_len=%d\n", earlyData, h.allow0RTT, len(data))
	tp, err := decodeDataFromSessionState(data, earlyData)
	if err != nil {
		fmt.Printf("[DEBUG 0RTT] decodeDataFromSessionState failed: %v\n", err)
		h.logger.Debugf("Restoring of transport parameters from session ticket failed: %s", err.Error())
		return
	}
	fmt.Printf("[DEBUG 0RTT] decodeDataFromSessionState: tp=%v\n", tp != nil)
	// The session ticket might have been saved from a connection that allowed 0-RTT,
	// and therefore contain transport parameters.
	// Only use them if 0-RTT is actually used on the new connection.
	if tp != nil && h.allow0RTT {
		h.zeroRTTParameters = tp
		fmt.Printf("[DEBUG 0RTT] Setting zeroRTTParameters, returning true\n")
		return true
	}
	fmt.Printf("[DEBUG 0RTT] NOT setting zeroRTTParameters: tp=%v, allow0RTT=%v\n", tp != nil, h.allow0RTT)
	return false
}

func decodeDataFromSessionState(b []byte, earlyData bool) (*wire.TransportParameters, error) {
	ver, l, err := quicvarint.Parse(b)
	if err != nil {
		return nil, err
	}
	b = b[l:]
	if ver != clientSessionStateRevision {
		return nil, fmt.Errorf("mismatching version. Got %d, expected %d", ver, clientSessionStateRevision)
	}
	if !earlyData {
		return nil, nil
	}
	var tp wire.TransportParameters
	if err := tp.UnmarshalFromSessionTicket(b); err != nil {
		return nil, err
	}
	return &tp, nil
}

func (h *cryptoSetup) getDataForSessionTicket() []byte {
	return (&sessionTicket{
		Parameters: h.ourParams,
	}).Marshal()
}

// GetSessionTicket generates a new session ticket.
// Due to limitations in crypto/tls, it's only possible to generate a single session ticket per connection.
// It is only valid for the server.
func (h *cryptoSetup) GetSessionTicket() ([]byte, error) {
	if err := h.conn.SendSessionTicket(tls.QUICSessionTicketOptions{
		EarlyData: h.allow0RTT,
		Extra:     [][]byte{addSessionStateExtraPrefix(h.getDataForSessionTicket())},
	}); err != nil {
		// Session tickets might be disabled by tls.Config.SessionTicketsDisabled.
		// We can't check h.tlsConfig here, since the actual config might have been obtained from
		// the GetConfigForClient callback.
		// See https://github.com/golang/go/issues/62032.
		// This error assertion can be removed once we drop support for Go 1.25.
		if strings.Contains(err.Error(), "session ticket keys unavailable") {
			return nil, nil
		}
		return nil, err
	}
	// If session tickets are disabled, NextEvent will immediately return QUICNoEvent,
	// and we will return a nil ticket.
	var ticket []byte
	for {
		ev := h.conn.NextEvent()
		if ev.Kind == tls.QUICNoEvent {
			break
		}
		if ev.Kind == tls.QUICWriteData && ev.Level == tls.QUICEncryptionLevelApplication {
			if ticket != nil {
				h.logger.Errorf("unexpected multiple session tickets")
				continue
			}
			ticket = ev.Data
		} else {
			h.logger.Errorf("unexpected event: %v", ev.Kind)
		}
	}
	return ticket, nil
}

// handleSessionTicket is called for the server when receiving the client's session ticket.
// It reads parameters from the session ticket and checks whether to accept 0-RTT if the session ticket enabled 0-RTT.
// Note that the fact that the session ticket allows 0-RTT doesn't mean that the actual TLS handshake enables 0-RTT:
// A client may use a 0-RTT enabled session to resume a TLS session without using 0-RTT.
func (h *cryptoSetup) handleSessionTicket(data []byte, using0RTT bool) (allowEarlyData bool) {
	var t sessionTicket
	if err := t.Unmarshal(data); err != nil {
		h.logger.Debugf("Unmarshalling session ticket failed: %s", err.Error())
		return false
	}
	if !using0RTT {
		return false
	}
	valid := h.ourParams.ValidFor0RTT(t.Parameters)
	if !valid {
		h.logger.Debugf("Transport parameters changed. Rejecting 0-RTT.")
		return false
	}
	if !h.allow0RTT {
		h.logger.Debugf("0-RTT not allowed. Rejecting 0-RTT.")
		return false
	}
	return true
}

// rejected0RTT is called for the client when the server rejects 0-RTT.
func (h *cryptoSetup) rejected0RTT() {
	h.logger.Debugf("0-RTT was rejected. Dropping 0-RTT keys.")

	had0RTTKeys := h.zeroRTTSealer != nil
	h.zeroRTTSealer = nil

	if had0RTTKeys {
		h.events = append(h.events, Event{Kind: EventDiscard0RTTKeys})
	}
}

func (h *cryptoSetup) setReadKey(el tls.QUICEncryptionLevel, suiteID uint16, trafficSecret []byte) {
	suite := getCipherSuite(suiteID)
	//nolint:exhaustive // The TLS stack doesn't export Initial keys.
	switch el {
	case tls.QUICEncryptionLevelEarly:
		if h.perspective == protocol.PerspectiveClient {
			panic("Received 0-RTT read key for the client")
		}
		h.zeroRTTOpener = newLongHeaderOpener(
			createAEAD(suite, trafficSecret, h.version),
			newHeaderProtector(suite, trafficSecret, true, h.version),
		)
		h.used0RTT.Store(true)
		if h.logger.Debug() {
			h.logger.Debugf("Installed 0-RTT Read keys (using %s)", tls.CipherSuiteName(suite.ID))
		}
	case tls.QUICEncryptionLevelHandshake:
		h.handshakeOpener = newLongHeaderOpener(
			createAEAD(suite, trafficSecret, h.version),
			newHeaderProtector(suite, trafficSecret, true, h.version),
		)
		if h.logger.Debug() {
			h.logger.Debugf("Installed Handshake Read keys (using %s)", tls.CipherSuiteName(suite.ID))
		}
	case tls.QUICEncryptionLevelApplication:
		h.aead.SetReadKey(suite, trafficSecret)
		h.has1RTTOpener = true
		if h.logger.Debug() {
			h.logger.Debugf("Installed 1-RTT Read keys (using %s)", tls.CipherSuiteName(suite.ID))
		}
	default:
		panic("unexpected read encryption level")
	}
	h.events = append(h.events, Event{Kind: EventReceivedReadKeys})
	if h.qlogger != nil {
		h.qlogger.RecordEvent(qlog.KeyUpdated{
			Trigger: qlog.KeyUpdateTLS,
			KeyType: encLevelToKeyType(protocol.FromTLSEncryptionLevel(el), h.perspective.Opposite()),
		})
	}
}

func (h *cryptoSetup) setWriteKey(el tls.QUICEncryptionLevel, suiteID uint16, trafficSecret []byte) {
	fmt.Printf("[DEBUG 0RTT] setWriteKey: level=%d, suiteID=%d\n", el, suiteID)
	suite := getCipherSuite(suiteID)
	//nolint:exhaustive // The TLS stack doesn't export Initial keys.
	switch el {
	case tls.QUICEncryptionLevelEarly:
		fmt.Printf("[DEBUG 0RTT] Setting 0-RTT write key!\n")
		if h.perspective == protocol.PerspectiveServer {
			panic("Received 0-RTT write key for the server")
		}
		h.zeroRTTSealer = newLongHeaderSealer(
			createAEAD(suite, trafficSecret, h.version),
			newHeaderProtector(suite, trafficSecret, true, h.version),
		)
		fmt.Printf("[DEBUG 0RTT] zeroRTTSealer created: %v\n", h.zeroRTTSealer != nil)
		if h.logger.Debug() {
			h.logger.Debugf("Installed 0-RTT Write keys (using %s)", tls.CipherSuiteName(suite.ID))
		}
		if h.qlogger != nil {
			h.qlogger.RecordEvent(qlog.KeyUpdated{
				Trigger: qlog.KeyUpdateTLS,
				KeyType: encLevelToKeyType(protocol.Encryption0RTT, h.perspective),
			})
		}
		// don't set used0RTT here. 0-RTT might still get rejected.
		return
	case tls.QUICEncryptionLevelHandshake:
		h.handshakeSealer = newLongHeaderSealer(
			createAEAD(suite, trafficSecret, h.version),
			newHeaderProtector(suite, trafficSecret, true, h.version),
		)
		if h.logger.Debug() {
			h.logger.Debugf("Installed Handshake Write keys (using %s)", tls.CipherSuiteName(suite.ID))
		}
	case tls.QUICEncryptionLevelApplication:
		h.aead.SetWriteKey(suite, trafficSecret)
		h.has1RTTSealer = true
		if h.logger.Debug() {
			h.logger.Debugf("Installed 1-RTT Write keys (using %s)", tls.CipherSuiteName(suite.ID))
		}
		if h.zeroRTTSealer != nil {
			// Once we receive handshake keys, we know that 0-RTT was not rejected.
			h.used0RTT.Store(true)
			h.zeroRTTSealer = nil
			h.logger.Debugf("Dropping 0-RTT keys.")
			if h.qlogger != nil {
				h.qlogger.RecordEvent(qlog.KeyDiscarded{KeyType: qlog.KeyTypeClient0RTT})
			}
		}
	default:
		panic("unexpected write encryption level")
	}
	if h.qlogger != nil {
		h.qlogger.RecordEvent(qlog.KeyUpdated{
			Trigger: qlog.KeyUpdateTLS,
			KeyType: encLevelToKeyType(protocol.FromTLSEncryptionLevel(el), h.perspective),
		})
	}
}

// writeRecord is called when TLS writes data
func (h *cryptoSetup) writeRecord(encLevel tls.QUICEncryptionLevel, p []byte) {
	//nolint:exhaustive // handshake records can only be written for Initial and Handshake.
	switch encLevel {
	case tls.QUICEncryptionLevelInitial:
		h.events = append(h.events, Event{Kind: EventWriteInitialData, Data: p})
	case tls.QUICEncryptionLevelHandshake:
		h.events = append(h.events, Event{Kind: EventWriteHandshakeData, Data: p})
	case tls.QUICEncryptionLevelApplication:
		panic("unexpected write")
	default:
		panic(fmt.Sprintf("unexpected write encryption level: %s", encLevel))
	}
}

func (h *cryptoSetup) DiscardInitialKeys() {
	dropped := h.initialOpener != nil
	h.initialOpener = nil
	h.initialSealer = nil
	if dropped {
		h.logger.Debugf("Dropping Initial keys.")
		if h.qlogger != nil {
			h.qlogger.RecordEvent(qlog.KeyDiscarded{KeyType: qlog.KeyTypeClientInitial})
			h.qlogger.RecordEvent(qlog.KeyDiscarded{KeyType: qlog.KeyTypeServerInitial})
		}
	}
}

func (h *cryptoSetup) handshakeComplete() {
	h.handshakeCompleteTime = time.Now()
	h.events = append(h.events, Event{Kind: EventHandshakeComplete})
}

func (h *cryptoSetup) SetHandshakeConfirmed() {
	h.aead.SetHandshakeConfirmed()
	// drop Handshake keys
	var dropped bool
	if h.handshakeOpener != nil {
		h.handshakeOpener = nil
		h.handshakeSealer = nil
		dropped = true
	}
	if dropped {
		h.logger.Debugf("Dropping Handshake keys.")
		if h.qlogger != nil {
			h.qlogger.RecordEvent(qlog.KeyDiscarded{KeyType: qlog.KeyTypeClientHandshake})
			h.qlogger.RecordEvent(qlog.KeyDiscarded{KeyType: qlog.KeyTypeServerHandshake})
		}
	}
}

func (h *cryptoSetup) GetInitialSealer() (LongHeaderSealer, error) {
	if h.initialSealer == nil {
		return nil, ErrKeysDropped
	}
	return h.initialSealer, nil
}

func (h *cryptoSetup) Get0RTTSealer() (LongHeaderSealer, error) {
	if h.zeroRTTSealer == nil {
		return nil, ErrKeysDropped
	}
	return h.zeroRTTSealer, nil
}

func (h *cryptoSetup) GetHandshakeSealer() (LongHeaderSealer, error) {
	if h.handshakeSealer == nil {
		if h.initialSealer == nil {
			return nil, ErrKeysDropped
		}
		return nil, ErrKeysNotYetAvailable
	}
	return h.handshakeSealer, nil
}

func (h *cryptoSetup) Get1RTTSealer() (ShortHeaderSealer, error) {
	if !h.has1RTTSealer {
		return nil, ErrKeysNotYetAvailable
	}
	return h.aead, nil
}

func (h *cryptoSetup) GetInitialOpener() (LongHeaderOpener, error) {
	if h.initialOpener == nil {
		return nil, ErrKeysDropped
	}
	return h.initialOpener, nil
}

func (h *cryptoSetup) Get0RTTOpener() (LongHeaderOpener, error) {
	if h.zeroRTTOpener == nil {
		if h.initialOpener != nil {
			return nil, ErrKeysNotYetAvailable
		}
		// if the initial opener is also not available, the keys were already dropped
		return nil, ErrKeysDropped
	}
	return h.zeroRTTOpener, nil
}

func (h *cryptoSetup) GetHandshakeOpener() (LongHeaderOpener, error) {
	if h.handshakeOpener == nil {
		if h.initialOpener != nil {
			return nil, ErrKeysNotYetAvailable
		}
		// if the initial opener is also not available, the keys were already dropped
		return nil, ErrKeysDropped
	}
	return h.handshakeOpener, nil
}

func (h *cryptoSetup) Get1RTTOpener() (ShortHeaderOpener, error) {
	if h.zeroRTTOpener != nil && time.Since(h.handshakeCompleteTime) > 3*h.rttStats.PTO(true) {
		h.zeroRTTOpener = nil
		h.logger.Debugf("Dropping 0-RTT keys.")
		if h.qlogger != nil {
			h.qlogger.RecordEvent(qlog.KeyDiscarded{KeyType: qlog.KeyTypeClient0RTT})
		}
	}

	if !h.has1RTTOpener {
		return nil, ErrKeysNotYetAvailable
	}
	return h.aead, nil
}

func (h *cryptoSetup) ConnectionState() ConnectionState {
	return ConnectionState{
		ConnectionState: h.conn.ConnectionState(),
		Used0RTT:        h.used0RTT.Load(),
	}
}

func wrapError(err error) error {
	if alertErr := tls.AlertError(0); errors.As(err, &alertErr) {
		return qerr.NewLocalCryptoError(uint8(alertErr), err)
	}
	return &qerr.TransportError{ErrorCode: qerr.InternalError, ErrorMessage: err.Error()}
}

// getExtensionTypeID returns a unique identifier for a TLS extension type.
// This is used to match extensions between specs for reordering.
func getExtensionTypeID(ext utls.TLSExtension) string {
	switch ext.(type) {
	case *utls.SNIExtension:
		return "SNI"
	case *utls.StatusRequestExtension:
		return "StatusRequest"
	case *utls.SupportedCurvesExtension:
		return "SupportedCurves"
	case *utls.SupportedPointsExtension:
		return "SupportedPoints"
	case *utls.SignatureAlgorithmsExtension:
		return "SignatureAlgorithms"
	case *utls.SignatureAlgorithmsCertExtension:
		return "SignatureAlgorithmsCert"
	case *utls.ALPNExtension:
		return "ALPN"
	case *utls.ApplicationSettingsExtension:
		return "ApplicationSettings"
	case *utls.ApplicationSettingsExtensionNew:
		return "ApplicationSettingsNew"
	case *utls.SCTExtension:
		return "SCT"
	case *utls.ExtendedMasterSecretExtension:
		return "ExtendedMasterSecret"
	case *utls.RenegotiationInfoExtension:
		return "RenegotiationInfo"
	case *utls.KeyShareExtension:
		return "KeyShare"
	case *utls.PSKKeyExchangeModesExtension:
		return "PSKKeyExchangeModes"
	case *utls.SupportedVersionsExtension:
		return "SupportedVersions"
	case *utls.UtlsCompressCertExtension:
		return "CompressCert"
	case *utls.QUICTransportParametersExtension:
		return "QUICTransportParameters"
	case *utls.GREASEEncryptedClientHelloExtension:
		return "GREASEECH"
	case *utls.UtlsGREASEExtension:
		return "GREASE"
	case *utls.UtlsPaddingExtension:
		return "Padding"
	case *utls.GenericExtension:
		e := ext.(*utls.GenericExtension)
		return fmt.Sprintf("Generic_%d", e.Id)
	default:
		return fmt.Sprintf("Unknown_%T", ext)
	}
}

// reorderExtensions reorders freshSpec's extensions to match the order in cachedSpec.
// For extensions with random state (like GREASE ECH), we use the cached version
// to maintain fingerprint consistency. For extensions with crypto state (like KeyShare),
// we use the fresh version so keys get regenerated.
func reorderExtensions(freshSpec, cachedSpec *utls.ClientHelloSpec) {
	if freshSpec == nil || cachedSpec == nil {
		return
	}

	// Build a map from extension type to extension in freshSpec
	freshExtMap := make(map[string]utls.TLSExtension)
	for _, ext := range freshSpec.Extensions {
		typeID := getExtensionTypeID(ext)
		freshExtMap[typeID] = ext
	}

	// Build the reordered extension list based on cachedSpec's order
	reordered := make([]utls.TLSExtension, 0, len(cachedSpec.Extensions))
	for _, cachedExt := range cachedSpec.Extensions {
		typeID := getExtensionTypeID(cachedExt)

		// For extensions with random state that affects fingerprint,
		// use the cached version to maintain consistency
		switch cachedExt.(type) {
		case *utls.GREASEEncryptedClientHelloExtension:
			// GREASE ECH has random payload - use cached to keep fingerprint consistent
			reordered = append(reordered, cachedExt)
			delete(freshExtMap, typeID)
			continue
		}

		// For other extensions, use fresh version (especially KeyShare for fresh keys)
		if freshExt, ok := freshExtMap[typeID]; ok {
			reordered = append(reordered, freshExt)
			delete(freshExtMap, typeID)
		}
	}

	// Add any remaining extensions from freshSpec that weren't in cachedSpec
	for _, ext := range freshSpec.Extensions {
		typeID := getExtensionTypeID(ext)
		if _, ok := freshExtMap[typeID]; ok {
			reordered = append(reordered, ext)
		}
	}

	freshSpec.Extensions = reordered
}

// copyClientHelloSpec creates a deep copy of a ClientHelloSpec to avoid state corruption
// when reusing a cached spec across multiple connections.
// The key issue is that ApplyPreset modifies extensions in place (shallow copy),
// which corrupts the original spec's extensions (especially KeyShareExtension).
func copyClientHelloSpec(spec *utls.ClientHelloSpec) *utls.ClientHelloSpec {
	if spec == nil {
		return nil
	}

	// Create new spec with copied primitive fields
	newSpec := &utls.ClientHelloSpec{
		TLSVersMin:   spec.TLSVersMin,
		TLSVersMax:   spec.TLSVersMax,
		GetSessionID: spec.GetSessionID,
	}

	// Deep copy CipherSuites
	if spec.CipherSuites != nil {
		newSpec.CipherSuites = make([]uint16, len(spec.CipherSuites))
		copy(newSpec.CipherSuites, spec.CipherSuites)
	}

	// Deep copy CompressionMethods
	if spec.CompressionMethods != nil {
		newSpec.CompressionMethods = make([]uint8, len(spec.CompressionMethods))
		copy(newSpec.CompressionMethods, spec.CompressionMethods)
	}

	// Deep copy Extensions - this is the critical part
	// We need to create fresh extension instances to avoid shared state
	if spec.Extensions != nil {
		newSpec.Extensions = make([]utls.TLSExtension, len(spec.Extensions))
		for i, ext := range spec.Extensions {
			newSpec.Extensions[i] = copyExtension(ext)
		}
	}

	return newSpec
}

// copyExtension creates a copy of a TLS extension with reset mutable state
func copyExtension(ext utls.TLSExtension) utls.TLSExtension {
	switch e := ext.(type) {
	case *utls.KeyShareExtension:
		// KeyShareExtension has mutable Data that must be reset for key regeneration
		newKeyShares := make([]utls.KeyShare, len(e.KeyShares))
		for i, ks := range e.KeyShares {
			newKeyShares[i] = utls.KeyShare{
				Group: ks.Group,
				Data:  nil, // Reset to nil so ApplyPreset regenerates keys
			}
		}
		return &utls.KeyShareExtension{KeyShares: newKeyShares}

	case *utls.SNIExtension:
		return &utls.SNIExtension{ServerName: e.ServerName}

	case *utls.SupportedCurvesExtension:
		curves := make([]utls.CurveID, len(e.Curves))
		copy(curves, e.Curves)
		return &utls.SupportedCurvesExtension{Curves: curves}

	case *utls.SupportedPointsExtension:
		formats := make([]uint8, len(e.SupportedPoints))
		copy(formats, e.SupportedPoints)
		return &utls.SupportedPointsExtension{SupportedPoints: formats}

	case *utls.SignatureAlgorithmsExtension:
		algos := make([]utls.SignatureScheme, len(e.SupportedSignatureAlgorithms))
		copy(algos, e.SupportedSignatureAlgorithms)
		return &utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: algos}

	case *utls.SignatureAlgorithmsCertExtension:
		algos := make([]utls.SignatureScheme, len(e.SupportedSignatureAlgorithms))
		copy(algos, e.SupportedSignatureAlgorithms)
		return &utls.SignatureAlgorithmsCertExtension{SupportedSignatureAlgorithms: algos}

	case *utls.ALPNExtension:
		protos := make([]string, len(e.AlpnProtocols))
		copy(protos, e.AlpnProtocols)
		return &utls.ALPNExtension{AlpnProtocols: protos}

	case *utls.SupportedVersionsExtension:
		versions := make([]uint16, len(e.Versions))
		copy(versions, e.Versions)
		return &utls.SupportedVersionsExtension{Versions: versions}

	case *utls.PSKKeyExchangeModesExtension:
		modes := make([]uint8, len(e.Modes))
		copy(modes, e.Modes)
		return &utls.PSKKeyExchangeModesExtension{Modes: modes}

	case *utls.QUICTransportParametersExtension:
		// For QUIC, the transport params will be set by SetTransportParameters
		// We just need to preserve the extension type with empty data
		return &utls.QUICTransportParametersExtension{}

	case *utls.UtlsGREASEExtension:
		// GREASE extension - return the same object to preserve Value and any Body
		// Value is the GREASE ID (e.g., 0x0a0a) which is part of the fingerprint
		return e

	case *utls.UtlsPaddingExtension:
		return &utls.UtlsPaddingExtension{
			GetPaddingLen: e.GetPaddingLen,
			WillPad:       e.WillPad,
			PaddingLen:    e.PaddingLen,
		}

	case *utls.UtlsCompressCertExtension:
		algos := make([]utls.CertCompressionAlgo, len(e.Algorithms))
		copy(algos, e.Algorithms)
		return &utls.UtlsCompressCertExtension{Algorithms: algos}

	case *utls.StatusRequestExtension:
		return &utls.StatusRequestExtension{}

	case *utls.StatusRequestV2Extension:
		return &utls.StatusRequestV2Extension{}

	case *utls.SCTExtension:
		return &utls.SCTExtension{}

	case *utls.ExtendedMasterSecretExtension:
		return &utls.ExtendedMasterSecretExtension{}

	case *utls.RenegotiationInfoExtension:
		return &utls.RenegotiationInfoExtension{Renegotiation: e.Renegotiation}

	case *utls.ApplicationSettingsExtension:
		protos := make([]string, len(e.SupportedProtocols))
		copy(protos, e.SupportedProtocols)
		return &utls.ApplicationSettingsExtension{SupportedProtocols: protos}

	case *utls.ApplicationSettingsExtensionNew:
		protos := make([]string, len(e.SupportedProtocols))
		copy(protos, e.SupportedProtocols)
		return &utls.ApplicationSettingsExtensionNew{SupportedProtocols: protos}

	case *utls.GREASEEncryptedClientHelloExtension:
		// GREASE ECH generates its random state lazily via sync.Once during first Write()
		// Return the SAME object so all connections share the same initialized state
		// This ensures consistent fingerprint - the state is immutable after initialization
		return e

	case *utls.GenericExtension:
		data := make([]byte, len(e.Data))
		copy(data, e.Data)
		return &utls.GenericExtension{Id: e.Id, Data: data}

	case *utls.CookieExtension:
		cookie := make([]byte, len(e.Cookie))
		copy(cookie, e.Cookie)
		return &utls.CookieExtension{Cookie: cookie}

	case *utls.FakeRecordSizeLimitExtension:
		return &utls.FakeRecordSizeLimitExtension{Limit: e.Limit}

	default:
		// For any unhandled extension types, return the original
		// This is a fallback - ideally all extension types should be handled
		return ext
	}
}

func encLevelToKeyType(encLevel protocol.EncryptionLevel, pers protocol.Perspective) qlog.KeyType {
	if pers == protocol.PerspectiveServer {
		switch encLevel {
		case protocol.EncryptionInitial:
			return qlog.KeyTypeServerInitial
		case protocol.EncryptionHandshake:
			return qlog.KeyTypeServerHandshake
		case protocol.Encryption0RTT:
			return qlog.KeyTypeServer0RTT
		case protocol.Encryption1RTT:
			return qlog.KeyTypeServer1RTT
		default:
			return ""
		}
	}
	switch encLevel {
	case protocol.EncryptionInitial:
		return qlog.KeyTypeClientInitial
	case protocol.EncryptionHandshake:
		return qlog.KeyTypeClientHandshake
	case protocol.Encryption0RTT:
		return qlog.KeyTypeClient0RTT
	case protocol.Encryption1RTT:
		return qlog.KeyTypeClient1RTT
	default:
		return ""
	}
}
