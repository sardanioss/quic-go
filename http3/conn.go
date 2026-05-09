package http3

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"

	"github.com/sardanioss/quic-go"
	"github.com/sardanioss/quic-go/http3/qlog"
	"github.com/sardanioss/quic-go/qlogwriter"
	"github.com/sardanioss/quic-go/quicvarint"
)

const maxQuarterStreamID = 1<<60 - 1

// invalidStreamID is a stream ID that is invalid. The first valid stream ID in QUIC is 0.
const invalidStreamID = quic.StreamID(-1)

// rawConn is an HTTP/3 connection.
// It provides HTTP/3 specific functionality by wrapping a quic.Conn,
// in particular handling of unidirectional HTTP/3 streams, SETTINGS and datagrams.
type rawConn struct {
	conn *quic.Conn

	logger *slog.Logger

	enableDatagrams  bool
	sendGreaseFrames bool

	streamMx sync.Mutex
	streams  map[quic.StreamID]*stateTrackingStream

	rcvdControlStr      atomic.Bool
	rcvdQPACKEncoderStr atomic.Bool
	rcvdQPACKDecoderStr atomic.Bool
	controlStrHandler   func(*quic.ReceiveStream, *frameParser) // is called *after* the SETTINGS frame was parsed

	onStreamsEmpty func()

	settings         *Settings
	receivedSettings chan struct{}

	qlogger qlogwriter.Recorder

	// qpackEncoderInstructionHandler processes QPACK encoder instructions from the peer
	// This is optional - if nil, encoder instructions are ignored (no dynamic table)
	qpackEncoderInstructionHandler func([]byte) error

	// controlStrSend is the client-side send-half of the control stream.
	// Stored after openControlStream so we can lazily write PRIORITY_UPDATE
	// frames keyed to actual request stream IDs (RFC 9218 §7.1). Real Chrome
	// emits PRIORITY_UPDATE just before HEADERS for a request, with the
	// priority field value derived from the request's Sec-Fetch-Dest /
	// resource type (matches the per-request "priority:" header).
	controlStrSend       *quic.SendStream
	controlStrSendMx     sync.Mutex
	priorityUpdateSentMx sync.Mutex
	priorityUpdateSent   bool
}

func newRawConn(
	quicConn *quic.Conn,
	enableDatagrams bool,
	sendGreaseFrames bool,
	onStreamsEmpty func(),
	controlStrHandler func(*quic.ReceiveStream, *frameParser),
	qlogger qlogwriter.Recorder,
	logger *slog.Logger,
) *rawConn {
	return &rawConn{
		conn:              quicConn,
		logger:            logger,
		enableDatagrams:   enableDatagrams,
		sendGreaseFrames:  sendGreaseFrames,
		receivedSettings:  make(chan struct{}),
		streams:           make(map[quic.StreamID]*stateTrackingStream),
		qlogger:           qlogger,
		onStreamsEmpty:    onStreamsEmpty,
		controlStrHandler: controlStrHandler,
	}
}

func (c *rawConn) OpenUniStream() (*quic.SendStream, error) {
	return c.conn.OpenUniStream()
}

// openControlStream opens the control stream and sends the SETTINGS frame.
// It returns the control stream (needed by the server for sending GOAWAY later).
//
// Note: PRIORITY_UPDATE is NOT written here. Chrome emits PRIORITY_UPDATE
// lazily, just before the HEADERS frame for the first request, with the
// prioritized_stream_id and priority value matching that request. See
// SendInitialPriorityUpdate.
func (c *rawConn) openControlStream(settings *settingsFrame) (*quic.SendStream, error) {
	str, err := c.conn.OpenUniStream()
	if err != nil {
		return nil, err
	}
	b := make([]byte, 0, 64)
	b = quicvarint.Append(b, streamTypeControlStream)
	b = settings.Append(b)

	// Add GREASE frame after SETTINGS if enabled (mimics Chrome behavior)
	if c.sendGreaseFrames {
		b = appendGreaseFrame(b)
	}

	if c.qlogger != nil {
		sf := qlog.SettingsFrame{
			MaxFieldSectionSize: settings.MaxFieldSectionSize,
			Other:               maps.Clone(settings.Other),
		}
		if settings.Datagram {
			sf.Datagram = pointer(true)
		}
		if settings.ExtendedConnect {
			sf.ExtendedConnect = pointer(true)
		}
		c.qlogger.RecordEvent(qlog.FrameCreated{
			StreamID: str.StreamID(),
			Raw:      qlog.RawInfo{Length: len(b)},
			Frame:    qlog.Frame{Frame: sf},
		})
	}
	if _, err := str.Write(b); err != nil {
		return nil, err
	}
	// Stash the send-side so SendInitialPriorityUpdate can write to it later
	// when the first request stream is opened. This is the only writer to the
	// control stream after open, so a single mutex on writes is sufficient.
	c.controlStrSendMx.Lock()
	c.controlStrSend = str
	c.controlStrSendMx.Unlock()
	return str, nil
}

// SendInitialPriorityUpdate writes a PRIORITY_UPDATE frame on the control
// stream with the given prioritized_stream_id and priority field value.
// Idempotent: only the first call (with a stream ID Chrome would actually
// reference) has effect; subsequent calls are no-ops. Used by the H3 client
// to mimic Chrome's "PRIORITY_UPDATE just before HEADERS for the first
// request, value derived from the request's resource type" behavior.
// priorityValue is e.g. "u=0, i" for documents, "u=1" for scripts, "u=2"
// for images — the same value the request's "priority:" header carries
// (RFC 9218 §7.1).
//
// Why we skip stream ID 0: real Chrome's first H3 request lands on stream 4
// because Chrome opens server-bidi-credit-burning streams (or 0-RTT probes
// on stream 0) before the first real request. Sending PRIORITY_UPDATE for
// stream 0 is technically valid per RFC 9218 §7.1 (refers to a stream that
// doesn't exist yet), but H3 fingerprinters silently drop those references
// because real Chrome never emits them. We mirror Chrome by waiting until
// the first ID >= 4.
//
// Caller must guard with c.sendGreaseFrames so we don't emit PRIORITY_UPDATE
// for non-Chrome presets that don't ship the GREASE/PRIORITY_UPDATE pair.
//
// Returns nil silently if the control stream isn't open yet (early shutdown
// race) — the failure mode is "we lose one PRIORITY_UPDATE frame" not "the
// connection breaks."
func (c *rawConn) SendInitialPriorityUpdate(streamID quic.StreamID, priorityValue string) error {
	// Skip stream 0 — Chrome's first request lands on stream 4 after the
	// 0-RTT probe on stream 0 burns the lowest bidi ID.
	if streamID < 4 {
		return nil
	}
	c.priorityUpdateSentMx.Lock()
	if c.priorityUpdateSent {
		c.priorityUpdateSentMx.Unlock()
		return nil
	}
	c.priorityUpdateSent = true
	c.priorityUpdateSentMx.Unlock()

	c.controlStrSendMx.Lock()
	str := c.controlStrSend
	c.controlStrSendMx.Unlock()
	if str == nil {
		return nil
	}

	b := appendPriorityUpdateFrameDynamic(nil, uint64(streamID), priorityValue)
	_, err := str.Write(b)
	return err
}

// appendPriorityUpdateFrameDynamic is the per-request equivalent of
// appendPriorityUpdateFrame: caller passes the actual stream ID and the
// resolved priority field value instead of the function hardcoding both.
func appendPriorityUpdateFrameDynamic(b []byte, streamID uint64, priorityValue string) []byte {
	b = quicvarint.Append(b, priorityUpdateFrameType)
	pv := []byte(priorityValue)
	streamIDLen := quicvarint.Len(streamID)
	b = quicvarint.Append(b, uint64(streamIDLen)+uint64(len(pv)))
	b = quicvarint.Append(b, streamID)
	b = append(b, pv...)
	return b
}

func (c *rawConn) TrackStream(str *quic.Stream) *stateTrackingStream {
	hstr := newStateTrackingStream(str, c, func(b []byte) error { return c.sendDatagram(str.StreamID(), b) })

	c.streamMx.Lock()
	c.streams[str.StreamID()] = hstr
	c.streamMx.Unlock()
	return hstr
}

func (c *rawConn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func (c *rawConn) ConnectionState() quic.ConnectionState {
	return c.conn.ConnectionState()
}

func (c *rawConn) clearStream(id quic.StreamID) {
	c.streamMx.Lock()
	defer c.streamMx.Unlock()

	delete(c.streams, id)
	if len(c.streams) == 0 {
		c.onStreamsEmpty()
	}
}

func (c *rawConn) hasActiveStreams() bool {
	c.streamMx.Lock()
	defer c.streamMx.Unlock()

	return len(c.streams) > 0
}

func (c *rawConn) CloseWithError(code quic.ApplicationErrorCode, msg string) error {
	return c.conn.CloseWithError(code, msg)
}

func (c *rawConn) handleUnidirectionalStream(str *quic.ReceiveStream, isServer bool) {
	streamType, err := quicvarint.Read(quicvarint.NewReader(str))
	if err != nil {
		if c.logger != nil {
			c.logger.Debug("reading stream type on stream failed", "stream ID", str.StreamID(), "error", err)
		}
		return
	}
	// We're only interested in the control stream here.
	switch streamType {
	case streamTypeControlStream:
	case streamTypeQPACKEncoderStream:
		if isFirst := c.rcvdQPACKEncoderStr.CompareAndSwap(false, true); !isFirst {
			c.CloseWithError(quic.ApplicationErrorCode(ErrCodeStreamCreationError), "duplicate QPACK encoder stream")
			return
		}
		// Process encoder instructions if handler is set
		if c.qpackEncoderInstructionHandler != nil {
			go c.handleQPACKEncoderStream(str)
		}
		return
	case streamTypeQPACKDecoderStream:
		if isFirst := c.rcvdQPACKDecoderStr.CompareAndSwap(false, true); !isFirst {
			c.CloseWithError(quic.ApplicationErrorCode(ErrCodeStreamCreationError), "duplicate QPACK decoder stream")
		}
		// Our QPACK implementation doesn't use the dynamic table yet.
		return
	case streamTypePushStream:
		if isServer {
			// only the server can push
			c.CloseWithError(quic.ApplicationErrorCode(ErrCodeStreamCreationError), "")
		} else {
			// we never increased the Push ID, so we don't expect any push streams
			c.CloseWithError(quic.ApplicationErrorCode(ErrCodeIDError), "")
		}
		return
	default:
		str.CancelRead(quic.StreamErrorCode(ErrCodeStreamCreationError))
		return
	}
	// Only a single control stream is allowed.
	if isFirstControlStr := c.rcvdControlStr.CompareAndSwap(false, true); !isFirstControlStr {
		c.conn.CloseWithError(quic.ApplicationErrorCode(ErrCodeStreamCreationError), "duplicate control stream")
		return
	}
	c.handleControlStream(str)
}

func (c *rawConn) handleControlStream(str *quic.ReceiveStream) {
	fp := &frameParser{closeConn: c.conn.CloseWithError, r: str, streamID: str.StreamID()}
	f, err := fp.ParseNext(c.qlogger)
	if err != nil {
		var serr *quic.StreamError
		if err == io.EOF || errors.As(err, &serr) {
			c.conn.CloseWithError(quic.ApplicationErrorCode(ErrCodeClosedCriticalStream), "")
			return
		}
		c.conn.CloseWithError(quic.ApplicationErrorCode(ErrCodeFrameError), "")
		return
	}
	sf, ok := f.(*settingsFrame)
	if !ok {
		c.conn.CloseWithError(quic.ApplicationErrorCode(ErrCodeMissingSettings), "")
		return
	}
	c.settings = &Settings{
		EnableDatagrams:       sf.Datagram,
		EnableExtendedConnect: sf.ExtendedConnect,
		Other:                 sf.Other,
	}
	close(c.receivedSettings)
	if sf.Datagram {
		// If datagram support was enabled on our side as well as on the server side,
		// we can expect it to have been negotiated both on the transport and on the HTTP/3 layer.
		// Note: ConnectionState() will block until the handshake is complete (relevant when using 0-RTT).
		if c.enableDatagrams && !c.ConnectionState().SupportsDatagrams {
			c.CloseWithError(quic.ApplicationErrorCode(ErrCodeSettingsError), "missing QUIC Datagram support")
			return
		}
		go func() {
			if err := c.receiveDatagrams(); err != nil {
				if c.logger != nil {
					c.logger.Debug("receiving datagrams failed", "error", err)
				}
			}
		}()
	}

	if c.controlStrHandler != nil {
		c.controlStrHandler(str, fp)
	}
}

func (c *rawConn) sendDatagram(streamID quic.StreamID, b []byte) error {
	// TODO: this creates a lot of garbage and an additional copy
	data := make([]byte, 0, len(b)+8)
	quarterStreamID := uint64(streamID / 4)
	data = quicvarint.Append(data, uint64(streamID/4))
	data = append(data, b...)
	if c.qlogger != nil {
		c.qlogger.RecordEvent(qlog.DatagramCreated{
			QuaterStreamID: quarterStreamID,
			Raw: qlog.RawInfo{
				Length:        len(data),
				PayloadLength: len(b),
			},
		})
	}
	return c.conn.SendDatagram(data)
}

func (c *rawConn) receiveDatagrams() error {
	for {
		b, err := c.conn.ReceiveDatagram(context.Background())
		if err != nil {
			return err
		}
		quarterStreamID, n, err := quicvarint.Parse(b)
		if err != nil {
			c.CloseWithError(quic.ApplicationErrorCode(ErrCodeDatagramError), "")
			return fmt.Errorf("could not read quarter stream id: %w", err)
		}
		if c.qlogger != nil {
			c.qlogger.RecordEvent(qlog.DatagramParsed{
				QuaterStreamID: quarterStreamID,
				Raw: qlog.RawInfo{
					Length:        len(b),
					PayloadLength: len(b) - n,
				},
			})
		}
		if quarterStreamID > maxQuarterStreamID {
			c.CloseWithError(quic.ApplicationErrorCode(ErrCodeDatagramError), "")
			return fmt.Errorf("invalid quarter stream id: %w", err)
		}
		streamID := quic.StreamID(4 * quarterStreamID)
		c.streamMx.Lock()
		dg, ok := c.streams[streamID]
		c.streamMx.Unlock()
		if !ok {
			continue
		}
		dg.enqueueDatagram(b[n:])
	}
}

// ReceivedSettings returns a channel that is closed once the peer's SETTINGS frame was received.
// Settings can be optained from the Settings method after the channel was closed.
func (c *rawConn) ReceivedSettings() <-chan struct{} { return c.receivedSettings }

// Settings returns the settings received on this connection.
// It is only valid to call this function after the channel returned by ReceivedSettings was closed.
func (c *rawConn) Settings() *Settings { return c.settings }

// Context returns the context of the underlying QUIC connection.
func (c *rawConn) Context() context.Context { return c.conn.Context() }

// handleQPACKEncoderStream reads and processes QPACK encoder instructions from the peer.
// This populates the dynamic table so we can decode headers that reference it.
func (c *rawConn) handleQPACKEncoderStream(str *quic.ReceiveStream) {
	buf := make([]byte, 4096)
	for {
		n, err := str.Read(buf)
		if err != nil {
			if err == io.EOF {
				return
			}
			if c.logger != nil {
				c.logger.Debug("reading QPACK encoder stream failed", "error", err)
			}
			return
		}
		if n > 0 {
			if err := c.qpackEncoderInstructionHandler(buf[:n]); err != nil {
				if c.logger != nil {
					c.logger.Debug("processing QPACK encoder instructions failed", "error", err)
				}
				c.CloseWithError(quic.ApplicationErrorCode(ErrCodeQPACKDecompressionFailed), "")
				return
			}
		}
	}
}

// generateGreaseFrameType generates a random GREASE frame type.
// GREASE frame types are of the form 0x1f * N + 0x21 where N is random.
// Chrome uses large random N values, producing frame types like 1508608275.
func generateGreaseFrameType() uint64 {
	// Generate a large random N value (Chrome uses values that produce 9-10 digit frame types)
	// N range: 1000000 to 100000000 produces realistic Chrome-like values
	n := uint64(1000000 + rand.Intn(99000000))
	return 0x1f*n + 0x21
}

// appendGreaseFrame appends a GREASE frame to the byte slice.
// GREASE frames help prevent implementation bugs from ossifying protocol extensions.
func appendGreaseFrame(b []byte) []byte {
	greaseFrameType := generateGreaseFrameType()
	b = quicvarint.Append(b, greaseFrameType)
	// Chrome sends empty GREASE frames (length 0)
	b = quicvarint.Append(b, 0) // frame length
	return b
}

// PRIORITY_UPDATE frame type for request streams (RFC 9218)
const priorityUpdateFrameType = 0xf0700

// PRIORITY_UPDATE on the control stream is now emitted lazily — see
// rawConn.SendInitialPriorityUpdate / appendPriorityUpdateFrameDynamic.
// The previous unconditional appendPriorityUpdateFrame helper used a
// hardcoded stream_id=4 and "u=0, i" priority, which only matched Chrome
// for document navigations and silently lost per-resource-type variations
// the priority_table expressed.
