package http3

import (
	"bytes"
	"fmt"
	"sync"
	"testing"

	"github.com/sardanioss/quic-go"
	"github.com/sardanioss/quic-go/quicvarint"

	"github.com/stretchr/testify/require"
)

// parsePriorityUpdates reads a stream of PRIORITY_UPDATE frames off a buffer
// and returns (prioritized_stream_id, field value) for each. It insists every
// frame is well formed and that nothing else is present, so a torn or
// interleaved write shows up as a parse failure rather than a silent pass.
func parsePriorityUpdates(t *testing.T, b []byte) [][2]string {
	t.Helper()
	r := bytes.NewReader(b)
	var out [][2]string
	for r.Len() > 0 {
		ft, err := quicvarint.Read(r)
		require.NoError(t, err, "reading frame type")
		require.Equal(t, uint64(priorityUpdateFrameType), ft, "unexpected frame on the control stream")
		l, err := quicvarint.Read(r)
		require.NoError(t, err, "reading frame length")
		payload := make([]byte, l)
		_, err = r.Read(payload)
		require.NoError(t, err, "reading frame payload")
		pr := bytes.NewReader(payload)
		id, err := quicvarint.Read(pr)
		require.NoError(t, err, "reading prioritized_stream_id")
		rest := make([]byte, pr.Len())
		_, _ = pr.Read(rest)
		out = append(out, [2]string{fmt.Sprint(id), string(rest)})
	}
	return out
}

// Chrome 151 puts these exact bytes on the wire for a document request. The
// literal is a real capture, so a change to the framing shows up here as a
// byte diff rather than as a fingerprint mismatch found in the field.
func TestPriorityUpdateWireBytes(t *testing.T) {
	// 800f0700  frame type varint 0xf0700 (984832)
	// 07        length: 1 byte of stream ID plus 6 bytes of value
	// 04        prioritized_stream_id
	// 753d302c2069  "u=0, i"
	require.Equal(t,
		"800f07000704753d302c2069",
		fmt.Sprintf("%x", appendPriorityUpdateFrameDynamic(nil, 4, "u=0, i")))
	// Stream 0 differs only in the ID byte. It has to be encodable, because the
	// first request on a fresh connection lands there.
	require.Equal(t,
		"800f07000700753d302c2069",
		fmt.Sprintf("%x", appendPriorityUpdateFrameDynamic(nil, 0, "u=0, i")))
}

// The first request on a fresh H3 connection uses stream 0, and Chrome sends a
// PRIORITY_UPDATE for it. A stream-ID floor here means every connection's very
// first request goes out unpriorised, which is the request most likely to be
// looked at.
func TestPriorityUpdateCoversStreamZero(t *testing.T) {
	buf := &bytes.Buffer{}
	c := &rawConn{controlStrSend: buf}
	require.NoError(t, c.MaybeSendPriorityUpdate(0, "u=0, i"))

	got := parsePriorityUpdates(t, buf.Bytes())
	require.Len(t, got, 1, "stream 0 must produce a frame")
	require.Equal(t, [2]string{"0", "u=0, i"}, got[0])
}

// Chromium's QuicSpdyStream::MaybeSendPriorityUpdateFrame runs per stream, not
// per connection: last_sent_priority_ is a stream member seeded with the RFC
// 9218 defaults. One frame per connection leaves requests 2..N unpriorised.
func TestPriorityUpdateIsPerRequestNotPerConnection(t *testing.T) {
	buf := &bytes.Buffer{}
	c := &rawConn{controlStrSend: buf}
	for _, id := range []quic.StreamID{0, 4, 8, 12} {
		require.NoError(t, c.MaybeSendPriorityUpdate(id, "u=1"))
	}

	got := parsePriorityUpdates(t, buf.Bytes())
	require.Equal(t, [][2]string{
		{"0", "u=1"}, {"4", "u=1"}, {"8", "u=1"}, {"12", "u=1"},
	}, got, "every request stream needs its own frame")
}

// quiche seeds last_sent_priority_ with urgency 3, non-incremental and only
// writes on a change, so a stream carrying exactly the defaults produces
// nothing. Anything unparseable produces a frame rather than dropping one.
func TestPriorityUpdateSkipsDefaultPriority(t *testing.T) {
	for _, tc := range []struct {
		value string
		skip  bool
	}{
		{"u=3", true},         // the RFC 9218 default, spelled out
		{"u=3, i=?0", true},   // same thing, incremental set false explicitly
		{"", true},            // nothing said means the defaults apply
		{"u=3, i", false},     // incremental differs, audio/track/video use this
		{"u=0, i", false},     // documents
		{"u=1", false},        // scripts
		{"u=2, i", false},     // images
		{"u=3, q=0.5", false}, // unknown parameter: send rather than guess
		{"u=nonsense", false}, // unparseable urgency: send rather than guess
	} {
		buf := &bytes.Buffer{}
		c := &rawConn{controlStrSend: buf}
		require.NoError(t, c.MaybeSendPriorityUpdate(4, tc.value))
		if tc.skip {
			require.Empty(t, buf.Bytes(), "%q is the default priority, expected no frame", tc.value)
			continue
		}
		require.Len(t, parsePriorityUpdates(t, buf.Bytes()), 1,
			"%q differs from the default, expected a frame", tc.value)
	}
}

// One frame per request means one control-stream writer per in-flight request.
// quic.SendStream.Write is not safe for concurrent use, so the lock has to be
// held across the write and not just the pointer read. Run under -race.
func TestPriorityUpdateConcurrentWritesDoNotTear(t *testing.T) {
	const n = 64
	buf := &bytes.Buffer{}
	c := &rawConn{controlStrSend: buf}

	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(id quic.StreamID) {
			defer wg.Done()
			require.NoError(t, c.MaybeSendPriorityUpdate(id, "u=0, i"))
		}(quic.StreamID(i * 4))
	}
	wg.Wait()

	// A torn write makes this parse fail; a dropped one makes the count wrong.
	require.Len(t, parsePriorityUpdates(t, buf.Bytes()), n)
}
