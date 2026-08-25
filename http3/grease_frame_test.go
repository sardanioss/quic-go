package http3

import (
	"testing"

	"github.com/sardanioss/quic-go/quicvarint"
)

// Locks on the GREASE frame a client writes to its control stream, right after
// SETTINGS. A server reads it off the handshake with no request sent.
//
// quiche, HttpEncoder::SerializeGreasingFrame:
//
//	uint32_t result;
//	QuicRandom::GetInstance()->RandBytes(&result, sizeof(result));
//	frame_type = 0x1fULL * static_cast<uint64_t>(result) + 0x21ULL;
//
//	// The payload length is random but within [0, 3].
//	payload_length = result % 4;

// The payload length is derived from the same draw as the frame type, so a
// server can invert the type and check the length it implies.
//
// This is the sharp one. The old implementation always wrote a zero-length
// payload, which contradicts the frame's own type on three draws in four, with
// no probability argument needed and one frame to read. Two GREASE frames
// captured from this client against a live origin inverted to lengths of 3 and
// 2 and carried no payload at all.
func TestGreaseFramePayloadLengthMatchesItsType(t *testing.T) {
	const runs = 500
	lengths := map[int]int{}

	for i := 0; i < runs; i++ {
		frameType, payload := greaseFrame()
		if (frameType-0x21)%0x1f != 0 {
			t.Fatalf("frame type %d is not of the form 0x1f*N + 0x21, which "+
				"draft-ietf-quic-http reserves for greasing", frameType)
		}
		result := (frameType - 0x21) / 0x1f
		if want := int(result % 4); len(payload) != want {
			t.Fatalf("frame type %d implies a payload of %d bytes and the frame "+
				"carries %d; upstream derives both from one draw",
				frameType, want, len(payload))
		}
		lengths[len(payload)]++
	}

	// All four lengths have to actually occur, or the derivation is being
	// faked by a generator that only ever produces one of them.
	for n := 0; n < 4; n++ {
		if lengths[n] == 0 {
			t.Errorf("no frame in %d draws carried a %d-byte payload; the four "+
				"lengths are equally likely upstream", runs, n)
		}
	}
}

// The frame type is drawn from a full uint32, not a hand-picked decimal band.
//
// The old range was N in [1e6, 1e8), so the type never exceeded about 3.1e9. A
// real client lands in that band on about 2 percent of connections, and a
// captured Chrome 152 frame type was 119790168723, forty times the old ceiling.
func TestGreaseFrameTypeSpansTheDrawSpace(t *testing.T) {
	const runs = 500
	const oldCeiling = uint64(0x1f*100000000 + 0x21)

	var above, largest uint64
	types := map[uint64]bool{}
	for i := 0; i < runs; i++ {
		frameType, _ := greaseFrame()
		types[frameType] = true
		if frameType > oldCeiling {
			above++
		}
		if frameType > largest {
			largest = frameType
		}
		if result := (frameType - 0x21) / 0x1f; result >= 1<<32 {
			t.Fatalf("frame type %d inverts to %d, which does not fit the "+
				"uint32 upstream draws", frameType, result)
		}
	}
	if len(types) < runs-1 {
		t.Fatalf("%d draws produced only %d distinct frame types", runs, len(types))
	}
	// A uniform uint32 exceeds the old ceiling about 97.7 percent of the time.
	if above < runs*9/10 {
		t.Errorf("only %d of %d frame types exceeded the old ceiling of %d; a "+
			"uniform uint32 draw exceeds it about 98 percent of the time",
			above, runs, oldCeiling)
	}
	if largest < 1e11 {
		t.Errorf("the largest frame type in %d draws was %d; a uniform uint32 "+
			"reaches past 1e11 routinely", runs, largest)
	}
}

// And the frame that actually goes on the wire carries the payload, rather
// than declaring a length it does not write.
func TestAppendGreaseFrameIsWellFormed(t *testing.T) {
	for i := 0; i < 200; i++ {
		b := appendGreaseFrame(nil)
		frameType, n, err := quicvarint.Parse(b)
		if err != nil {
			t.Fatalf("parsing the frame type: %v", err)
		}
		b = b[n:]
		length, n, err := quicvarint.Parse(b)
		if err != nil {
			t.Fatalf("parsing the frame length: %v", err)
		}
		b = b[n:]
		if uint64(len(b)) != length {
			t.Fatalf("frame declares %d payload bytes and %d follow", length, len(b))
		}
		if want := ((frameType - 0x21) / 0x1f) % 4; length != want {
			t.Fatalf("frame type %d implies %d payload bytes, wire says %d",
				frameType, want, length)
		}
	}
}
