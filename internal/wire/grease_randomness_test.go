package wire

import (
	"testing"

	"github.com/sardanioss/quic-go/internal/protocol"
	"github.com/sardanioss/quic-go/quicvarint"
)

// The GREASE a client mixes into its transport parameters has to be random in
// every dimension a server can read, and a server reads all of them for free
// off the handshake with no request sent.
//
// quiche, for reference:
//
//	uint64_t grease_id64 = random->RandUint64() % ((1ULL << 62) - 31);
//	grease_id64 = (grease_id64 / 31) * 31 + 27;
//
//	for (size_t i = parameter_ids.size() - 1; i > 0; i--) {
//	  std::swap(parameter_ids[i],
//	            parameter_ids[random->InsecureRandUint64() % (i + 1)]);
//	}
//
// The id is uniform across the whole 62-bit space, and the order is reshuffled
// on every serialization rather than once per session.

func chromeParams() *TransportParameters {
	return &TransportParameters{
		OrderMode:                      TransportParameterOrderChrome,
		InitialMaxStreamDataBidiLocal:  6291456,
		InitialMaxStreamDataBidiRemote: 6291456,
		InitialMaxStreamDataUni:        6291456,
		InitialMaxData:                 15728640,
		MaxBidiStreamNum:               100,
		MaxUniStreamNum:                103,
		MaxIdleTimeout:                 30000000000,
		ActiveConnectionIDLimit:        2,
		MaxUDPPayloadSize:              1472,
		MaxDatagramFrameSize:           65536,
	}
}

// paramIDs reads back the transport parameter IDs in wire order, and reports
// which of them was the GREASE one.
func paramIDs(t *testing.T, b []byte) (ids []uint64, greaseIdx int, greaseID uint64) {
	t.Helper()
	greaseIdx = -1
	for len(b) > 0 {
		id, n, err := quicvarint.Parse(b)
		if err != nil {
			t.Fatalf("parsing a parameter id: %v", err)
		}
		b = b[n:]
		l, n, err := quicvarint.Parse(b)
		if err != nil {
			t.Fatalf("parsing a parameter length: %v", err)
		}
		b = b[n:]
		if uint64(len(b)) < l {
			t.Fatalf("parameter %d claims %d bytes and %d remain", id, l, len(b))
		}
		b = b[l:]
		if id%31 == 27 {
			greaseIdx = len(ids)
			greaseID = id
		}
		ids = append(ids, id)
	}
	return ids, greaseIdx, greaseID
}

func idString(ids []uint64) string {
	s := ""
	for _, id := range ids {
		if id%31 == 27 {
			s += "GREASE,"
			continue
		}
		s += string(rune('a'+id%26)) + ","
	}
	return s
}

// idStringNoGrease is the parameter order with the GREASE entry removed. The
// seed pins the order of the real parameters; where GREASE lands among them is
// separate randomness, exactly as it is upstream, where GREASE simply joins the
// list being shuffled.
func idStringNoGrease(ids []uint64) string {
	s := ""
	for _, id := range ids {
		if id%31 == 27 {
			continue
		}
		s += string(rune('a'+id%26)) + ","
	}
	return s
}

// The parameter order is reshuffled per serialization, so two connections from
// one client never carry the same ID sequence. A seed fixed for a transport's
// lifetime made every connection it opened byte-identical here, which needs no
// probability argument to detect at all.
func TestParameterOrderVariesPerMarshal(t *testing.T) {
	const runs = 200
	seen := map[string]int{}
	for i := 0; i < runs; i++ {
		ids, _, _ := paramIDs(t, chromeParams().Marshal(protocol.PerspectiveClient))
		seen[idString(ids)]++
	}
	if len(seen) < runs/2 {
		t.Fatalf("%d serializations produced only %d distinct parameter orders; "+
			"a client that repeats its order is identifiable across connections",
			runs, len(seen))
	}
}

// An explicit seed still pins the order, for anything that wants reproducibility.
func TestParameterOrderSeedIsReproducible(t *testing.T) {
	first := ""
	for i := 0; i < 5; i++ {
		p := chromeParams()
		p.ShuffleSeed = 424242
		ids, _, _ := paramIDs(t, p.Marshal(protocol.PerspectiveClient))
		got := idStringNoGrease(ids)
		if i == 0 {
			first = got
			continue
		}
		if got != first {
			t.Fatalf("the same seed gave two orders:\n %s\n %s", first, got)
		}
	}
}

// The GREASE parameter moves. It used to sit immediately after
// max_datagram_frame_size on every connection, which is a fixed relationship a
// server sees every time.
func TestGreaseParameterPositionVaries(t *testing.T) {
	const runs = 400
	positions := map[int]int{}
	for i := 0; i < runs; i++ {
		ids, idx, _ := paramIDs(t, chromeParams().Marshal(protocol.PerspectiveClient))
		if idx < 0 {
			t.Fatalf("no GREASE parameter among %d parameters", len(ids))
		}
		positions[idx]++
	}
	if len(positions) < 5 {
		t.Fatalf("the GREASE parameter only ever appeared at %d distinct positions "+
			"across %d serializations: %v", len(positions), runs, positions)
	}
}

// The GREASE ID is uniform across the 62-bit space, not clamped into a narrow
// decimal band. The old range was [3.1e15, 3.1e16), which a real client hits
// about once in 165 connections.
func TestGreaseParameterIDSpansTheSpace(t *testing.T) {
	const runs = 400

	// The band the old implementation confined every id to. A uniform draw over
	// the 62-bit space, which tops out near 4.6e18, lands above it about 99.3
	// percent of the time, so seeing nearly every draw outside the band is the
	// discriminating observation. 350 of 400 is far below that expectation and
	// far above what the old code could ever reach, which was zero.
	const bandHigh = uint64(31_000_000_000_000_000)

	var outside int
	var largest uint64
	for i := 0; i < runs; i++ {
		_, idx, id := paramIDs(t, chromeParams().Marshal(protocol.PerspectiveClient))
		if idx < 0 {
			t.Fatal("no GREASE parameter")
		}
		if id%31 != 27 {
			t.Fatalf("GREASE id %d is not of the form 31k+27, which RFC 9000 "+
				"requires of a reserved parameter", id)
		}
		if id >= 1<<62 {
			t.Fatalf("GREASE id %d does not fit the 62-bit varint space", id)
		}
		if id >= bandHigh {
			outside++
		}
		if id > largest {
			largest = id
		}
	}
	if outside < 350 {
		t.Fatalf("only %d of %d GREASE ids landed above %d; a uniform draw over "+
			"the 62-bit space lands there about 99 percent of the time, and the "+
			"clamped version never did", outside, runs, bandHigh)
	}
	if largest < 1e18 {
		t.Fatalf("the largest GREASE id in %d draws was %d; a uniform draw "+
			"reaches past 1e18 routinely and the clamped version topped out "+
			"three orders of magnitude below that", runs, largest)
	}
}
