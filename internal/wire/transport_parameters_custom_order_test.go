package wire

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/sardanioss/quic-go/internal/protocol"

	"github.com/stretchr/testify/require"
)

// safariParams are the values Safari 26.3 sent on macOS 26.3, plus the ones a
// quic-go client always carries and Safari doesn't send. A custom order that
// leaves those out must not write them.
func safariParams() *TransportParameters {
	return &TransportParameters{
		OrderMode:                      TransportParameterOrderCustom,
		CustomOrder:                    []uint64{0x9, 0xe, 0xf, 0x4, 0x5, 0x6, 0x7, 0xff080808},
		InitialMaxStreamDataBidiLocal:  2097152,
		InitialMaxStreamDataBidiRemote: 2097152,
		InitialMaxStreamDataUni:        2097152,
		InitialMaxData:                 16777216,
		MaxUniStreamNum:                8,
		ActiveConnectionIDLimit:        64,
		InitialSourceConnectionID:      protocol.ParseConnectionID(nil),
		AdditionalParams:               map[uint64][]byte{0xff080808: {0x07}},

		// Not listed, so not sent.
		MaxBidiStreamNum:     100,
		MaxIdleTimeout:       30 * time.Second,
		MaxUDPPayloadSize:    1472,
		MaxDatagramFrameSize: 65536,
		MaxAckDelay:          protocol.DefaultMaxAckDelay,
		AckDelayExponent:     protocol.DefaultAckDelayExponent,
	}
}

// The 43 bytes of quic_transport_parameters in Safari 26.3's QUIC ClientHello,
// decrypted from its first two Initial packets (run-20261121-225724, lo0.pcap
// packets 34075 and 34076): eight parameters, no GREASE, and 0xff080808, an
// ID no RFC assigns.
const safariParamsHex = "0901080e0240400f00040481000000050480200000060480200000070480200000c0000000ff0808080107"

func TestTransportParametersCustomOrderSafari(t *testing.T) {
	want, err := hex.DecodeString(safariParamsHex)
	require.NoError(t, err)
	require.Equal(t, want, safariParams().Marshal(protocol.PerspectiveClient))
}

func TestTransportParametersCustomOrderPlacesAdditionalParams(t *testing.T) {
	p := safariParams()
	// The unimplemented ID first, and one additional parameter the list
	// doesn't name, which goes last.
	p.CustomOrder = []uint64{0xff080808, 0x9, 0xf}
	p.AdditionalParams = map[uint64][]byte{0xff080808: {0x07}, 0x1234: {0xab}}

	ids, greaseIdx, _ := paramIDs(t, p.Marshal(protocol.PerspectiveClient))
	require.Equal(t, []uint64{0xff080808, 0x9, 0xf, 0x1234}, ids)
	require.Equal(t, -1, greaseIdx, "a custom order adds no GREASE parameter")
}

func TestTransportParametersCustomOrderSkipsUnsuppliedIDs(t *testing.T) {
	p := safariParams()
	// 0xff080808 is listed, but nothing supplies a value for it.
	p.AdditionalParams = map[uint64][]byte{}

	ids, _, _ := paramIDs(t, p.Marshal(protocol.PerspectiveClient))
	require.Equal(t, []uint64{0x9, 0xe, 0xf, 0x4, 0x5, 0x6, 0x7}, ids)
}

func TestTransportParametersChromeOrderWritesGoogleParamsOnce(t *testing.T) {
	p := chromeParams()
	p.AdditionalParams = map[uint64][]byte{
		uint64(googleVersionParameterID):           {0, 0, 0, 1},
		uint64(googleConnectionOptionsParameterID): []byte("ORIG"),
		uint64(versionInformationParameterID):      {0, 0, 0, 1, 0, 0, 0, 1},
	}
	ids, _, _ := paramIDs(t, p.Marshal(protocol.PerspectiveClient))
	seen := map[uint64]int{}
	for _, id := range ids {
		seen[id]++
	}
	for _, id := range []transportParameterID{googleVersionParameterID, googleConnectionOptionsParameterID, versionInformationParameterID} {
		require.Equal(t, 1, seen[uint64(id)], "parameter %#x", uint64(id))
	}
}
