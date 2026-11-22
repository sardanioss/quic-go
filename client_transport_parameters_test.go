package quic

import (
	"testing"

	"github.com/sardanioss/quic-go/internal/protocol"
	"github.com/sardanioss/quic-go/quicvarint"

	"github.com/stretchr/testify/require"
)

// clientParamIDs marshals a client's transport parameters and reads back
// their IDs, in wire order, with each value.
func clientParamIDs(t *testing.T, conf *Config) ([]uint64, map[uint64][]byte) {
	t.Helper()
	b := clientTransportParameters(populateConfig(conf), protocol.ParseConnectionID(nil)).Marshal(protocol.PerspectiveClient)
	var ids []uint64
	values := map[uint64][]byte{}
	for len(b) > 0 {
		id, n, err := quicvarint.Parse(b)
		require.NoError(t, err)
		b = b[n:]
		l, n, err := quicvarint.Parse(b)
		require.NoError(t, err)
		b = b[n:]
		require.LessOrEqual(t, l, uint64(len(b)))
		ids = append(ids, id)
		values[id] = b[:l]
		b = b[l:]
	}
	return ids, values
}

func TestClientTransportParametersCustomOrder(t *testing.T) {
	ids, values := clientParamIDs(t, &Config{
		TransportParameterOrder:        TransportParameterOrderCustom,
		CustomTransportParameterOrder:  []uint64{0x9, 0xf, 0x4, 0xff080808},
		AdditionalTransportParameters:  map[uint64][]byte{0xff080808: {0x07}},
		MaxIncomingUniStreams:          8,
		InitialConnectionReceiveWindow: 16777216,
		EnableDatagrams:                true,
	})
	require.Equal(t, []uint64{0x9, 0xf, 0x4, 0xff080808}, ids)
	require.Equal(t, []byte{0x08}, values[0x9])
	require.Equal(t, []byte{0x07}, values[0xff080808])
}
