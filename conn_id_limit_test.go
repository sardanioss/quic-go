package quic

import (
	"testing"

	"github.com/sardanioss/quic-go/internal/protocol"
	"github.com/sardanioss/quic-go/internal/qerr"
	"github.com/sardanioss/quic-go/internal/wire"

	"github.com/stretchr/testify/require"
)

func newConnIDFrame(i uint64) *wire.NewConnectionIDFrame {
	b := byte(i)
	return &wire.NewConnectionIDFrame{
		SequenceNumber:      i,
		ConnectionID:        protocol.ParseConnectionID([]byte{b, b, b, b}),
		StatelessResetToken: protocol.StatelessResetToken{b, b, b, b, b, b, b, b, b, b, b, b, b, b, b, b},
	}
}

func TestConnIDManagerRaisedLimit(t *testing.T) {
	m := newConnIDManager(
		protocol.ParseConnectionID([]byte{1, 2, 3, 4}),
		func(protocol.StatelessResetToken) {},
		func(protocol.StatelessResetToken) {},
		func(f wire.Frame) {},
	)
	m.raiseLimit(8)
	// Eight in all, the one in use included.
	for i := uint64(1); i < 8; i++ {
		require.NoError(t, m.Add(newConnIDFrame(i)))
	}
	require.Equal(t, &qerr.TransportError{ErrorCode: qerr.ConnectionIDLimitError}, m.Add(newConnIDFrame(8)))
}

func TestConnIDManagerLimitIsNeverLowered(t *testing.T) {
	m := newConnIDManager(
		protocol.ParseConnectionID([]byte{1, 2, 3, 4}),
		func(protocol.StatelessResetToken) {},
		func(protocol.StatelessResetToken) {},
		func(f wire.Frame) {},
	)
	m.raiseLimit(2)
	require.Equal(t, protocol.MaxActiveConnectionIDs, m.limit)
}

func TestClientConnectionStoresItsAdvertisedConnIDLimit(t *testing.T) {
	tc := newClientTestConnection(t, nil, &Config{DisablePathMTUDiscovery: true, ActiveConnectionIDLimit: 64}, false)
	require.Equal(t, 64, tc.conn.connIDManager.limit)

	tc = newClientTestConnection(t, nil, nil, false)
	require.Equal(t, protocol.MaxActiveConnectionIDs, tc.conn.connIDManager.limit)
}

func TestClientTransportParametersActiveConnectionIDLimit(t *testing.T) {
	custom := func(limit uint64) *Config {
		return &Config{
			TransportParameterOrder:       TransportParameterOrderCustom,
			CustomTransportParameterOrder: []uint64{0xe, 0xf},
			ActiveConnectionIDLimit:       limit,
		}
	}
	ids, values := clientParamIDs(t, custom(64))
	require.Equal(t, []uint64{0xe, 0xf}, ids)
	require.Equal(t, []byte{0x40, 0x40}, values[0xe]) // 64

	// The default, and anything below it, isn't sent.
	for _, limit := range []uint64{0, 1, 2} {
		ids, _ = clientParamIDs(t, custom(limit))
		require.Equal(t, []uint64{0xf}, ids, "limit %d", limit)
	}

	// quic-go's own order sends it too.
	_, values = clientParamIDs(t, &Config{ActiveConnectionIDLimit: 64})
	require.Equal(t, []byte{0x40, 0x40}, values[0xe])
}
