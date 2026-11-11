package ackhandler

import (
	"testing"
	"time"

	"github.com/sardanioss/quic-go/internal/monotime"
	"github.com/sardanioss/quic-go/internal/protocol"
	"github.com/sardanioss/quic-go/internal/utils"
	"github.com/sardanioss/quic-go/internal/wire"

	"github.com/stretchr/testify/require"
)

// A close carries an ACK even when everything in it was acknowledged before,
// the way quiche bundles its current ACK with every CONNECTION_CLOSE, and
// building it leaves the regular ACK state alone.
func TestGetAckFrameForClose(t *testing.T) {
	handler := NewReceivedPacketHandler(&utils.RTTStats{}, utils.DefaultLogger)
	now := monotime.Now()
	rcvTime := now.Add(-time.Second)

	for _, encLevel := range []protocol.EncryptionLevel{protocol.EncryptionInitial, protocol.EncryptionHandshake, protocol.Encryption1RTT} {
		require.Nil(t, handler.GetAckFrameForClose(encLevel, now), "nothing received at %s", encLevel)
	}

	require.NoError(t, handler.ReceivedPacket(2, protocol.ECT0, protocol.EncryptionInitial, rcvTime, true))
	require.NoError(t, handler.ReceivedPacket(1, protocol.ECNNon, protocol.EncryptionHandshake, rcvTime, true))
	require.NoError(t, handler.ReceivedPacket(8, protocol.ECNNon, protocol.Encryption1RTT, rcvTime, true))
	require.NoError(t, handler.ReceivedPacket(9, protocol.ECNNon, protocol.Encryption1RTT, rcvTime, true))
	require.NoError(t, handler.ReceivedPacket(10, protocol.ECNNon, protocol.Encryption1RTT, rcvTime, false))

	// Everything is acknowledged the regular way first.
	require.NotNil(t, handler.GetAckFrame(protocol.EncryptionInitial, now, false))
	require.NotNil(t, handler.GetAckFrame(protocol.EncryptionHandshake, now, false))
	require.NotNil(t, handler.GetAckFrame(protocol.Encryption1RTT, now, false))
	require.Nil(t, handler.GetAckFrame(protocol.Encryption1RTT, now, false), "nothing new to acknowledge")

	initialAck := handler.GetAckFrameForClose(protocol.EncryptionInitial, now)
	require.NotNil(t, initialAck)
	require.Equal(t, []wire.AckRange{{Smallest: 2, Largest: 2}}, initialAck.AckRanges)
	require.EqualValues(t, 1, initialAck.ECT0)
	handshakeAck := handler.GetAckFrameForClose(protocol.EncryptionHandshake, now)
	require.NotNil(t, handshakeAck)
	require.Equal(t, []wire.AckRange{{Smallest: 1, Largest: 1}}, handshakeAck.AckRanges)
	oneRTTAck := handler.GetAckFrameForClose(protocol.Encryption1RTT, now)
	require.NotNil(t, oneRTTAck)
	require.Equal(t, []wire.AckRange{{Smallest: 8, Largest: 10}}, oneRTTAck.AckRanges)
	require.Equal(t, time.Second, oneRTTAck.DelayTime)
	require.Nil(t, handler.GetAckFrameForClose(protocol.Encryption0RTT, now), "a 0-RTT packet cannot carry an ACK")

	// The regular state is as it was: still nothing new, and a new packet is
	// acknowledged as usual.
	require.Nil(t, handler.GetAckFrame(protocol.Encryption1RTT, now, false))
	require.NoError(t, handler.ReceivedPacket(11, protocol.ECNNon, protocol.Encryption1RTT, now, true))
	ack := handler.GetAckFrame(protocol.Encryption1RTT, now, false)
	require.NotNil(t, ack)
	require.Equal(t, []wire.AckRange{{Smallest: 8, Largest: 11}}, ack.AckRanges)
}
