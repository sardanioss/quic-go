package ackhandler

import (
	"testing"
	"time"

	"github.com/sardanioss/quic-go/internal/monotime"
	"github.com/sardanioss/quic-go/internal/protocol"
	"github.com/sardanioss/quic-go/internal/utils"
	"github.com/sardanioss/quic-go/internal/wire"
)

func TestDiagnosticPTOClearsOutstandingAfterProbeACK(t *testing.T) {
	rtt := utils.NewRTTStats()
	rtt.UpdateRTT(time.Millisecond, 0)
	rtt.SetMaxAckDelay(25 * time.Millisecond)
	h := NewSentPacketHandler(0, 1200, rtt, &utils.ConnectionStats{}, false, false, nil, protocol.PerspectiveClient, nil, utils.DefaultLogger).(*sentPacketHandler)
	h.handshakeConfirmed = true
	h.peerCompletedAddressValidation = true
	h.initialPackets = nil
	h.handshakePackets = nil
	now := monotime.Now()
	send := func(at monotime.Time) protocol.PacketNumber {
		pn := h.PopPacketNumber(protocol.Encryption1RTT)
		h.SentPacket(at, pn, protocol.InvalidPacketNumber, nil, []Frame{{Frame: &wire.PingFrame{}}}, protocol.Encryption1RTT, protocol.ECNNon, 41, false, false)
		return pn
	}
	original := send(now)
	firstPTO := h.GetLossDetectionTimeout()
	if firstPTO.IsZero() {
		t.Fatal("missing initial PTO")
	}
	if err := h.OnLossDetectionTimeout(firstPTO); err != nil {
		t.Fatal(err)
	}
	if !h.QueueProbePacket(protocol.Encryption1RTT) {
		t.Fatal("probe not queued")
	}
	t.Logf("original PN %d removed: history length=%d outstanding=%d bytes=%d", original, h.appDataPackets.history.Len(), h.appDataPackets.history.numOutstanding, h.bytesInFlight)
	pn1 := send(firstPTO)
	pn2 := send(firstPTO)
	_, err := h.ReceivedAck(&wire.AckFrame{AckRanges: ackRanges(pn1, pn2)}, protocol.Encryption1RTT, firstPTO.Add(time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("ACK all probes: history length=%d outstanding=%d bytes=%d PTO=%v ptoCount=%d", h.appDataPackets.history.Len(), h.appDataPackets.history.numOutstanding, h.bytesInFlight, h.GetLossDetectionTimeout(), h.ptoCount)
	if h.appDataPackets.history.HasOutstandingPackets() {
		t.Errorf("phantom outstanding packets after ACK of all probes: %d", h.appDataPackets.history.numOutstanding)
	}
	if !h.GetLossDetectionTimeout().IsZero() {
		t.Errorf("PTO stays armed after all actual packets were acknowledged")
	}
}
