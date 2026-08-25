package ackhandler

import (
	"fmt"
	"time"

	"github.com/sardanioss/quic-go/internal/monotime"
	"github.com/sardanioss/quic-go/internal/protocol"
	"github.com/sardanioss/quic-go/internal/utils"
	"github.com/sardanioss/quic-go/internal/wire"
)

const reorderingThreshold = 1

// The receivedPacketTracker tracks packets for the Initial and Handshake packet number space.
// Every received packet is acknowledged immediately.
type receivedPacketTracker struct {
	ect0, ect1, ecnce uint64

	packetHistory receivedPacketHistory

	lastAck   *wire.AckFrame
	hasNewAck bool // true as soon as we received an ack-eliciting new packet
}

func newReceivedPacketTracker() *receivedPacketTracker {
	return &receivedPacketTracker{packetHistory: *newReceivedPacketHistory()}
}

func (h *receivedPacketTracker) ReceivedPacket(pn protocol.PacketNumber, ecn protocol.ECN, ackEliciting bool) error {
	if isNew := h.packetHistory.ReceivedPacket(pn); !isNew {
		return fmt.Errorf("receivedPacketTracker BUG: ReceivedPacket called for old / duplicate packet %d", pn)
	}

	//nolint:exhaustive // Only need to count ECT(0), ECT(1) and ECN-CE.
	switch ecn {
	case protocol.ECT0:
		h.ect0++
	case protocol.ECT1:
		h.ect1++
	case protocol.ECNCE:
		h.ecnce++
	}
	if !ackEliciting {
		return nil
	}
	h.hasNewAck = true
	return nil
}

func (h *receivedPacketTracker) GetAckFrame() *wire.AckFrame {
	if !h.hasNewAck {
		return nil
	}

	// This function always returns the same ACK frame struct, filled with the most recent values.
	ack := h.lastAck
	if ack == nil {
		ack = &wire.AckFrame{}
	}
	ack.Reset()
	ack.ECT0 = h.ect0
	ack.ECT1 = h.ect1
	ack.ECNCE = h.ecnce
	for r := range h.packetHistory.Backward() {
		ack.AckRanges = append(ack.AckRanges, wire.AckRange{Smallest: r.Start, Largest: r.End})
	}

	h.lastAck = ack
	h.hasNewAck = false
	return ack
}

func (h *receivedPacketTracker) IsPotentiallyDuplicate(pn protocol.PacketNumber) bool {
	return h.packetHistory.IsPotentiallyDuplicate(pn)
}

// ACK decimation, from quiche's QuicReceivedPacketManager.
//
// A client that acknowledges every second packet forever is welded to a ratio
// no real one holds. quiche starts at 2 and raises the threshold to 10 once the
// peer has sent 100 ack-eliciting packets, and once decimated it also stops
// using a flat max_ack_delay alarm and scales it to a quarter of min_rtt.
//
// The discriminator is not any single ratio: below the crossover the alarm
// governs and a browser also lands near one ACK per two packets. It is the
// INVARIANCE. Sweep the send rate over two decades and a real client's ratio
// walks from about 1 through 2 to about 10, while a fixed threshold stays at
// exactly 2.00 throughout.
const (
	// packetsBeforeAck is the threshold before decimation kicks in.
	packetsBeforeAck = 2
	// packetsBeforeAckDecimated is the threshold after it does.
	// quiche: kMaxRetransmittablePacketsBeforeAck.
	packetsBeforeAckDecimated = 10
	// minReceivedBeforeAckDecimation is how many ack-eliciting packets the peer
	// must have sent before the threshold is raised.
	// quiche: kMinReceivedBeforeAckDecimation.
	minReceivedBeforeAckDecimation = 100
	// ackDecimationDelayDivisor scales the ACK alarm to a fraction of min_rtt
	// once decimated. quiche uses a quarter.
	ackDecimationDelayDivisor = 4
	// minAckDecimationDelay is the floor on that scaled alarm.
	minAckDecimationDelay = time.Millisecond
)

// The appDataReceivedPacketTracker tracks packets received in the Application Data packet number space.
// It waits until at least 2 packets were received before queueing an ACK, or until the max_ack_delay was reached.
type appDataReceivedPacketTracker struct {
	receivedPacketTracker

	largestObservedRcvdTime monotime.Time

	largestObserved protocol.PacketNumber
	ignoreBelow     protocol.PacketNumber

	maxAckDelay time.Duration
	ackQueued   bool // true if we need send a new ACK

	ackElicitingPacketsReceivedSinceLastAck int
	ackAlarm                                monotime.Time

	// ackElicitingPacketsReceived counts every ack-eliciting packet the peer
	// has sent on this connection, which is what decimation keys off.
	ackElicitingPacketsReceived int

	rttStats *utils.RTTStats
	logger   utils.Logger
}

func newAppDataReceivedPacketTracker(rttStats *utils.RTTStats, logger utils.Logger) *appDataReceivedPacketTracker {
	h := &appDataReceivedPacketTracker{
		receivedPacketTracker: *newReceivedPacketTracker(),
		maxAckDelay:           protocol.MaxAckDelay,
		rttStats:              rttStats,
		logger:                logger,
	}
	return h
}

// decimated reports whether the peer has sent enough for the raised threshold
// to apply.
func (h *appDataReceivedPacketTracker) decimated() bool {
	return h.ackElicitingPacketsReceived >= minReceivedBeforeAckDecimation
}

// packetsBeforeAck is the number of ack-eliciting packets to wait for before
// queueing an ACK.
func (h *appDataReceivedPacketTracker) packetsBeforeAck() int {
	if h.decimated() {
		return packetsBeforeAckDecimated
	}
	return packetsBeforeAck
}

// ackDelay is how long to wait before sending an ACK that the threshold has not
// already triggered.
//
// quiche uses the flat local_max_ack_delay_ until decimation, then
// max(min(local_max_ack_delay_, min_rtt/4), 1ms). Waiting a flat 25ms on a
// decimated connection would undo the threshold on any path slower than 100ms.
func (h *appDataReceivedPacketTracker) ackDelay() time.Duration {
	if !h.decimated() || h.rttStats == nil {
		return h.maxAckDelay
	}
	minRTT := h.rttStats.MinRTT()
	if minRTT <= 0 {
		return h.maxAckDelay
	}
	return max(min(h.maxAckDelay, minRTT/ackDecimationDelayDivisor), minAckDecimationDelay)
}

func (h *appDataReceivedPacketTracker) ReceivedPacket(pn protocol.PacketNumber, ecn protocol.ECN, rcvTime monotime.Time, ackEliciting bool) error {
	if err := h.receivedPacketTracker.ReceivedPacket(pn, ecn, ackEliciting); err != nil {
		return err
	}
	if pn >= h.largestObserved {
		h.largestObserved = pn
		h.largestObservedRcvdTime = rcvTime
	}
	if !ackEliciting {
		return nil
	}
	h.ackElicitingPacketsReceivedSinceLastAck++
	h.ackElicitingPacketsReceived++
	isMissing := h.isMissing(pn)
	if !h.ackQueued && h.shouldQueueACK(pn, ecn, isMissing) {
		h.ackQueued = true
		h.ackAlarm = 0 // cancel the ack alarm
	}
	if !h.ackQueued {
		// No ACK queued, but we'll need to acknowledge the packet after max_ack_delay.
		delay := h.ackDelay()
		h.ackAlarm = rcvTime.Add(delay)
		if h.logger.Debug() {
			h.logger.Debugf("\tSetting ACK timer to %s", delay)
		}
	}
	return nil
}

// IgnoreBelow sets a lower limit for acknowledging packets.
// Packets with packet numbers smaller than p will not be acked.
func (h *appDataReceivedPacketTracker) IgnoreBelow(pn protocol.PacketNumber) {
	if pn <= h.ignoreBelow {
		return
	}
	h.ignoreBelow = pn
	h.packetHistory.DeleteBelow(pn)
	if h.logger.Debug() {
		h.logger.Debugf("\tIgnoring all packets below %d.", pn)
	}
}

// isMissing says if a packet was reported missing in the last ACK.
func (h *appDataReceivedPacketTracker) isMissing(p protocol.PacketNumber) bool {
	if h.lastAck == nil || p < h.ignoreBelow {
		return false
	}
	return p < h.lastAck.LargestAcked() && !h.lastAck.AcksPacket(p)
}

func (h *appDataReceivedPacketTracker) hasNewMissingPackets() bool {
	if h.lastAck == nil {
		return false
	}
	if h.largestObserved < reorderingThreshold {
		return false
	}
	highestMissing := h.packetHistory.HighestMissingUpTo(h.largestObserved - reorderingThreshold)
	if highestMissing == protocol.InvalidPacketNumber {
		return false
	}
	if highestMissing < h.lastAck.LargestAcked() {
		// the packet was already reported missing in the last ACK
		return false
	}
	return highestMissing > h.lastAck.LargestAcked()-reorderingThreshold
}

func (h *appDataReceivedPacketTracker) shouldQueueACK(pn protocol.PacketNumber, ecn protocol.ECN, wasMissing bool) bool {
	// Send an ACK if this packet was reported missing in an ACK sent before.
	// Ack decimation with reordering relies on the timer to send an ACK, but if
	// missing packets we reported in the previous ACK, send an ACK immediately.
	if wasMissing {
		if h.logger.Debug() {
			h.logger.Debugf("\tQueueing ACK because packet %d was missing before.", pn)
		}
		return true
	}

	// send an ACK once enough ack-eliciting packets have arrived
	threshold := h.packetsBeforeAck()
	if h.ackElicitingPacketsReceivedSinceLastAck >= threshold {
		if h.logger.Debug() {
			h.logger.Debugf("\tQueueing ACK because %d packets were received after the last ACK (threshold: %d).", h.ackElicitingPacketsReceivedSinceLastAck, threshold)
		}
		return true
	}

	// queue an ACK if there are new missing packets to report
	if h.hasNewMissingPackets() {
		h.logger.Debugf("\tQueuing ACK because there's a new missing packet to report.")
		return true
	}

	// queue an ACK if the packet was ECN-CE marked
	if ecn == protocol.ECNCE {
		h.logger.Debugf("\tQueuing ACK because the packet was ECN-CE marked.")
		return true
	}
	return false
}

func (h *appDataReceivedPacketTracker) GetAckFrame(now monotime.Time, onlyIfQueued bool) *wire.AckFrame {
	if onlyIfQueued && !h.ackQueued {
		if h.ackAlarm.IsZero() || h.ackAlarm.After(now) {
			return nil
		}
		if h.logger.Debug() && !h.ackAlarm.IsZero() {
			h.logger.Debugf("Sending ACK because the ACK timer expired.")
		}
	}
	ack := h.receivedPacketTracker.GetAckFrame()
	if ack == nil {
		return nil
	}
	ack.DelayTime = max(0, now.Sub(h.largestObservedRcvdTime))
	h.ackQueued = false
	h.ackAlarm = 0
	h.ackElicitingPacketsReceivedSinceLastAck = 0
	return ack
}

func (h *appDataReceivedPacketTracker) GetAlarmTimeout() monotime.Time { return h.ackAlarm }
