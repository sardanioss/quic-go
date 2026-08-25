package ackhandler

import (
	"testing"
	"time"

	"github.com/sardanioss/quic-go/internal/monotime"
	"github.com/sardanioss/quic-go/internal/protocol"
	"github.com/sardanioss/quic-go/internal/utils"
)

// ACK decimation.
//
// A client that acknowledges every second packet forever is welded to a ratio
// no real one holds. quiche starts at 2 and raises the threshold to 10 once the
// peer has sent 100 ack-eliciting packets, and once decimated scales the ACK
// alarm to a quarter of min_rtt instead of a flat max_ack_delay.
//
// The discriminating observation is not any single ratio. Below the crossover
// the alarm governs and a browser also lands near one ACK per two packets; at
// the very fast end a browser sends MORE ACKs than a fixed threshold does. It
// is the INVARIANCE: sweep the send rate over two decades and a real client's
// ratio walks from about 1 through 2 to about 10, while a fixed threshold sits
// at exactly 2.00 throughout. So the lock below measures a sweep, not a point.

// ackRatio drives the tracker with n ack-eliciting packets spaced `spacing`
// apart and returns packets-per-ACK.
func ackRatio(t *testing.T, minRTT time.Duration, packets int, spacing time.Duration) float64 {
	t.Helper()
	rtt := &utils.RTTStats{}
	if minRTT > 0 {
		rtt.UpdateRTT(minRTT, 0)
	}
	h := newAppDataReceivedPacketTracker(rtt, utils.DefaultLogger)

	// Both the packet arrivals and the ACK alarm have to be modelled, or the
	// alarm can never fire and the sweep measures only the threshold. The
	// connection wakes on whichever comes first.
	now := monotime.Now()
	next := now.Add(spacing)
	sent, acks := 0, 0
	for sent < packets {
		if alarm := h.GetAlarmTimeout(); !alarm.IsZero() && alarm.Before(next) {
			now = alarm
			if h.GetAckFrame(now, true) != nil {
				acks++
			}
			continue
		}
		now = next
		next = now.Add(spacing)
		if err := h.ReceivedPacket(protocol.PacketNumber(sent), protocol.ECNNon, now, true); err != nil {
			t.Fatalf("packet %d: %v", sent, err)
		}
		sent++
		if h.GetAckFrame(now, true) != nil {
			acks++
		}
	}
	if acks == 0 {
		return float64(packets)
	}
	return float64(packets) / float64(acks)
}

// The threshold rises once the peer has sent enough, and the ratio moves with
// it. A fixed threshold gives 2.00 at every rate.
func TestAckRatioWalksWithTheSendRate(t *testing.T) {
	const minRTT = 40 * time.Millisecond

	// Fast enough that the threshold governs rather than the alarm: ten
	// packets arrive well inside a quarter of min_rtt.
	fast := ackRatio(t, minRTT, 400, 200*time.Microsecond)
	// Slow enough that the alarm fires first and the threshold cannot.
	slow := ackRatio(t, minRTT, 400, 20*time.Millisecond)

	t.Logf("packets per ACK: fast(200us)=%.2f slow(20ms)=%.2f", fast, slow)
	if fast < 5 {
		t.Errorf("at 200us spacing the ratio is %.2f packets per ACK; past the "+
			"decimation point the threshold should be carrying it to near 10", fast)
	}
	if slow > 3 {
		t.Errorf("at 20ms spacing the ratio is %.2f packets per ACK; the alarm "+
			"should be firing well before the threshold", slow)
	}
	if fast <= slow {
		t.Errorf("the ratio did not move with the send rate: fast %.2f, slow %.2f. "+
			"A client whose ratio is invariant across a sweep is identifiable "+
			"without any single measurement being wrong", fast, slow)
	}
}

// Before the crossover the threshold is 2, which is also what a browser does.
// The fix must not make the early part of a connection unusual.
func TestAckRatioBeforeDecimationIsTwo(t *testing.T) {
	const minRTT = 40 * time.Millisecond
	// Well under 100 ack-eliciting packets, so decimation cannot have engaged.
	ratio := ackRatio(t, minRTT, 60, 200*time.Microsecond)
	if ratio < 1.8 || ratio > 2.2 {
		t.Errorf("before decimation the ratio is %.2f packets per ACK, want about 2", ratio)
	}
}

// The threshold and the alarm, asserted directly rather than inferred.
func TestDecimationStateTransitions(t *testing.T) {
	rtt := &utils.RTTStats{}
	rtt.UpdateRTT(40*time.Millisecond, 0)
	h := newAppDataReceivedPacketTracker(rtt, utils.DefaultLogger)

	if got := h.packetsBeforeAck(); got != 2 {
		t.Errorf("fresh connection threshold = %d, want 2", got)
	}
	if got := h.ackDelay(); got != protocol.MaxAckDelay {
		t.Errorf("fresh connection ACK delay = %v, want the flat %v", got, protocol.MaxAckDelay)
	}

	now := monotime.Now()
	for i := 0; i < minReceivedBeforeAckDecimation; i++ {
		now = now.Add(time.Microsecond)
		h.ReceivedPacket(protocol.PacketNumber(i), protocol.ECNNon, now, true)
		h.GetAckFrame(now, true)
	}

	if got := h.packetsBeforeAck(); got != packetsBeforeAckDecimated {
		t.Errorf("after %d ack-eliciting packets the threshold is %d, want %d",
			minReceivedBeforeAckDecimation, got, packetsBeforeAckDecimated)
	}
	// min_rtt/4 is 10ms, below the flat 25ms, so it wins.
	if got, want := h.ackDelay(), 10*time.Millisecond; got != want {
		t.Errorf("decimated ACK delay = %v, want %v (a quarter of min_rtt)", got, want)
	}
}

// On a fast path a quarter of min_rtt is under a millisecond, and the floor
// takes over. Without it a decimated connection on loopback would send an ACK
// almost per packet, which is the opposite of the intent.
func TestDecimatedAckDelayHasAFloor(t *testing.T) {
	rtt := &utils.RTTStats{}
	rtt.UpdateRTT(400*time.Microsecond, 0)
	h := newAppDataReceivedPacketTracker(rtt, utils.DefaultLogger)
	h.ackElicitingPacketsReceived = minReceivedBeforeAckDecimation

	if got := h.ackDelay(); got != minAckDecimationDelay {
		t.Errorf("with a 400us min_rtt the decimated ACK delay is %v, want the %v floor",
			got, minAckDecimationDelay)
	}
}

// With no RTT sample yet, the flat delay stands rather than collapsing to the
// floor. A connection that has measured nothing must not start acking on a
// one-millisecond timer.
func TestDecimatedAckDelayWithoutAnRTTSample(t *testing.T) {
	h := newAppDataReceivedPacketTracker(&utils.RTTStats{}, utils.DefaultLogger)
	h.ackElicitingPacketsReceived = minReceivedBeforeAckDecimation
	if got := h.ackDelay(); got != protocol.MaxAckDelay {
		t.Errorf("with no RTT sample the decimated ACK delay is %v, want the flat %v",
			got, protocol.MaxAckDelay)
	}
}
