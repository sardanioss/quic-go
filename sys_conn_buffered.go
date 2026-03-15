package quic

import (
	"net"
	"time"

	"github.com/sardanioss/quic-go/internal/protocol"
)

// bufferedConn wraps a rawConn with a userspace receive buffer.
// A dedicated drain goroutine reads packets from the inner connection
// as fast as possible and pushes them into a bounded channel, keeping
// the kernel UDP receive buffer permanently drained. This prevents
// silent packet drops on systems where the kernel limits the socket
// receive buffer to a size smaller than protocol.DesiredReceiveBufferSize.
type bufferedConn struct {
	inner   rawConn
	packets chan receivedPacket // bounded FIFO
	errChan chan error          // capacity 1, first fatal read error
	done    chan struct{}       // closed when drain goroutine exits
}

var _ rawConn = &bufferedConn{}

// newBufferedConn wraps inner with a userspace packet buffer of the given size.
// The drain goroutine starts immediately.
func newBufferedConn(inner rawConn, bufSize int) *bufferedConn {
	bc := &bufferedConn{
		inner:   inner,
		packets: make(chan receivedPacket, bufSize),
		errChan: make(chan error, 1),
		done:    make(chan struct{}),
	}
	go bc.drain()
	return bc
}

// drain reads packets from the inner connection in a tight loop and
// pushes them into the packets channel. On channel full, the packet
// is tail-dropped and its buffer returned to the pool.
func (bc *bufferedConn) drain() {
	defer close(bc.done)
	for {
		p, err := bc.inner.ReadPacket()
		if err != nil {
			// Send the first fatal error; non-blocking in case errChan is full.
			select {
			case bc.errChan <- err:
			default:
			}
			return
		}
		// Non-blocking send: if the channel is full, tail-drop.
		select {
		case bc.packets <- p:
		default:
			// Channel full — drop this packet and return its buffer to the pool.
			p.buffer.Release()
		}
	}
}

// ReadPacket returns the next buffered packet, or an error if the
// inner connection has failed.
func (bc *bufferedConn) ReadPacket() (receivedPacket, error) {
	// Priority check: if there's already a fatal error and no packets
	// left, return the error immediately.
	select {
	case err := <-bc.errChan:
		bc.drainRemaining()
		return receivedPacket{}, err
	default:
	}

	// Block until a packet or error arrives.
	select {
	case p := <-bc.packets:
		return p, nil
	case err := <-bc.errChan:
		bc.drainRemaining()
		return receivedPacket{}, err
	}
}

// drainRemaining releases all buffered packetBuffers back to the pool.
// Called on shutdown to prevent buffer pool exhaustion.
func (bc *bufferedConn) drainRemaining() {
	for {
		select {
		case p := <-bc.packets:
			p.buffer.Release()
		default:
			return
		}
	}
}

// WritePacket is a pure passthrough to the inner connection.
func (bc *bufferedConn) WritePacket(b []byte, addr net.Addr, packetInfoOOB []byte, gsoSize uint16, ecn protocol.ECN) (int, error) {
	return bc.inner.WritePacket(b, addr, packetInfoOOB, gsoSize, ecn)
}

// LocalAddr delegates to the inner connection.
func (bc *bufferedConn) LocalAddr() net.Addr {
	return bc.inner.LocalAddr()
}

// SetReadDeadline delegates to the inner connection.
// This is how Transport.Close() triggers the drain goroutine to exit:
// setting a deadline in the past causes inner.ReadPacket() to return
// a timeout error, which the drain goroutine sends to errChan.
func (bc *bufferedConn) SetReadDeadline(t time.Time) error {
	return bc.inner.SetReadDeadline(t)
}

// Close delegates to the inner connection.
func (bc *bufferedConn) Close() error {
	return bc.inner.Close()
}

// capabilities delegates to the inner connection.
func (bc *bufferedConn) capabilities() connCapabilities {
	return bc.inner.capabilities()
}

// computeBufferSize calculates the number of packet slots needed for
// userspace buffering given the actual kernel receive buffer size.
// It computes the deficit between the desired and actual buffer sizes,
// converts to packet count at MaxPacketBufferSize (1472) bytes per packet,
// and clamps to [256, 4096].
func computeBufferSize(kernelBufSize int) int {
	deficit := protocol.DesiredReceiveBufferSize - kernelBufSize
	if deficit <= 0 {
		return 256 // minimum; shouldn't happen since caller checks
	}
	slots := deficit / protocol.MaxPacketBufferSize
	if slots < 256 {
		return 256
	}
	if slots > 4096 {
		return 4096
	}
	return slots
}
