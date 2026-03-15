package quic

import (
	"io"
	"net"
	"syscall"
	"time"

	"github.com/sardanioss/quic-go/internal/monotime"
	"github.com/sardanioss/quic-go/internal/protocol"
	"github.com/sardanioss/quic-go/internal/utils"
)

type connCapabilities struct {
	// This connection has the Don't Fragment (DF) bit set.
	// This means it makes to run DPLPMTUD.
	DF bool
	// GSO (Generic Segmentation Offload) supported
	GSO bool
	// ECN (Explicit Congestion Notifications) supported
	ECN bool
}

// rawConn is a connection that allow reading of a receivedPackeh.
type rawConn interface {
	ReadPacket() (receivedPacket, error)
	// WritePacket writes a packet on the wire.
	// gsoSize is the size of a single packet, or 0 to disable GSO.
	// It is invalid to set gsoSize if capabilities.GSO is not set.
	WritePacket(b []byte, addr net.Addr, packetInfoOOB []byte, gsoSize uint16, ecn protocol.ECN) (int, error)
	LocalAddr() net.Addr
	SetReadDeadline(time.Time) error
	io.Closer

	capabilities() connCapabilities
}

// OOBCapablePacketConn is a connection that allows the reading of ECN bits from the IP header.
// If the PacketConn passed to the [Transport] satisfies this interface, quic-go will use it.
// In this case, ReadMsgUDP() will be used instead of ReadFrom() to read packets.
type OOBCapablePacketConn interface {
	net.PacketConn
	SyscallConn() (syscall.RawConn, error)
	SetReadBuffer(int) error
	ReadMsgUDP(b, oob []byte) (n, oobn, flags int, addr *net.UDPAddr, err error)
	WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (n, oobn int, err error)
}

var _ OOBCapablePacketConn = &net.UDPConn{}

func wrapConn(pc net.PacketConn) (rawConn, error) {
	// Best-effort: try to increase kernel buffers, silently ignore failures.
	// On constrained systems the userspace bufferedConn compensates for
	// small receive buffers, and send buffer size is rarely the bottleneck.
	setReceiveBuffer(pc)
	setSendBuffer(pc)

	conn, ok := pc.(interface {
		SyscallConn() (syscall.RawConn, error)
	})
	var supportsDF bool
	var syscallConn syscall.RawConn
	if ok {
		var err error
		syscallConn, err = conn.SyscallConn()
		if err != nil {
			return nil, err
		}

		// only set DF on UDP sockets
		if _, ok := pc.LocalAddr().(*net.UDPAddr); ok {
			supportsDF, err = setDF(syscallConn)
			if err != nil {
				return nil, err
			}
		}
	}

	var rc rawConn
	c, ok := pc.(OOBCapablePacketConn)
	if !ok {
		utils.DefaultLogger.Infof("PacketConn is not a net.UDPConn. Disabling optimizations possible on UDP connections.")
		rc = &basicConn{PacketConn: pc, supportsDF: supportsDF}
	} else {
		var err error
		rc, err = newConn(c, supportsDF)
		if err != nil {
			return nil, err
		}
	}

	// If the kernel receive buffer is smaller than desired, wrap with
	// userspace buffering to prevent packet drops during bursts.
	if syscallConn != nil {
		rcvBufSize, err := inspectReadBuffer(syscallConn)
		if err == nil && rcvBufSize > 0 && rcvBufSize < protocol.DesiredReceiveBufferSize {
			bufSize := computeBufferSize(rcvBufSize)
			utils.DefaultLogger.Debugf("Kernel UDP rcv buffer %d kiB < desired %d kiB, adding userspace buffer (%d slots)",
				rcvBufSize/1024, protocol.DesiredReceiveBufferSize/1024, bufSize)
			rc = newBufferedConn(rc, bufSize)
		}
	}

	return rc, nil
}

// The basicConn is the most trivial implementation of a rawConn.
// It reads a single packet from the underlying net.PacketConn.
// It is used when
// * the net.PacketConn is not a OOBCapablePacketConn, and
// * when the OS doesn't support OOB.
type basicConn struct {
	net.PacketConn
	supportsDF bool
}

var _ rawConn = &basicConn{}

func (c *basicConn) ReadPacket() (receivedPacket, error) {
	buffer := getPacketBuffer()
	// The packet size should not exceed protocol.MaxPacketBufferSize bytes
	// If it does, we only read a truncated packet, which will then end up undecryptable
	buffer.Data = buffer.Data[:protocol.MaxPacketBufferSize]
	n, addr, err := c.ReadFrom(buffer.Data)
	if err != nil {
		return receivedPacket{}, err
	}
	return receivedPacket{
		remoteAddr: addr,
		rcvTime:    monotime.Now(),
		data:       buffer.Data[:n],
		buffer:     buffer,
	}, nil
}

func (c *basicConn) WritePacket(b []byte, addr net.Addr, _ []byte, gsoSize uint16, ecn protocol.ECN) (n int, err error) {
	if gsoSize != 0 {
		panic("cannot use GSO with a basicConn")
	}
	if ecn != protocol.ECNUnsupported {
		panic("cannot use ECN with a basicConn")
	}
	return c.WriteTo(b, addr)
}

func (c *basicConn) capabilities() connCapabilities { return connCapabilities{DF: c.supportsDF} }
