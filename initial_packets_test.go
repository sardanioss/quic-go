package quic

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/sardanioss/quic-go/internal/handshake"
	"github.com/sardanioss/quic-go/internal/protocol"
	"github.com/sardanioss/quic-go/quicvarint"
	tls "github.com/sardanioss/utls"

	"github.com/stretchr/testify/require"
)

// sentInitial is one client Initial packet as a server reads it.
type sentInitial struct {
	datagram int // size of the datagram it came in
	pn       protocol.PacketNumber
	pnLen    int
	frames   []string // "CRYPTO offset+length", "PADDING n" or "PING"
}

// clientInitials dials a socket that never answers and decrypts the first n
// datagrams the client sends, each holding one Initial packet.
func clientInitials(t *testing.T, conf *Config, n int) []sentInitial {
	t.Helper()
	ln, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	defer ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	dialed := make(chan struct{})
	go func() {
		defer close(dialed)
		// A name, so the ClientHello carries SNI.
		DialAddr(ctx, ln.LocalAddr().String(), &tls.Config{ServerName: "localhost", NextProtos: []string{"h3"}}, conf)
	}()
	defer func() { cancel(); <-dialed }()

	var out []sentInitial
	var origDestConnID protocol.ConnectionID
	buf := make([]byte, 2048)
	require.NoError(t, ln.SetReadDeadline(time.Now().Add(5*time.Second)))
	for len(out) < n {
		size, _, err := ln.ReadFromUDP(buf)
		require.NoError(t, err)
		data := buf[:size]
		require.Equal(t, byte(0xc0), data[0]&0xf0, "an Initial packet")

		p := 5
		destConnID := protocol.ParseConnectionID(data[p+1 : p+1+int(data[p])])
		if origDestConnID.Len() == 0 {
			origDestConnID = destConnID
		}
		p += 1 + int(data[p])
		p += 1 + int(data[p]) // source connection ID
		tokenLen, l, err := quicvarint.Parse(data[p:])
		require.NoError(t, err)
		p += l + int(tokenLen)
		length, l, err := quicvarint.Parse(data[p:])
		require.NoError(t, err)
		p += l
		require.Equal(t, size, p+int(length), "one packet per datagram")

		// The keys come from the first destination connection ID.
		_, opener := handshake.NewInitialAEAD(origDestConnID, protocol.PerspectiveServer, protocol.Version1)
		// The mask covers four bytes; those past the packet number are
		// ciphertext and get put back, as the unpacker does.
		orig := append([]byte(nil), data[p:p+4]...)
		opener.DecryptHeader(data[p+4:p+20], &data[0], data[p:p+4])
		pnLen := int(data[0]&0x3) + 1
		copy(data[p+pnLen:p+4], orig[pnLen:])
		var wirePN protocol.PacketNumber
		for _, b := range data[p : p+pnLen] {
			wirePN = wirePN<<8 | protocol.PacketNumber(b)
		}
		pn := opener.DecodePacketNumber(wirePN, protocol.PacketNumberLen(pnLen))
		payload, err := opener.Open(nil, data[p+pnLen:size], pn, data[:p+pnLen])
		require.NoError(t, err)

		pkt := sentInitial{datagram: size, pn: pn, pnLen: pnLen}
		for len(payload) > 0 {
			switch payload[0] {
			case 0x00:
				z := 0
				for z < len(payload) && payload[z] == 0 {
					z++
				}
				pkt.frames = append(pkt.frames, fmt.Sprintf("PADDING %d", z))
				payload = payload[z:]
			case 0x01:
				pkt.frames = append(pkt.frames, "PING")
				payload = payload[1:]
			case 0x06:
				q := 1
				off, l, err := quicvarint.Parse(payload[q:])
				require.NoError(t, err)
				q += l
				dataLen, l, err := quicvarint.Parse(payload[q:])
				require.NoError(t, err)
				q += l
				pkt.frames = append(pkt.frames, fmt.Sprintf("CRYPTO %d+%d", off, dataLen))
				payload = payload[q+int(dataLen):]
			default:
				t.Fatalf("unexpected frame type %#x in a client Initial", payload[0])
			}
		}
		out = append(out, pkt)
	}
	return out
}

// helloLength reads the ClientHello length off the first Initial's CRYPTO
// frames, which together carry the whole hello in these tests.
func cryptoTotal(pkts []sentInitial) int {
	total := 0
	for _, p := range pkts {
		for _, f := range p.frames {
			var off, l int
			if _, err := fmt.Sscanf(f, "CRYPTO %d+%d", &off, &l); err == nil {
				total = max(total, off+l)
			}
		}
	}
	return total
}

func TestClientInitialPacketsDefault(t *testing.T) {
	pkts := clientInitials(t, &Config{InitialPacketSize: 1200, DisableClientHelloScrambling: true}, 2)
	total := cryptoTotal(pkts)
	require.Greater(t, total, 1200, "the ClientHello needs two Initials")

	// Chrome's first packet number and two-byte packet numbers; the first
	// packet filled with ClientHello bytes.
	require.Equal(t, protocol.PacketNumber(1), pkts[0].pn)
	require.Equal(t, 2, pkts[0].pnLen)
	require.Equal(t, protocol.PacketNumber(2), pkts[1].pn)
	require.Equal(t, 2, pkts[1].pnLen)
	require.Len(t, pkts[0].frames, 1)
	first := 1200 - 20 - 16 - 4 // header, AEAD tag and CRYPTO frame header
	require.Equal(t, fmt.Sprintf("CRYPTO 0+%d", first), pkts[0].frames[0])
	require.Equal(t, fmt.Sprintf("CRYPTO %d+%d", first, total-first), pkts[1].frames[0])
}

func TestClientInitialPacketsSafari(t *testing.T) {
	pkts := clientInitials(t, &Config{
		InitialPacketSize:            1200,
		DisableClientHelloScrambling: true,
		InitialCryptoDataPerPacket:   999,
		PacketNumbersFromZero:        true,
		ShortInitialPacketNumbers:    true,
	}, 2)
	total := cryptoTotal(pkts)
	require.Greater(t, total, 999)

	// Safari 26.3's first two Initials: pn 0 and 1 in one byte each, CRYPTO
	// 0+999 then the rest, each followed by padding to 1200 bytes. A header
	// of 19 bytes with an 8-byte destination and empty source connection ID
	// leaves 1200-19-16 = 1165 bytes of frames.
	header := 1 + 4 + 1 + 8 + 1 + 0 + 1 + 2 + 1
	for i, p := range pkts {
		require.Equal(t, 1200, p.datagram)
		require.Equal(t, protocol.PacketNumber(i), p.pn)
		require.Equal(t, 1, p.pnLen)
	}
	frames := 1200 - header - 16
	require.Equal(t, []string{"CRYPTO 0+999", fmt.Sprintf("PADDING %d", frames-4-999)}, pkts[0].frames)
	second := total - 999
	require.Equal(t, []string{
		fmt.Sprintf("CRYPTO 999+%d", second),
		fmt.Sprintf("PADDING %d", frames-1-2-quicvarint.Len(uint64(second))-second),
	}, pkts[1].frames)
}

func TestClientInitialCryptoCapWithScrambling(t *testing.T) {
	// With the ClientHello scrambled around its SNI, the cap still holds for
	// every Initial packet, and the hello still arrives whole.
	pkts := clientInitials(t, &Config{InitialPacketSize: 1200, InitialCryptoDataPerPacket: 500}, 3)
	for _, p := range pkts {
		sum := 0
		for _, f := range p.frames {
			var off, l int
			if _, err := fmt.Sscanf(f, "CRYPTO %d+%d", &off, &l); err == nil {
				sum += l
			}
		}
		require.LessOrEqual(t, sum, 500, "%v", p.frames)
	}
}
