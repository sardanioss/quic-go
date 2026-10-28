package http3

import (
	"context"
	"testing"
	"time"

	http "github.com/sardanioss/http"
	"github.com/sardanioss/http/httptest"
	"github.com/sardanioss/quic-go"
	"github.com/sardanioss/quic-go/qlog"
	"github.com/sardanioss/quic-go/testutils/events"
	tls "github.com/sardanioss/utls"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// CloseConn decides how Close and CloseIdleConnections end a connection. Here
// it closes the way Chromium does at shutdown, and the server receives one
// packet holding an ACK and a transport CONNECTION_CLOSE with Chromium's code
// and reason.
func TestTransportCloseConn(t *testing.T) {
	for _, tc := range []struct {
		name  string
		close func(*testing.T, *Transport)
	}{
		{"Close", func(t *testing.T, tr *Transport) { require.NoError(t, tr.Close()) }},
		{"CloseIdleConnections", func(t *testing.T, tr *Transport) { tr.CloseIdleConnections() }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mockCtrl := gomock.NewController(t)
			var rec events.Recorder
			conn, server := newConnPair(t, withServerRecorder(&rec))
			tr := &Transport{
				Dial: func(context.Context, string, *tls.Config, *quic.Config) (*quic.Conn, error) {
					return conn, nil
				},
				newClientConn: func(*quic.Conn) clientConn {
					cl := NewMockClientConn(mockCtrl)
					cl.EXPECT().RoundTrip(gomock.Any()).Return(&http.Response{}, nil)
					return cl
				},
				CloseConn: func(c *quic.Conn) error {
					return c.CloseWithTransportError(quic.NoError, "70:net error")
				},
			}
			req := httptest.NewRequest(http.MethodGet, "https://quic-go.net/foobar.html", nil)
			_, err := tr.RoundTrip(req)
			require.NoError(t, err)
			// Let the client acknowledge everything first, as it will have when
			// a browser closes an idle connection: the close still carries an ACK.
			time.Sleep(100 * time.Millisecond)
			tc.close(t, tr)

			select {
			case <-server.Context().Done():
			case <-time.After(time.Second):
				t.Fatal("timeout")
			}
			var terr *quic.TransportError
			require.ErrorAs(t, context.Cause(server.Context()), &terr)
			require.True(t, terr.Remote)
			require.Equal(t, quic.NoError, terr.ErrorCode)
			require.Equal(t, "70:net error", terr.ErrorMessage)

			var closePacket []qlog.Frame
			for _, ev := range rec.Events(qlog.PacketReceived{}) {
				for _, f := range ev.(qlog.PacketReceived).Frames {
					if _, ok := f.Frame.(*qlog.ConnectionCloseFrame); ok {
						closePacket = ev.(qlog.PacketReceived).Frames
					}
				}
			}
			require.Len(t, closePacket, 2)
			require.IsType(t, &qlog.AckFrame{}, closePacket[0].Frame)
			require.Equal(t, &qlog.ConnectionCloseFrame{ReasonPhrase: "70:net error"}, closePacket[1].Frame)
		})
	}
}
