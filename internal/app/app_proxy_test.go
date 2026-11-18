package app

import (
	"io"
	"net"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/platacard/cacheprog/internal/infra/storage"
)

func TestNewProxyServer_Config(t *testing.T) {
	srv := newProxyServer("127.0.0.1:0", http.NotFoundHandler())

	assert.Equal(t, "127.0.0.1:0", srv.Addr)
	assert.Equal(t, proxyReadHeaderTimeout, srv.ReadHeaderTimeout)
	assert.Equal(t, proxyIdleTimeout, srv.IdleTimeout)
	assert.Positive(t, srv.IdleTimeout, "idle h2c connections must not stay open forever")

	require.NotNil(t, srv.Protocols)
	assert.True(t, srv.Protocols.HTTP1(), "HTTP/1.1 clients must keep working")
	assert.True(t, srv.Protocols.UnencryptedHTTP2(), "h2c clients must be accepted")

	require.NotNil(t, srv.HTTP2)
	assert.Equal(t, proxyMaxConcurrentStreams, srv.HTTP2.MaxConcurrentStreams)
	assert.Equal(t, storage.HTTP2MaxReceiveBufferPerConnection, srv.HTTP2.MaxReceiveBufferPerConnection)
	assert.Equal(t, storage.HTTP2MaxReceiveBufferPerStream, srv.HTTP2.MaxReceiveBufferPerStream)
}

func TestNewProxyServer_ServesHTTP1AndH2C(t *testing.T) {
	srv := newProxyServer("", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, r.Proto)
	}))

	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() { _ = srv.Serve(listener) }()
	t.Cleanup(func() { _ = srv.Close() })

	baseURL := "http://" + listener.Addr().String() + "/"

	h2cProtocols := new(http.Protocols)
	h2cProtocols.SetUnencryptedHTTP2(true)

	tests := []struct {
		name      string
		protocols *http.Protocols
		wantProto string
	}{
		{name: "HTTP/1.1", protocols: nil, wantProto: "HTTP/1.1"},
		{name: "h2c", protocols: h2cProtocols, wantProto: "HTTP/2.0"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := &http.Transport{Protocols: tt.protocols}
			t.Cleanup(transport.CloseIdleConnections)

			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, baseURL, http.NoBody)
			require.NoError(t, err)
			resp, err := (&http.Client{Transport: transport}).Do(req)
			require.NoError(t, err)
			defer resp.Body.Close()

			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			assert.Equal(t, http.StatusOK, resp.StatusCode)
			assert.Equal(t, tt.wantProto, string(body))
		})
	}
}
