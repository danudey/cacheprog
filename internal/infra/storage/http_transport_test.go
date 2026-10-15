package storage

import (
	"bytes"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/platacard/cacheprog/internal/app/cacheprog"
)

// An h2c transport must still reach https:// URLs, e.g. when an h2c server
// redirects to a presigned URL.
func TestNewHTTPTransport_H2CFollowsHTTPSRedirect(t *testing.T) {
	target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(r.Proto))
	}))
	target.EnableHTTP2 = true
	target.StartTLS()
	t.Cleanup(target.Close)

	redirector := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	protocols := new(http.Protocols)
	protocols.SetUnencryptedHTTP2(true)
	redirector.Config.Protocols = protocols
	redirector.Start()
	t.Cleanup(redirector.Close)

	transport := newHTTPTransport(0, true)
	transport.TLSClientConfig = target.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	client := &http.Client{Transport: transport}

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, redirector.URL, http.NoBody)
	require.NoError(t, err)
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, 2, resp.ProtoMajor, "the https:// target should be reached over HTTP/2")
}

// transportOf returns the transport ConfigureHTTP built for h.
func transportOf(t *testing.T, h *HTTP) *http.Transport {
	t.Helper()
	transport, ok := h.client.Transport.(*http.Transport)
	require.True(t, ok, "expected *http.Transport, got %T", h.client.Transport)
	return transport
}

func TestConfigureHTTP_Transport(t *testing.T) {
	tests := []struct {
		name            string
		cfg             HTTPConfig
		wantIdlePerHost int
		wantH2C         bool
	}{
		{
			name:            "default idle connections",
			cfg:             HTTPConfig{BaseURL: "https://example.com"},
			wantIdlePerHost: DefaultHTTPMaxIdleConnsPerHost,
		},
		{
			name:            "negative idle connections fall back to default",
			cfg:             HTTPConfig{BaseURL: "https://example.com", MaxIdleConnsPerHost: -1},
			wantIdlePerHost: DefaultHTTPMaxIdleConnsPerHost,
		},
		{
			name:            "custom idle connections",
			cfg:             HTTPConfig{BaseURL: "https://example.com", MaxIdleConnsPerHost: 7},
			wantIdlePerHost: 7,
		},
		{
			name:            "idle connections above the global limit raise it",
			cfg:             HTTPConfig{BaseURL: "https://example.com", MaxIdleConnsPerHost: 500},
			wantIdlePerHost: 500,
		},
		{
			name:            "h2c on http",
			cfg:             HTTPConfig{BaseURL: "http://example.com", AllowInsecure: true, H2C: true},
			wantIdlePerHost: DefaultHTTPMaxIdleConnsPerHost,
			wantH2C:         true,
		},
		{
			name:            "h2c scheme check ignores case",
			cfg:             HTTPConfig{BaseURL: "HTTP://example.com", AllowInsecure: true, H2C: true},
			wantIdlePerHost: DefaultHTTPMaxIdleConnsPerHost,
			wantH2C:         true,
		},
		{
			name:            "h2c ignored on https",
			cfg:             HTTPConfig{BaseURL: "https://example.com", H2C: true},
			wantIdlePerHost: DefaultHTTPMaxIdleConnsPerHost,
		},
		{
			name:            "h2c off on http",
			cfg:             HTTPConfig{BaseURL: "http://example.com", AllowInsecure: true},
			wantIdlePerHost: DefaultHTTPMaxIdleConnsPerHost,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, err := ConfigureHTTP(tt.cfg)
			require.NoError(t, err)
			transport := transportOf(t, h)

			assert.Equal(t, tt.wantIdlePerHost, transport.MaxIdleConnsPerHost)
			assert.GreaterOrEqual(t, transport.MaxIdleConns, tt.wantIdlePerHost)

			if !tt.wantH2C {
				assert.Nil(t, transport.Protocols, "default protocols expected without h2c")
				assert.Nil(t, transport.HTTP2, "default HTTP/2 settings expected without h2c")
				return
			}

			require.NotNil(t, transport.Protocols)
			assert.True(t, transport.Protocols.UnencryptedHTTP2(), "h2c must be enabled")
			assert.True(t, transport.Protocols.HTTP2(), "HTTP/2 over TLS must stay enabled")
			assert.False(t, transport.Protocols.HTTP1(), "HTTP1 must be off so http:// uses prior-knowledge h2c")

			require.NotNil(t, transport.HTTP2)
			assert.Equal(t, HTTP2MaxReceiveBufferPerConnection, transport.HTTP2.MaxReceiveBufferPerConnection)
			assert.Equal(t, HTTP2MaxReceiveBufferPerStream, transport.HTTP2.MaxReceiveBufferPerStream)
		})
	}
}

// Failed Gets (cache misses, server errors, malformed responses) must release
// their connection, so the next request reuses it instead of dialing again.
func TestHTTP_GetErrorsReuseConnection(t *testing.T) {
	tests := []struct {
		name    string
		handler http.HandlerFunc
		wantErr error
	}{
		{
			name:    "not found",
			handler: func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) },
			wantErr: cacheprog.ErrNotFound,
		},
		{
			name: "server error",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, "boom", http.StatusInternalServerError)
			},
		},
		{
			name: "malformed headers",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set(OutputIDHeader, "not hex")
				_, _ = w.Write([]byte("payload"))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var opened atomic.Int64
			server := httptest.NewUnstartedServer(tt.handler)
			server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
				if state == http.StateNew {
					opened.Add(1)
				}
			}
			server.Start()
			t.Cleanup(server.Close)

			h, err := ConfigureHTTP(HTTPConfig{BaseURL: server.URL, AllowInsecure: true})
			require.NoError(t, err)

			for range 5 {
				_, err := h.Get(t.Context(), &cacheprog.GetRequest{ActionID: []byte{1, 2, 3, 4}})
				require.Error(t, err)
				if tt.wantErr != nil {
					require.ErrorIs(t, err, tt.wantErr)
				}
			}

			// The transport returns a drained connection to the pool
			// asynchronously, so a later request may rarely dial again; a leak
			// dials on every request.
			assert.LessOrEqual(t, opened.Load(), int64(2), "failed Gets should reuse the connection")
		})
	}
}

func TestConfigureHTTP_H2COnHTTPSWarns(t *testing.T) {
	var logs bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	_, err := ConfigureHTTP(HTTPConfig{BaseURL: "https://example.com", H2C: true})
	require.NoError(t, err)

	assert.Contains(t, logs.String(), "level=WARN")
	assert.Contains(t, logs.String(), "h2c")
	assert.Contains(t, logs.String(), "scheme=https")
}

func TestConfigureHTTP_Errors(t *testing.T) {
	_, err := ConfigureHTTP(HTTPConfig{})
	require.ErrorContains(t, err, "base URL is required")

	_, err = ConfigureHTTP(HTTPConfig{BaseURL: "http://example.com", H2C: true})
	require.ErrorContains(t, err, "insecure scheme", "h2c must not bypass the insecure-scheme check")
}
