package app

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alexflint/go-arg"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/platacard/cacheprog/internal/app/cacheprog"
	"github.com/platacard/cacheprog/internal/infra/storage"
)

// parseArgs parses args the way RunApp does, including CACHEPROG_ env vars.
func parseArgs(t *testing.T, args ...string) *Args {
	t.Helper()
	var parsed Args
	parser, err := arg.NewParser(arg.Config{EnvPrefix: "CACHEPROG_"}, &parsed)
	require.NoError(t, err)
	require.NoError(t, parser.Parse(args))
	return &parsed
}

func TestHTTPStorageArgs_Parse(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		parsed := parseArgs(t, "direct")
		require.NotNil(t, parsed.CacheprogApp)
		assert.Equal(t, storage.DefaultHTTPMaxIdleConnsPerHost, parsed.CacheprogApp.MaxIdleConns)
		assert.False(t, parsed.CacheprogApp.H2C)
	})

	t.Run("env vars", func(t *testing.T) {
		t.Setenv("CACHEPROG_HTTP_STORAGE_MAX_IDLE_CONNS", "7")
		t.Setenv("CACHEPROG_HTTP_STORAGE_H2C", "true")

		parsed := parseArgs(t, "direct")
		require.NotNil(t, parsed.CacheprogApp)
		assert.Equal(t, 7, parsed.CacheprogApp.MaxIdleConns)
		assert.True(t, parsed.CacheprogApp.H2C)
	})

	t.Run("flags", func(t *testing.T) {
		parsed := parseArgs(t, "direct", "--http-storage-max-idle-conns", "9", "--http-storage-h2c")
		require.NotNil(t, parsed.CacheprogApp)
		assert.Equal(t, 9, parsed.CacheprogApp.MaxIdleConns)
		assert.True(t, parsed.CacheprogApp.H2C)
	})

	t.Run("proxy subcommand", func(t *testing.T) {
		t.Setenv("CACHEPROG_HTTP_STORAGE_MAX_IDLE_CONNS", "11")
		t.Setenv("CACHEPROG_HTTP_STORAGE_H2C", "true")

		parsed := parseArgs(t, "proxy")
		require.NotNil(t, parsed.ProxyApp)
		assert.Equal(t, 11, parsed.ProxyApp.MaxIdleConns)
		assert.True(t, parsed.ProxyApp.H2C)
	})
}

// TestConfigureBaseStorage_HTTPMaxIdleConns checks that the parsed max idle
// connections setting reaches the HTTP storage client: after a burst of
// parallel requests, the client must keep exactly that many connections idle
// and close the rest.
func TestConfigureBaseStorage_HTTPMaxIdleConns(t *testing.T) {
	const (
		maxIdleConns = 3
		burst        = maxIdleConns + 4
	)

	var arrived atomic.Int64
	allArrived := make(chan struct{})
	var opened, closed atomic.Int64
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Hold every request until the whole burst is in flight, so the
		// client must open one connection per request.
		if arrived.Add(1) == burst {
			close(allArrived)
		}
		select {
		case <-allArrived:
		case <-r.Context().Done():
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		switch state {
		case http.StateNew:
			opened.Add(1)
		case http.StateClosed:
			closed.Add(1)
		}
	}
	server.Start()
	t.Cleanup(server.Close)

	t.Setenv("CACHEPROG_REMOTE_STORAGE_TYPE", "http")
	t.Setenv("CACHEPROG_HTTP_STORAGE_BASE_URL", server.URL+"/")
	t.Setenv("CACHEPROG_ALLOW_INSECURE_HTTP_REMOTES", "true")
	t.Setenv("CACHEPROG_HTTP_STORAGE_MAX_IDLE_CONNS", strconv.Itoa(maxIdleConns))

	parsed := parseArgs(t, "direct")
	require.NotNil(t, parsed.CacheprogApp)

	remote, err := parsed.CacheprogApp.configureBaseStorage()
	require.NoError(t, err)
	require.IsType(t, &storage.HTTP{}, remote)

	var wg sync.WaitGroup
	for i := range burst {
		wg.Go(func() {
			_, err := remote.Put(t.Context(), &cacheprog.PutRequest{ActionID: []byte{byte(i)}})
			assert.NoError(t, err)
		})
	}
	wg.Wait()

	assert.Equal(t, int64(burst), opened.Load())
	// The transport returns connections to the pool asynchronously, so wait
	// for it to close the ones over the limit.
	assert.Eventually(t, func() bool {
		return closed.Load() == burst-maxIdleConns
	}, 5*time.Second, 10*time.Millisecond,
		"want %d of %d connections closed", burst-maxIdleConns, burst)
}

// TestConfigureBaseStorage_HTTPH2C checks that the H2C setting reaches the
// HTTP storage client: requests must use HTTP/2 only when it is on.
func TestConfigureBaseStorage_HTTPH2C(t *testing.T) {
	var lastProtoMajor atomic.Int64
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lastProtoMajor.Store(int64(r.ProtoMajor))
		http.NotFound(w, r)
	}))
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetUnencryptedHTTP2(true)
	server.Config.Protocols = protocols
	server.Start()
	t.Cleanup(server.Close)

	for _, h2c := range []bool{false, true} {
		t.Run("h2c="+strconv.FormatBool(h2c), func(t *testing.T) {
			t.Setenv("CACHEPROG_REMOTE_STORAGE_TYPE", "http")
			t.Setenv("CACHEPROG_HTTP_STORAGE_BASE_URL", server.URL+"/")
			t.Setenv("CACHEPROG_ALLOW_INSECURE_HTTP_REMOTES", "true")
			t.Setenv("CACHEPROG_HTTP_STORAGE_H2C", strconv.FormatBool(h2c))

			parsed := parseArgs(t, "direct")
			require.NotNil(t, parsed.CacheprogApp)

			remote, err := parsed.CacheprogApp.configureBaseStorage()
			require.NoError(t, err)
			require.IsType(t, &storage.HTTP{}, remote)

			_, err = remote.Get(t.Context(), &cacheprog.GetRequest{ActionID: []byte{1, 2, 3, 4}})
			require.ErrorIs(t, err, cacheprog.ErrNotFound)

			wantProtoMajor := int64(1)
			if h2c {
				wantProtoMajor = 2
			}
			assert.Equal(t, wantProtoMajor, lastProtoMajor.Load())
		})
	}
}
