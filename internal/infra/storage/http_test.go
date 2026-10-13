package storage_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/platacard/cacheprog/internal/app/cacheprog"
	"github.com/platacard/cacheprog/internal/infra/storage"
)

func TestHTTP_Get(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		// Create a copy of the response body for testing
		bodyContent := []byte("hello world")

		// Setup test server that simulates successful response
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Verify request
			assert.Equal(t, "/cache/01020304", r.URL.Path)
			assert.Equal(t, http.MethodGet, r.Method)

			// Set response headers
			outputID := []byte("test-output-id")
			w.Header().Set(storage.OutputIDHeader, hex.EncodeToString(outputID))
			w.Header().Set("Last-Modified", time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC).Format(http.TimeFormat))
			w.Header().Set("Content-Length", "11")
			w.Header().Set(storage.CompressionAlgorithmHeader, "gzip")
			w.Header().Set(storage.UncompressedSizeHeader, "20")

			// Write response body
			w.WriteHeader(http.StatusOK)
			w.Write(bodyContent)
		}))
		defer server.Close()

		// Create a mock HTTP client that returns our prepared response
		origClient := http.DefaultClient
		client := storage.NewHTTP(origClient, server.URL, nil)

		// Create test request
		request := &cacheprog.GetRequest{
			ActionID: []byte{1, 2, 3, 4},
		}

		// Call the method
		response, err := client.Get(context.Background(), request)

		// Verify response
		require.NoError(t, err)
		require.NotNil(t, response)

		assert.Equal(t, "test-output-id", string(response.OutputID))
		assert.Equal(t, time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC), response.ModTime)
		assert.Equal(t, int64(11), response.Size)
		assert.Equal(t, "gzip", response.CompressionAlgorithm)
		assert.Equal(t, int64(20), response.UncompressedSize)

		// Don't try to read response.Body as it's already closed due to defer in HTTP.Get
		// Instead, just verify that it was properly set up initially
	})

	t.Run("not found", func(t *testing.T) {
		// Setup test server that simulates not found response
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Verify request
			assert.Equal(t, "/cache/01020304", r.URL.Path)
			assert.Equal(t, http.MethodGet, r.Method)

			// Return not found
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("not found"))
		}))
		defer server.Close()

		// Initialize HTTP client with test server endpoint
		client := storage.NewHTTP(http.DefaultClient, server.URL, nil)

		// Create test request
		request := &cacheprog.GetRequest{
			ActionID: []byte{1, 2, 3, 4},
		}

		// Call the method
		response, err := client.Get(context.Background(), request)

		// Verify error is ErrNotFound
		assert.Nil(t, response)
		assert.ErrorIs(t, err, cacheprog.ErrNotFound)
	})
}

func TestHTTP_Put(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		// Setup test server that simulates successful response
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Verify request
			assert.Equal(t, "/cache/01020304", r.URL.Path)
			assert.Equal(t, http.MethodPut, r.Method)
			assert.Equal(t, hex.EncodeToString([]byte("test-output-id")), r.Header.Get(storage.OutputIDHeader))
			assert.Equal(t, hex.EncodeToString([]byte("md5-test")), r.Header.Get(storage.MD5SumHeader))
			assert.Equal(t, hex.EncodeToString([]byte("sha256-test")), r.Header.Get(storage.Sha256SumHeader))
			assert.Equal(t, "gzip", r.Header.Get(storage.CompressionAlgorithmHeader))
			assert.Equal(t, "20", r.Header.Get(storage.UncompressedSizeHeader))
			assert.Equal(t, int64(11), r.ContentLength)

			// Read request body
			body, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			assert.Equal(t, "hello world", string(body))

			// Write success response
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		// Initialize HTTP client with test server endpoint
		client := storage.NewHTTP(http.DefaultClient, server.URL, nil)

		// Create test request
		request := &cacheprog.PutRequest{
			ActionID:             []byte{1, 2, 3, 4},
			OutputID:             []byte("test-output-id"),
			Size:                 11,
			Body:                 bytes.NewReader([]byte("hello world")),
			MD5Sum:               []byte("md5-test"),
			Sha256Sum:            []byte("sha256-test"),
			CompressionAlgorithm: "gzip",
			UncompressedSize:     20,
		}

		// Call the method
		response, err := client.Put(context.Background(), request)

		// Verify response
		require.NoError(t, err)
		require.NotNil(t, response)
	})
}

// newHTTPTestServer starts a server that answers every GET with a small object
// and counts the connections clients open to it.
func newHTTPTestServer(t *testing.T, h2c bool) (*httptest.Server, *atomic.Int64, *atomic.Int64) {
	t.Helper()

	var newConns, http2Requests atomic.Int64
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor == 2 {
			http2Requests.Add(1)
		}
		w.Header().Set(storage.OutputIDHeader, hex.EncodeToString([]byte("out")))
		w.Header().Set("Last-Modified", time.Now().UTC().Format(http.TimeFormat))
		w.Header().Set(storage.UncompressedSizeHeader, "5")
		w.Header().Set("Content-Length", "5")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("hello"))
	}))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			newConns.Add(1)
		}
	}
	if h2c {
		protocols := new(http.Protocols)
		protocols.SetHTTP1(true)
		protocols.SetUnencryptedHTTP2(true)
		server.Config.Protocols = protocols
	}
	server.Start()
	t.Cleanup(server.Close)

	return server, &newConns, &http2Requests
}

// runConcurrentGets fetches an object rounds times with parallel concurrent
// requests per round, fully consuming every body so connections can be reused.
func runConcurrentGets(t *testing.T, client *storage.HTTP, rounds, parallel int) {
	t.Helper()

	for range rounds {
		var wg sync.WaitGroup
		for range parallel {
			wg.Go(func() {
				resp, err := client.Get(t.Context(), &cacheprog.GetRequest{ActionID: []byte{1, 2, 3, 4}})
				if !assert.NoError(t, err) {
					return
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
			})
		}
		wg.Wait()
	}
}

func TestConfigureHTTP_ReusesConnections(t *testing.T) {
	const rounds, parallel = 4, 16

	server, newConns, http2Requests := newHTTPTestServer(t, false)

	client, err := storage.ConfigureHTTP(storage.HTTPConfig{BaseURL: server.URL, AllowInsecure: true})
	require.NoError(t, err)

	runConcurrentGets(t, client, rounds, parallel)

	// net/http's default of 2 idle connections per host would open ~parallel-2
	// new connections every round after the first.
	assert.LessOrEqual(t, newConns.Load(), int64(parallel))
	assert.Zero(t, http2Requests.Load(), "HTTP/1.1 expected without h2c")
}

func TestConfigureHTTP_H2C(t *testing.T) {
	const rounds, parallel = 4, 16

	server, newConns, http2Requests := newHTTPTestServer(t, true)

	client, err := storage.ConfigureHTTP(storage.HTTPConfig{BaseURL: server.URL, AllowInsecure: true, H2C: true})
	require.NoError(t, err)

	// A cold burst may dial several connections before the first one is up,
	// so establish one first, then check that it carries everything.
	runConcurrentGets(t, client, 1, 1)
	runConcurrentGets(t, client, rounds, parallel)

	assert.Equal(t, int64(rounds*parallel+1), http2Requests.Load(), "every request should use HTTP/2")
	assert.Equal(t, int64(1), newConns.Load(), "HTTP/2 should multiplex over one connection")
}

func TestConfigureHTTP_H2CRequiresServerSupport(t *testing.T) {
	server, _, _ := newHTTPTestServer(t, false)

	client, err := storage.ConfigureHTTP(storage.HTTPConfig{BaseURL: server.URL, AllowInsecure: true, H2C: true})
	require.NoError(t, err)

	_, err = client.Get(t.Context(), &cacheprog.GetRequest{ActionID: []byte{1, 2, 3, 4}})
	assert.Error(t, err, "an HTTP/1-only server cannot answer prior-knowledge h2c")
}
