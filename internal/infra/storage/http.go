package storage

import (
	"cmp"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/platacard/cacheprog/internal/app/cacheprog"
)

type HTTP struct {
	client       *http.Client
	endpoint     string
	extraHeaders http.Header
}

func NewHTTP(client *http.Client, endpoint string, extraHeaders http.Header) *HTTP {
	return &HTTP{
		client:       cmp.Or(client, http.DefaultClient),
		endpoint:     endpoint,
		extraHeaders: extraHeaders,
	}
}

// DefaultHTTPMaxIdleConnsPerHost is the default number of idle keep-alive
// connections kept per host. The Go compiler issues many cache requests in
// parallel; net/http's default of 2 makes most of them open a fresh connection.
const DefaultHTTPMaxIdleConnsPerHost = 64

type HTTPConfig struct {
	BaseURL      string
	ExtraHeaders http.Header

	// AllowInsecure permits plaintext http:// base URLs.
	AllowInsecure bool

	// MaxIdleConnsPerHost is the number of idle keep-alive connections kept
	// per host, DefaultHTTPMaxIdleConnsPerHost if zero or negative.
	MaxIdleConnsPerHost int

	// H2C makes requests to http:// base URLs use HTTP/2 without TLS (prior
	// knowledge), multiplexing all requests over one connection. The server
	// must support it. Ignored for https:// base URLs, which negotiate HTTP/2
	// via TLS anyway.
	H2C bool
}

func ConfigureHTTP(cfg HTTPConfig) (*HTTP, error) {
	if cfg.BaseURL == "" {
		return nil, fmt.Errorf("base URL is required")
	}

	if err := checkRemoteURLScheme("HTTP storage base URL", cfg.BaseURL, cfg.AllowInsecure); err != nil {
		return nil, err
	}

	u, err := url.Parse(cfg.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse HTTP storage base URL: %w", err)
	}
	h2c := cfg.H2C && strings.EqualFold(u.Scheme, "http")
	if cfg.H2C && !h2c {
		slog.Warn("HTTP/2 without TLS (h2c) applies only to http:// base URLs, ignoring", slog.String("scheme", u.Scheme))
	}

	slog.Info("Configuring HTTP storage with base URL", slog.String("baseURL", cfg.BaseURL), slog.Bool("h2c", h2c))

	return NewHTTP(&http.Client{Transport: newHTTPTransport(cfg.MaxIdleConnsPerHost, h2c)}, cfg.BaseURL, cfg.ExtraHeaders), nil
}

func newHTTPTransport(maxIdleConnsPerHost int, h2c bool) *http.Transport {
	if maxIdleConnsPerHost <= 0 {
		maxIdleConnsPerHost = DefaultHTTPMaxIdleConnsPerHost
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxIdleConnsPerHost = maxIdleConnsPerHost
	transport.MaxIdleConns = max(transport.MaxIdleConns, maxIdleConnsPerHost)

	if h2c {
		// Without HTTP1 in the set, http:// requests use HTTP/2 with prior knowledge.
		protocols := new(http.Protocols)
		protocols.SetUnencryptedHTTP2(true)
		transport.Protocols = protocols
	}

	return transport
}

func (h *HTTP) Get(ctx context.Context, request *cacheprog.GetRequest) (*cacheprog.GetResponse, error) {
	req, err := NewGetRequest(ctx, h.endpoint, request)
	if err != nil {
		return nil, err
	}

	for k, vs := range h.extraHeaders {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}

	resp, err := h.client.Do(req) //nolint:bodyclose // closed in upper layer
	if err != nil {
		return nil, err
	}

	return ParseGetResponse(resp)
}

func (h *HTTP) Put(ctx context.Context, request *cacheprog.PutRequest) (*cacheprog.PutResponse, error) {
	req, err := NewPutRequest(ctx, h.endpoint, request)
	if err != nil {
		return nil, err
	}

	for k, vs := range h.extraHeaders {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}

	resp, err := h.client.Do(req)
	if resp != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(body))
	}

	return &cacheprog.PutResponse{}, nil
}
