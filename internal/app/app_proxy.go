package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/platacard/cacheprog/internal/app/proxy"
)

type ProxyAppArgs struct {
	MetricsProxyArgs
	RemoteStorageArgs

	ListenAddress string `arg:"--listen-address,env:PROXY_LISTEN_ADDRESS" placeholder:"ADDR" default:"127.0.0.1:8080" help:"Listen address. Defaults to loopback because the proxy has no authentication; bind to a routable address only on a trusted, isolated network."`
}

type MetricsProxyArgs struct {
	Endpoint     *url.URL          `arg:"--metrics-proxy-endpoint,env:METRICS_PROXY_ENDPOINT" placeholder:"URL" help:"Metrics endpoint, metrics push proxy endpoint will be enabled if provided"`
	ExtraLabels  map[string]string `arg:"--metrics-proxy-extra-labels,env:METRICS_PROXY_EXTRA_LABELS" placeholder:"[key=value]" help:"Extra labels to be added to each metric, format: key=value"`
	ExtraHeaders []httpHeader      `arg:"--metrics-proxy-extra-headers,env:METRICS_PROXY_EXTRA_HEADERS" placeholder:"[key:value]" help:"Extra headers to be added to each request."`
}

// isNonLoopbackListenAddress reports whether addr would expose the listener
// beyond the local host. An empty host (e.g. ":8080") or the wildcard
// addresses bind on all interfaces and are therefore considered non-loopback.
func isNonLoopbackListenAddress(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		// can't parse, assume the worst so the operator is warned
		return true
	}
	if host == "" {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		// a hostname (not an IP literal) may resolve to a routable address
		return !strings.EqualFold(host, "localhost")
	}
	return !ip.IsLoopback()
}

func (a *ProxyAppArgs) Run(ctx context.Context) error {
	remoteStorage, err := a.configureRemoteStorage()
	if err != nil {
		return fmt.Errorf("failed to configure remote storage: %w", err)
	}

	handler, err := proxy.NewHandler(remoteStorage, proxy.MetricsConfig{
		Endpoint:     urlOrEmpty(a.Endpoint),
		ExtraLabels:  a.ExtraLabels,
		ExtraHeaders: headerValuesToHTTP(a.ExtraHeaders),
	})
	if err != nil {
		return fmt.Errorf("failed to configure proxy handler: %w", err)
	}

	if isNonLoopbackListenAddress(a.ListenAddress) {
		slog.Warn("Proxy is listening on a non-loopback address and has NO authentication. "+
			"Anyone able to reach this address can read and poison the build cache using the proxy's credentials. "+
			"Only do this on a trusted, isolated network.",
			"address", a.ListenAddress)
	}

	srv := &http.Server{
		Addr:              a.ListenAddress,
		Handler:           handler,
		ReadHeaderTimeout: time.Minute,
	}
	defer context.AfterFunc(ctx, func() {
		_ = srv.Close()
	})()

	slog.Info("Listening", "address", a.ListenAddress)

	if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("failed to serve: %w", err)
	}

	return nil
}
