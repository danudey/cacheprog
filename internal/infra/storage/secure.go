package storage

import (
	"fmt"
	"log/slog"
	"net/url"
	"strings"
)

// insecureSchemes are URL schemes whose transport is plaintext and therefore
// vulnerable to in-transit tampering (which can poison builds) and credential
// disclosure.
const schemeHTTP = "http"

var insecureSchemes = map[string]struct{}{
	schemeHTTP:   {},
	"minio+http": {},
}

// checkRemoteURLScheme rejects plaintext endpoints unless the operator has
// explicitly opted in via allowInsecure. The name is included in error and
// warning messages so it's clear which endpoint is at fault.
//
// An empty rawURL is treated as "not configured" and accepted (e.g. AWS S3
// needs no endpoint and defaults to HTTPS); the returned URL is then nil.
// Otherwise it returns the parsed URL so callers need not parse it again.
func checkRemoteURLScheme(name, rawURL string, allowInsecure bool) (*url.URL, error) {
	if rawURL == "" {
		return nil, nil
	}

	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("parse %s URL: %w", name, err)
	}

	scheme := strings.ToLower(u.Scheme)
	if _, insecure := insecureSchemes[scheme]; !insecure {
		return u, nil
	}

	if !allowInsecure {
		return nil, fmt.Errorf("%s uses insecure scheme %q: plaintext traffic can be read or tampered with in transit; "+
			"use https (or minio+https) or pass --allow-insecure-http-remotes / CACHEPROG_ALLOW_INSECURE_HTTP_REMOTES=true to override for testing",
			name, u.Scheme)
	}

	slog.Warn("Using an insecure plaintext remote endpoint; traffic can be read or tampered with in transit, which can poison builds",
		"endpoint", name, "scheme", u.Scheme)

	return u, nil
}
