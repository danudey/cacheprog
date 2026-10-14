package storage

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
