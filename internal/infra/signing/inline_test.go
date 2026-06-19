package signing

import (
	"bytes"
	"crypto/sha256"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/platacard/cacheprog/internal/app/cacheprog"
)

func TestInlineCarrier_WrapUnwrap_RoundTrip(t *testing.T) {
	c := InlineCarrier{}
	payload := []byte("compressed-object-bytes")
	manifest := []byte("manifest-bytes")
	sig := []byte("signature")

	req := &cacheprog.PutRequest{Body: bytes.NewReader(payload)}
	require.NoError(t, c.WrapPut(req, manifest, sig))

	// the container's checksums must cover the wrapped body
	container, err := io.ReadAll(req.Body)
	require.NoError(t, err)
	assert.Equal(t, int64(len(container)), req.Size)
	wantSHA := sha256.Sum256(container)
	assert.Equal(t, wantSHA[:], req.Sha256Sum)

	resp := &cacheprog.GetResponse{Body: io.NopCloser(bytes.NewReader(container))}
	gotManifest, gotSig, gotPayload, signed, err := c.UnwrapGet(resp)
	require.NoError(t, err)
	require.True(t, signed)
	assert.Equal(t, manifest, gotManifest)
	assert.Equal(t, sig, gotSig)

	gotPayloadBytes, err := io.ReadAll(gotPayload)
	require.NoError(t, err)
	require.NoError(t, gotPayload.Close())
	assert.Equal(t, payload, gotPayloadBytes)
}

func TestInlineCarrier_UnwrapGet_Unsigned(t *testing.T) {
	c := InlineCarrier{}

	t.Run("no magic passes through", func(t *testing.T) {
		raw := []byte("just a raw object without magic")
		resp := &cacheprog.GetResponse{Body: io.NopCloser(bytes.NewReader(raw))}

		manifest, sig, payload, signed, err := c.UnwrapGet(resp)
		require.NoError(t, err)
		assert.False(t, signed)
		assert.Nil(t, manifest)
		assert.Nil(t, sig)

		got, err := io.ReadAll(payload)
		require.NoError(t, err)
		assert.Equal(t, raw, got)
	})

	t.Run("shorter than magic passes through", func(t *testing.T) {
		raw := []byte("ab")
		resp := &cacheprog.GetResponse{Body: io.NopCloser(bytes.NewReader(raw))}

		_, _, payload, signed, err := c.UnwrapGet(resp)
		require.NoError(t, err)
		assert.False(t, signed)

		got, err := io.ReadAll(payload)
		require.NoError(t, err)
		assert.Equal(t, raw, got)
	})
}

func TestInlineCarrier_UnwrapGet_Truncated(t *testing.T) {
	c := InlineCarrier{}
	// has the magic but is truncated mid-header
	truncated := append([]byte(inlineMagic), 0x00, 0x00)
	resp := &cacheprog.GetResponse{Body: io.NopCloser(bytes.NewReader(truncated))}

	_, _, _, _, err := c.UnwrapGet(resp) //nolint:dogsled // only the error matters here
	require.Error(t, err)
}
