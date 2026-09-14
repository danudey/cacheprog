package signing

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/platacard/cacheprog/internal/app/cacheprog"
)

func TestMetadataCarrier_WrapUnwrap(t *testing.T) {
	c := MetadataCarrier{}
	payload := []byte("compressed-object-bytes")
	manifest := []byte("manifest-bytes")
	sig := []byte("signature")

	req := &cacheprog.PutRequest{Body: bytes.NewReader(payload)}
	require.NoError(t, c.WrapPut(req, manifest, sig))

	// the body and checksums are left untouched; manifest/sig go out-of-band
	assert.Equal(t, manifest, req.Manifest)
	assert.Equal(t, sig, req.Signature)
	body, err := io.ReadAll(req.Body)
	require.NoError(t, err)
	assert.Equal(t, payload, body)

	resp := &cacheprog.GetResponse{
		Body:      io.NopCloser(bytes.NewReader(payload)),
		Manifest:  manifest,
		Signature: sig,
	}
	gotManifest, gotSig, gotPayload, signed, err := c.UnwrapGet(resp)
	require.NoError(t, err)
	require.True(t, signed)
	assert.Equal(t, manifest, gotManifest)
	assert.Equal(t, sig, gotSig)
	got, err := io.ReadAll(gotPayload)
	require.NoError(t, err)
	assert.Equal(t, payload, got)
}

func TestMetadataCarrier_UnwrapGet_Unsigned(t *testing.T) {
	c := MetadataCarrier{}
	payload := []byte("raw-object")
	resp := &cacheprog.GetResponse{Body: io.NopCloser(bytes.NewReader(payload))}

	manifest, sig, gotPayload, signed, err := c.UnwrapGet(resp)
	require.NoError(t, err)
	assert.False(t, signed)
	assert.Nil(t, manifest)
	assert.Nil(t, sig)
	got, err := io.ReadAll(gotPayload)
	require.NoError(t, err)
	assert.Equal(t, payload, got)
}

func newMetadataStore(t *testing.T, requireSig bool) (*RemoteStorage, *fakeStorage) {
	t.Helper()
	signer, err := NewHMACSigner([]byte("test-secret"), "key-1")
	require.NoError(t, err)
	fake := newFakeStorage()
	return NewRemoteStorage(fake, signer, MetadataCarrier{}, requireSig), fake
}

func TestRemoteStorage_MetadataCarrier_RoundTrip(t *testing.T) {
	s, fake := newMetadataStore(t, true)
	actionID := []byte("action-1")
	payload := []byte("the-compressed-payload-bytes")

	putObject(t, s, actionID, payload)

	// the stored body must be the raw payload (signature lives out-of-band)
	assert.Equal(t, payload, fake.objects[hex.EncodeToString(actionID)].body)
	assert.NotEmpty(t, fake.objects[hex.EncodeToString(actionID)].manifest)

	resp, err := s.Get(context.Background(), &cacheprog.GetRequest{ActionID: actionID})
	require.NoError(t, err)
	got, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, payload, got)
	assert.Equal(t, []byte("output-id"), resp.OutputID)
}

func TestRemoteStorage_MetadataCarrier_Tampering_IsMiss(t *testing.T) {
	actionID := []byte("action-1")

	t.Run("tampered payload", func(t *testing.T) {
		s, fake := newMetadataStore(t, true)
		putObject(t, s, actionID, []byte("the-compressed-payload-bytes"))
		fake.objects[hex.EncodeToString(actionID)].body[0] ^= 0xff
		_, err := s.Get(context.Background(), &cacheprog.GetRequest{ActionID: actionID})
		assert.ErrorIs(t, err, cacheprog.ErrNotFound)
	})

	t.Run("tampered manifest", func(t *testing.T) {
		s, fake := newMetadataStore(t, true)
		putObject(t, s, actionID, []byte("the-compressed-payload-bytes"))
		fake.objects[hex.EncodeToString(actionID)].manifest[3] ^= 0xff
		_, err := s.Get(context.Background(), &cacheprog.GetRequest{ActionID: actionID})
		assert.ErrorIs(t, err, cacheprog.ErrNotFound)
	})
}

func TestRemoteStorage_Ed25519_Inline_RoundTrip(t *testing.T) {
	privPEM, _ := genEd25519PEM(t)
	signer, err := NewEd25519Signer(privPEM, nil)
	require.NoError(t, err)
	fake := newFakeStorage()
	s := NewRemoteStorage(fake, signer, InlineCarrier{}, true)

	actionID := []byte("action-1")
	payload := []byte("payload-bytes-for-ed25519")
	sum := sha256.Sum256(payload)
	_, err = s.Put(context.Background(), &cacheprog.PutRequest{
		ActionID:  actionID,
		OutputID:  []byte("output-id"),
		Size:      int64(len(payload)),
		Body:      bytes.NewReader(payload),
		Sha256Sum: sum[:],
	})
	require.NoError(t, err)

	resp, err := s.Get(context.Background(), &cacheprog.GetRequest{ActionID: actionID})
	require.NoError(t, err)
	got, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, payload, got)
}
