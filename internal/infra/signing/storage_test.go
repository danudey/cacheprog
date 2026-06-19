package signing

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/platacard/cacheprog/internal/app/cacheprog"
)

// fakeStorage is an in-memory RemoteStorage that stores whatever bytes are
// uploaded, so we can exercise the decorator end to end and tamper with the
// stored object.
type fakeStorage struct {
	objects map[string][]byte
}

func newFakeStorage() *fakeStorage {
	return &fakeStorage{objects: map[string][]byte{}}
}

func (f *fakeStorage) Put(_ context.Context, req *cacheprog.PutRequest) (*cacheprog.PutResponse, error) {
	b, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	f.objects[hex.EncodeToString(req.ActionID)] = b
	return &cacheprog.PutResponse{}, nil
}

func (f *fakeStorage) Get(_ context.Context, req *cacheprog.GetRequest) (*cacheprog.GetResponse, error) {
	b, ok := f.objects[hex.EncodeToString(req.ActionID)]
	if !ok {
		return nil, cacheprog.ErrNotFound
	}
	return &cacheprog.GetResponse{
		Body: io.NopCloser(bytes.NewReader(b)),
		Size: int64(len(b)),
	}, nil
}

func newTestStore(t *testing.T, requireSig bool) (*RemoteStorage, *fakeStorage) {
	t.Helper()
	signer, err := NewHMACSigner([]byte("test-secret"), "key-1")
	require.NoError(t, err)
	fake := newFakeStorage()
	return NewRemoteStorage(fake, signer, InlineCarrier{}, requireSig), fake
}

func putObject(t *testing.T, s *RemoteStorage, actionID, payload []byte) {
	t.Helper()
	sum := sha256.Sum256(payload)
	_, err := s.Put(context.Background(), &cacheprog.PutRequest{
		ActionID:             actionID,
		OutputID:             []byte("output-id"),
		Size:                 int64(len(payload)),
		Body:                 bytes.NewReader(payload),
		Sha256Sum:            sum[:],
		CompressionAlgorithm: "zstd",
		UncompressedSize:     9999,
	})
	require.NoError(t, err)
}

func TestRemoteStorage_RoundTrip(t *testing.T) {
	s, _ := newTestStore(t, true)
	actionID := []byte("action-1")
	payload := []byte("the-compressed-payload-bytes")

	putObject(t, s, actionID, payload)

	resp, err := s.Get(context.Background(), &cacheprog.GetRequest{ActionID: actionID})
	require.NoError(t, err)

	got, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())

	assert.Equal(t, payload, got)
	// fields come from the authenticated manifest
	assert.Equal(t, []byte("output-id"), resp.OutputID)
	assert.Equal(t, "zstd", resp.CompressionAlgorithm)
	assert.Equal(t, int64(9999), resp.UncompressedSize)
	assert.Equal(t, int64(len(payload)), resp.Size)
}

func TestRemoteStorage_TamperedPayload_IsMiss(t *testing.T) {
	s, fake := newTestStore(t, true)
	actionID := []byte("action-1")
	putObject(t, s, actionID, []byte("the-compressed-payload-bytes"))

	// flip the last byte (part of the payload, after the signed header)
	stored := fake.objects[hex.EncodeToString(actionID)]
	stored[len(stored)-1] ^= 0xff

	_, err := s.Get(context.Background(), &cacheprog.GetRequest{ActionID: actionID})
	assert.ErrorIs(t, err, cacheprog.ErrNotFound)
}

func TestRemoteStorage_TamperedManifest_IsMiss(t *testing.T) {
	s, fake := newTestStore(t, true)
	actionID := []byte("action-1")
	putObject(t, s, actionID, []byte("the-compressed-payload-bytes"))

	// flip a byte inside the header region (manifest/sig), past the magic+lens
	stored := fake.objects[hex.EncodeToString(actionID)]
	stored[inlineHeaderSize+1] ^= 0xff

	_, err := s.Get(context.Background(), &cacheprog.GetRequest{ActionID: actionID})
	assert.ErrorIs(t, err, cacheprog.ErrNotFound)
}

func TestRemoteStorage_WrongKey_IsMiss(t *testing.T) {
	signerA, _ := NewHMACSigner([]byte("secret-a"), "key-1")
	signerB, _ := NewHMACSigner([]byte("secret-b"), "key-1")
	fake := newFakeStorage()

	writer := NewRemoteStorage(fake, signerA, InlineCarrier{}, true)
	reader := NewRemoteStorage(fake, signerB, InlineCarrier{}, true)

	actionID := []byte("action-1")
	putObject(t, writer, actionID, []byte("payload"))

	_, err := reader.Get(context.Background(), &cacheprog.GetRequest{ActionID: actionID})
	assert.ErrorIs(t, err, cacheprog.ErrNotFound)
}

func TestRemoteStorage_Unsigned(t *testing.T) {
	actionID := []byte("action-1")
	raw := []byte("a-pre-existing-unsigned-object")

	t.Run("required rejects", func(t *testing.T) {
		s, fake := newTestStore(t, true)
		fake.objects[hex.EncodeToString(actionID)] = raw
		_, err := s.Get(context.Background(), &cacheprog.GetRequest{ActionID: actionID})
		assert.ErrorIs(t, err, cacheprog.ErrNotFound)
	})

	t.Run("not required passes through", func(t *testing.T) {
		s, fake := newTestStore(t, false)
		fake.objects[hex.EncodeToString(actionID)] = raw
		resp, err := s.Get(context.Background(), &cacheprog.GetRequest{ActionID: actionID})
		require.NoError(t, err)
		got, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Equal(t, raw, got)
	})
}

func TestRemoteStorage_GetMissPropagates(t *testing.T) {
	s, _ := newTestStore(t, true)
	_, err := s.Get(context.Background(), &cacheprog.GetRequest{ActionID: []byte("missing")})
	assert.ErrorIs(t, err, cacheprog.ErrNotFound)
}

type verifyOnlySigner struct{ Signer }

func (verifyOnlySigner) CanSign() bool { return false }

func TestRemoteStorage_VerifyOnly_SkipsPut(t *testing.T) {
	base, _ := NewHMACSigner([]byte("secret"), "key-1")
	fake := newFakeStorage()
	s := NewRemoteStorage(fake, verifyOnlySigner{Signer: base}, InlineCarrier{}, true)

	putObject(t, s, []byte("action-1"), []byte("payload"))

	assert.Empty(t, fake.objects, "verify-only signer must not upload objects")
}

func TestRemoteStorage_PutErrorPropagates(t *testing.T) {
	signer, _ := NewHMACSigner([]byte("secret"), "key-1")
	s := NewRemoteStorage(errStorage{}, signer, InlineCarrier{}, true)
	sum := sha256.Sum256([]byte("x"))
	_, err := s.Put(context.Background(), &cacheprog.PutRequest{
		ActionID:  []byte("a"),
		Body:      bytes.NewReader([]byte("x")),
		Size:      1,
		Sha256Sum: sum[:],
	})
	require.Error(t, err)
}

type errStorage struct{}

func (errStorage) Put(context.Context, *cacheprog.PutRequest) (*cacheprog.PutResponse, error) {
	return nil, errors.New("boom")
}
func (errStorage) Get(context.Context, *cacheprog.GetRequest) (*cacheprog.GetResponse, error) {
	return nil, errors.New("boom")
}
