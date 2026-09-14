package app

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/platacard/cacheprog/internal/app/cacheprog"
)

// stubRemoteStorage is a do-nothing RemoteStorage used to exercise the signing
// wiring without touching a real backend.
type stubRemoteStorage struct{}

func (stubRemoteStorage) Get(context.Context, *cacheprog.GetRequest) (*cacheprog.GetResponse, error) {
	return nil, cacheprog.ErrNotFound
}

func (stubRemoteStorage) Put(context.Context, *cacheprog.PutRequest) (*cacheprog.PutResponse, error) {
	return &cacheprog.PutResponse{}, nil
}

func genEd25519PEM(t *testing.T) (privPEM, pubPEM []byte) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	require.NoError(t, err)
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	require.NoError(t, err)

	privPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})
	pubPEM = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	return privPEM, pubPEM
}

func TestWrapWithSigning(t *testing.T) {
	t.Run("full signer keeps puts enabled", func(t *testing.T) {
		privPEM, pubPEM := genEd25519PEM(t)
		args := &RemoteStorageArgs{}
		args.SigningAlgorithm = "ed25519"
		args.SigningKey = string(privPEM)
		args.VerifyKeys = string(pubPEM)

		storage, readOnly, err := args.wrapWithSigning(stubRemoteStorage{})
		require.NoError(t, err)
		assert.False(t, readOnly)
		assert.NotNil(t, storage)
	})

	t.Run("verify-only without signing key switches to read-only", func(t *testing.T) {
		_, pubPEM := genEd25519PEM(t)
		args := &RemoteStorageArgs{}
		args.SigningAlgorithm = "ed25519"
		args.VerifyKeys = string(pubPEM)

		storage, readOnly, err := args.wrapWithSigning(stubRemoteStorage{})
		require.NoError(t, err)
		assert.True(t, readOnly, "a node with only verify keys must not publish unsigned objects")
		assert.NotNil(t, storage)
	})

	t.Run("blank signing key from flag degrades to verify-only", func(t *testing.T) {
		_, pubPEM := genEd25519PEM(t)
		args := &RemoteStorageArgs{}
		args.SigningAlgorithm = "ed25519"
		args.SigningKey = "   " // whitespace-only: provided but blank
		args.VerifyKeys = string(pubPEM)

		storage, readOnly, err := args.wrapWithSigning(stubRemoteStorage{})
		require.NoError(t, err)
		assert.True(t, readOnly)
		assert.NotNil(t, storage)
	})

	t.Run("blank signing key from file degrades to verify-only", func(t *testing.T) {
		_, pubPEM := genEd25519PEM(t)
		keyFile := filepath.Join(t.TempDir(), "signing.key")
		require.NoError(t, os.WriteFile(keyFile, []byte("\n\n"), 0o600))

		args := &RemoteStorageArgs{}
		args.SigningAlgorithm = "ed25519"
		args.SigningKeyFile = keyFile
		args.VerifyKeys = string(pubPEM)

		storage, readOnly, err := args.wrapWithSigning(stubRemoteStorage{})
		require.NoError(t, err)
		assert.True(t, readOnly)
		assert.NotNil(t, storage)
	})

	t.Run("disabled signing leaves base untouched", func(t *testing.T) {
		args := &RemoteStorageArgs{}
		base := stubRemoteStorage{}

		storage, readOnly, err := args.wrapWithSigning(base)
		require.NoError(t, err)
		assert.False(t, readOnly)
		assert.Equal(t, base, storage)
	})
}

func TestSigningKeyProvided(t *testing.T) {
	t.Run("inline key", func(t *testing.T) {
		args := &RemoteStorageArgs{}
		args.SigningKey = "secret"
		assert.True(t, args.signingKeyProvided())
	})

	t.Run("blank inline key is still provided", func(t *testing.T) {
		args := &RemoteStorageArgs{}
		args.SigningKey = "  "
		assert.True(t, args.signingKeyProvided())
	})

	t.Run("key file path", func(t *testing.T) {
		args := &RemoteStorageArgs{}
		args.SigningKeyFile = "/some/path"
		assert.True(t, args.signingKeyProvided())
	})

	t.Run("empty env var counts as provided", func(t *testing.T) {
		t.Setenv("CACHEPROG_SIGNING_KEY", "")
		args := &RemoteStorageArgs{}
		assert.True(t, args.signingKeyProvided())
	})

	t.Run("nothing provided", func(t *testing.T) {
		args := &RemoteStorageArgs{}
		assert.False(t, args.signingKeyProvided())
	})
}
