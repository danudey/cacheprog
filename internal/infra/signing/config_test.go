package signing

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfigure(t *testing.T) {
	t.Run("disabled when no algorithm", func(t *testing.T) {
		signer, carrier, enabled, err := Configure(Config{})
		require.NoError(t, err)
		assert.False(t, enabled)
		assert.Nil(t, signer)
		assert.Nil(t, carrier)
	})

	t.Run("hmac inline", func(t *testing.T) {
		signer, carrier, enabled, err := Configure(Config{
			Algorithm: AlgHMACName,
			Key:       []byte("secret"),
		})
		require.NoError(t, err)
		assert.True(t, enabled)
		require.NotNil(t, signer)
		require.NotNil(t, carrier)
		assert.Equal(t, LocationInline, carrier.Name())
	})

	t.Run("hmac requires a key", func(t *testing.T) {
		_, _, _, err := Configure(Config{Algorithm: AlgHMACName})
		require.Error(t, err)
	})

	t.Run("ed25519 with verify keys", func(t *testing.T) {
		_, pubPEM := genEd25519PEM(t)
		signer, carrier, enabled, err := Configure(Config{Algorithm: AlgEd25519Name, VerifyKeys: pubPEM})
		require.NoError(t, err)
		assert.True(t, enabled)
		assert.Equal(t, AlgEd25519, signer.AlgID())
		assert.False(t, signer.CanSign())
		assert.Equal(t, LocationInline, carrier.Name())
	})

	t.Run("ed25519 needs some key", func(t *testing.T) {
		_, _, _, err := Configure(Config{Algorithm: AlgEd25519Name})
		require.Error(t, err)
	})

	t.Run("metadata location", func(t *testing.T) {
		_, carrier, enabled, err := Configure(Config{Algorithm: AlgHMACName, Key: []byte("k"), Location: LocationMetadata})
		require.NoError(t, err)
		assert.True(t, enabled)
		assert.Equal(t, LocationMetadata, carrier.Name())
	})

	t.Run("unknown algorithm", func(t *testing.T) {
		_, _, _, err := Configure(Config{Algorithm: "rot13", Key: []byte("k")})
		require.ErrorContains(t, err, "unknown signing algorithm")
	})

	t.Run("unknown location", func(t *testing.T) {
		_, _, _, err := Configure(Config{Algorithm: AlgHMACName, Key: []byte("k"), Location: "carrier-pigeon"})
		require.ErrorContains(t, err, "unknown signature location")
	})
}
