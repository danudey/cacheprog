package signing

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHMACSigner_SignVerify(t *testing.T) {
	s, err := NewHMACSigner([]byte("secret-key"), "key-1")
	require.NoError(t, err)

	assert.Equal(t, AlgHMACSHA256, s.AlgID())
	assert.Equal(t, "key-1", s.KeyID())
	assert.True(t, s.CanSign())

	msg := []byte("a manifest")
	sig, err := s.Sign(msg)
	require.NoError(t, err)

	require.NoError(t, s.Verify("key-1", msg, sig))
}

func TestHMACSigner_VerifyFailures(t *testing.T) {
	s, err := NewHMACSigner([]byte("secret-key"), "key-1")
	require.NoError(t, err)
	msg := []byte("a manifest")
	sig, err := s.Sign(msg)
	require.NoError(t, err)

	t.Run("tampered message", func(t *testing.T) {
		require.Error(t, s.Verify("key-1", []byte("a manifesX"), sig))
	})

	t.Run("tampered signature", func(t *testing.T) {
		bad := append([]byte(nil), sig...)
		bad[0] ^= 0xff
		require.Error(t, s.Verify("key-1", msg, bad))
	})

	t.Run("wrong key id", func(t *testing.T) {
		require.ErrorContains(t, s.Verify("key-2", msg, sig), "unknown key id")
	})

	t.Run("different key cannot verify", func(t *testing.T) {
		other, err := NewHMACSigner([]byte("other-key"), "key-1")
		require.NoError(t, err)
		require.Error(t, other.Verify("key-1", msg, sig))
	})
}

func TestNewHMACSigner(t *testing.T) {
	t.Run("empty key rejected", func(t *testing.T) {
		_, err := NewHMACSigner(nil, "")
		require.Error(t, err)
	})

	t.Run("derives key id when empty", func(t *testing.T) {
		s, err := NewHMACSigner([]byte("secret-key"), "")
		require.NoError(t, err)
		assert.Contains(t, s.KeyID(), "hmac-")
	})

	t.Run("derived key id is stable and key-dependent", func(t *testing.T) {
		a, _ := NewHMACSigner([]byte("secret-key"), "")
		b, _ := NewHMACSigner([]byte("secret-key"), "")
		c, _ := NewHMACSigner([]byte("other-key"), "")
		assert.Equal(t, a.KeyID(), b.KeyID())
		assert.NotEqual(t, a.KeyID(), c.KeyID())
	})
}
