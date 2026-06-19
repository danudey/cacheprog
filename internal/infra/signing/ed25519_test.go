package signing

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// genEd25519PEM returns a fresh keypair as PKCS#8 private PEM and PKIX public PEM.
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

func TestEd25519Signer_SignVerify(t *testing.T) {
	privPEM, _ := genEd25519PEM(t)

	signer, err := NewEd25519Signer(privPEM, nil)
	require.NoError(t, err)
	assert.Equal(t, AlgEd25519, signer.AlgID())
	assert.True(t, signer.CanSign())
	assert.Contains(t, signer.KeyID(), "ed25519-")

	msg := []byte("a manifest")
	sig, err := signer.Sign(msg)
	require.NoError(t, err)

	// a signer trusts its own public key
	require.NoError(t, signer.Verify(signer.KeyID(), msg, sig))
}

func TestEd25519Signer_VerifyOnly(t *testing.T) {
	privPEM, pubPEM := genEd25519PEM(t)

	writer, err := NewEd25519Signer(privPEM, nil)
	require.NoError(t, err)

	// a reader holding only the public key can verify but not sign
	reader, err := NewEd25519Signer(nil, pubPEM)
	require.NoError(t, err)
	assert.False(t, reader.CanSign())

	msg := []byte("a manifest")
	sig, err := writer.Sign(msg)
	require.NoError(t, err)

	require.NoError(t, reader.Verify(writer.KeyID(), msg, sig))

	_, err = reader.Sign(msg)
	require.Error(t, err)
}

func TestEd25519Signer_VerifyFailures(t *testing.T) {
	privPEM, _ := genEd25519PEM(t)
	otherPriv, _ := genEd25519PEM(t)

	signer, err := NewEd25519Signer(privPEM, nil)
	require.NoError(t, err)
	other, err := NewEd25519Signer(otherPriv, nil)
	require.NoError(t, err)

	msg := []byte("a manifest")
	sig, _ := signer.Sign(msg)

	t.Run("untrusted key id", func(t *testing.T) {
		require.ErrorContains(t, signer.Verify("ed25519-deadbeef", msg, sig), "untrusted key id")
	})

	t.Run("tampered message", func(t *testing.T) {
		require.Error(t, signer.Verify(signer.KeyID(), []byte("tampered!!"), sig))
	})

	t.Run("signature from another key", func(t *testing.T) {
		otherSig, _ := other.Sign(msg)
		// signer doesn't trust other's key id at all
		require.Error(t, signer.Verify(other.KeyID(), msg, otherSig))
	})
}

func TestNewEd25519Signer_Errors(t *testing.T) {
	t.Run("no keys at all", func(t *testing.T) {
		_, err := NewEd25519Signer(nil, nil)
		require.Error(t, err)
	})

	t.Run("garbage private key", func(t *testing.T) {
		_, err := NewEd25519Signer([]byte("not a pem"), nil)
		require.Error(t, err)
	})

	t.Run("garbage verify key", func(t *testing.T) {
		_, err := NewEd25519Signer(nil, []byte("not a pem"))
		require.Error(t, err)
	})
}

func TestEd25519Signer_MultipleTrustedKeys(t *testing.T) {
	priv1, pub1 := genEd25519PEM(t)
	_, pub2 := genEd25519PEM(t)

	// a reader that trusts two public keys (rotation)
	reader, err := NewEd25519Signer(nil, append(append([]byte{}, pub1...), pub2...))
	require.NoError(t, err)

	writer1, _ := NewEd25519Signer(priv1, nil)
	msg := []byte("manifest")
	sig, _ := writer1.Sign(msg)
	require.NoError(t, reader.Verify(writer1.KeyID(), msg, sig))
}
