package signing

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
)

// AlgHMACName is the configuration value selecting the HMAC-SHA256 signer.
const AlgHMACName = "hmac-sha256"

// hmacSigner implements Signer using HMAC-SHA256. It is symmetric: the same
// secret signs and verifies, so every party that can verify can also forge.
// This still defends against in-transit tampering and anyone who lacks the
// secret; use the asymmetric signer when readers must not be able to forge.
type hmacSigner struct {
	key   []byte
	keyID string
}

// NewHMACSigner returns an HMAC-SHA256 signer. If keyID is empty a stable,
// non-secret identifier is derived from the key so rotation still works.
func NewHMACSigner(key []byte, keyID string) (Signer, error) {
	if len(key) == 0 {
		return nil, errors.New("hmac signer: empty key")
	}
	if keyID == "" {
		keyID = deriveKeyID(key)
	}
	// copy so later mutation of the caller's slice can't change the key
	k := make([]byte, len(key))
	copy(k, key)
	return &hmacSigner{key: k, keyID: keyID}, nil
}

// deriveKeyID returns a short, non-secret identifier for a symmetric key. It is
// a truncated SHA-256 of the key, so it leaks nothing about the secret.
func deriveKeyID(key []byte) string {
	sum := sha256.Sum256(key)
	return "hmac-" + hex.EncodeToString(sum[:4])
}

func (s *hmacSigner) AlgID() uint8  { return AlgHMACSHA256 }
func (s *hmacSigner) KeyID() string { return s.keyID }
func (s *hmacSigner) CanSign() bool { return true }

func (s *hmacSigner) Sign(msg []byte) ([]byte, error) {
	mac := hmac.New(sha256.New, s.key)
	mac.Write(msg)
	return mac.Sum(nil), nil
}

func (s *hmacSigner) Verify(keyID string, msg, sig []byte) error {
	if keyID != s.keyID {
		return fmt.Errorf("unknown key id %q", keyID)
	}
	mac := hmac.New(sha256.New, s.key)
	mac.Write(msg)
	if !hmac.Equal(mac.Sum(nil), sig) {
		return errors.New("signature mismatch")
	}
	return nil
}
