package signing

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
)

// AlgEd25519Name is the configuration value selecting the Ed25519 signer.
const AlgEd25519Name = "ed25519"

// ed25519Signer implements Signer using Ed25519. It is asymmetric: the private
// key signs and public keys verify, so readers that hold only public keys can
// verify objects but cannot forge them. This is the right choice when untrusted
// consumers (e.g. fork/PR jobs) must verify the cache but must not be able to
// poison it.
//
// Key material is PEM-encoded: the private key as PKCS#8
// (-----BEGIN PRIVATE KEY-----) and public keys as PKIX/SubjectPublicKeyInfo
// (-----BEGIN PUBLIC KEY-----), as produced by e.g. `openssl genpkey
// -algorithm ed25519`. Key IDs are derived deterministically from the public
// key, so verifiers don't need to be told which id pairs with which key and
// rotation is just "trust both public keys for a while".
type ed25519Signer struct {
	priv   ed25519.PrivateKey           // nil for verify-only deployments
	keyID  string                       // id of our own signing key (when priv != nil)
	verify map[string]ed25519.PublicKey // trusted public keys, by derived id
}

// NewEd25519Signer builds a signer from an optional PEM private key and an
// optional bundle of PEM public keys to trust on verification. When a private
// key is supplied its own public key is automatically trusted. At least one
// key (private or public) must be provided.
func NewEd25519Signer(privPEM, verifyKeysPEM []byte) (Signer, error) {
	s := &ed25519Signer{verify: map[string]ed25519.PublicKey{}}

	if len(privPEM) > 0 {
		priv, err := parseEd25519Private(privPEM)
		if err != nil {
			return nil, err
		}
		s.priv = priv
		pub := priv.Public().(ed25519.PublicKey)
		s.keyID = deriveEd25519KeyID(pub)
		s.verify[s.keyID] = pub
	}

	pubs, err := parseEd25519Publics(verifyKeysPEM)
	if err != nil {
		return nil, err
	}
	for _, pub := range pubs {
		s.verify[deriveEd25519KeyID(pub)] = pub
	}

	if s.priv == nil && len(s.verify) == 0 {
		return nil, errors.New("ed25519 signer: no signing key and no verification keys provided")
	}
	return s, nil
}

func deriveEd25519KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return "ed25519-" + hex.EncodeToString(sum[:8])
}

func (s *ed25519Signer) AlgID() uint8  { return AlgEd25519 }
func (s *ed25519Signer) KeyID() string { return s.keyID }
func (s *ed25519Signer) CanSign() bool { return s.priv != nil }

func (s *ed25519Signer) Sign(msg []byte) ([]byte, error) {
	if s.priv == nil {
		return nil, errors.New("ed25519 signer: verify-only, no private key")
	}
	return ed25519.Sign(s.priv, msg), nil
}

func (s *ed25519Signer) Verify(keyID string, msg, sig []byte) error {
	pub, ok := s.verify[keyID]
	if !ok {
		return fmt.Errorf("untrusted key id %q", keyID)
	}
	if !ed25519.Verify(pub, msg, sig) {
		return errors.New("signature mismatch")
	}
	return nil
}

func parseEd25519Private(pemBytes []byte) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("ed25519 signer: no PEM block found in private key")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("ed25519 signer: parse private key: %w", err)
	}
	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("ed25519 signer: private key is %T, want ed25519", key)
	}
	return priv, nil
}

func parseEd25519Publics(pemBytes []byte) ([]ed25519.PublicKey, error) {
	var pubs []ed25519.PublicKey
	rest := pemBytes
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		key, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("ed25519 signer: parse public key: %w", err)
		}
		pub, ok := key.(ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf("ed25519 signer: public key is %T, want ed25519", key)
		}
		pubs = append(pubs, pub)
	}
	return pubs, nil
}
