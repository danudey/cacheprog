package signing

// Signer signs and verifies the (small) manifest bytes. Implementations are
// swappable: HMAC for the symmetric case, Ed25519 for the asymmetric case
// (follow-up), or a GPG-backed signer.
type Signer interface {
	// AlgID is the algorithm identifier recorded in (and authenticated by) the
	// manifest.
	AlgID() uint8

	// KeyID is the non-secret identifier of the active signing key. It is stored
	// in the manifest so verifiers can select the right key during rotation.
	KeyID() string

	// CanSign reports whether this signer holds signing key material. A
	// verify-only deployment (e.g. an asymmetric reader with only public keys)
	// returns false and does not upload objects.
	CanSign() bool

	// Sign returns a signature over msg.
	Sign(msg []byte) ([]byte, error)

	// Verify checks sig over msg, selecting the verification key by keyID.
	Verify(keyID string, msg, sig []byte) error
}
