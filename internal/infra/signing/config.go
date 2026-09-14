package signing

import (
	"fmt"
)

// Config describes how to build a Signer and Carrier from user settings.
type Config struct {
	Algorithm  string // "hmac-sha256", "ed25519", or "" to disable
	Key        []byte // signing key material: the HMAC secret, or the PEM ed25519 private key (empty for a verify-only ed25519 node)
	KeyID      string // optional label for the active key (HMAC only; ed25519 derives ids from the public key)
	VerifyKeys []byte // ed25519: PEM-encoded public keys to trust on verification
	Location   string // "inline" (default) or "metadata"
}

// Configure builds a Signer and Carrier from cfg. enabled is false (with no
// error) when signing is turned off (empty Algorithm).
func Configure(cfg Config) (signer Signer, carrier Carrier, enabled bool, err error) {
	if cfg.Algorithm == "" {
		return nil, nil, false, nil
	}

	switch cfg.Algorithm {
	case AlgHMACName:
		signer, err = NewHMACSigner(cfg.Key, cfg.KeyID)
		if err != nil {
			return nil, nil, false, err
		}
	case AlgEd25519Name:
		signer, err = NewEd25519Signer(cfg.Key, cfg.VerifyKeys)
		if err != nil {
			return nil, nil, false, err
		}
	default:
		return nil, nil, false, fmt.Errorf("unknown signing algorithm %q (supported: %s, %s)", cfg.Algorithm, AlgHMACName, AlgEd25519Name)
	}

	switch cfg.Location {
	case "", LocationInline:
		carrier = InlineCarrier{}
	case LocationMetadata:
		carrier = MetadataCarrier{}
	default:
		return nil, nil, false, fmt.Errorf("unknown signature location %q (supported: %s, %s)", cfg.Location, LocationInline, LocationMetadata)
	}

	return signer, carrier, true, nil
}
