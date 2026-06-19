package signing

import (
	"fmt"
)

// Config describes how to build a Signer and Carrier from user settings.
type Config struct {
	Algorithm string // "hmac-sha256", "ed25519", or "" to disable
	Key       []byte // signing key material (the HMAC secret); empty for verify-only
	KeyID     string // optional label for the active key
	Location  string // "inline" (default) or "metadata"
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
	case "ed25519":
		return nil, nil, false, fmt.Errorf("signing algorithm %q is not implemented yet (follow-up)", cfg.Algorithm)
	default:
		return nil, nil, false, fmt.Errorf("unknown signing algorithm %q (supported: %s)", cfg.Algorithm, AlgHMACName)
	}

	switch cfg.Location {
	case "", LocationInline:
		carrier = InlineCarrier{}
	case "metadata":
		return nil, nil, false, fmt.Errorf("signature location %q is not implemented yet (follow-up)", cfg.Location)
	default:
		return nil, nil, false, fmt.Errorf("unknown signature location %q (supported: %s)", cfg.Location, LocationInline)
	}

	return signer, carrier, true, nil
}
