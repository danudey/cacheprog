package signing

import (
	"io"

	"github.com/platacard/cacheprog/internal/app/cacheprog"
)

// Carrier decides where the (manifest, signature) pair travels relative to the
// object body. The signing/verifying logic is identical across carriers; only
// the transport differs:
//   - the inline carrier frames them in-band, wrapping the body in a small
//     self-describing container (storage-agnostic, proxy-friendly).
//   - the metadata carrier (follow-up) stores them out-of-band in S3 metadata
//     or HTTP headers, leaving the body as the raw payload.
type Carrier interface {
	// Name returns the configuration value identifying this carrier.
	Name() string

	// WrapPut attaches manifest+sig to an outgoing Put request, adjusting the
	// body, size and checksums as needed.
	WrapPut(req *cacheprog.PutRequest, manifest, sig []byte) error

	// UnwrapGet extracts the manifest and signature from an incoming Get
	// response and returns a reader over the raw (compressed) payload. The
	// returned payload reader takes ownership of resp.Body and must be closed by
	// the caller. signed reports whether a signature was present at all; when
	// false, manifest/sig are nil and payload yields the object unchanged.
	UnwrapGet(resp *cacheprog.GetResponse) (manifest, sig []byte, payload io.ReadCloser, signed bool, err error)
}
