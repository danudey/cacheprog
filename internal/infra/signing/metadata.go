package signing

import (
	"io"

	"github.com/platacard/cacheprog/internal/app/cacheprog"
)

// LocationMetadata is the configuration value selecting the metadata carrier.
const LocationMetadata = "metadata"

// MetadataCarrier transports the manifest and signature out-of-band, in the
// PutRequest/GetResponse Manifest and Signature fields, which the storage
// backends persist as S3 object metadata or HTTP headers. The object body stays
// the raw (compressed) payload, so objects remain consumable by other tools and
// the stored checksum continues to cover exactly the payload.
type MetadataCarrier struct{}

func (MetadataCarrier) Name() string { return LocationMetadata }

func (MetadataCarrier) WrapPut(req *cacheprog.PutRequest, manifest, sig []byte) error {
	req.Manifest = manifest
	req.Signature = sig
	return nil
}

func (MetadataCarrier) UnwrapGet(resp *cacheprog.GetResponse) (manifest, sig []byte, payload io.ReadCloser, signed bool, err error) {
	if len(resp.Manifest) == 0 {
		// No signing metadata: an unsigned object. The body is the raw payload.
		return nil, nil, resp.Body, false, nil
	}
	return resp.Manifest, resp.Signature, resp.Body, true, nil
}
