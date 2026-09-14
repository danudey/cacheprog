package signing

import (
	"bytes"
	"crypto/md5" //nolint:gosec // md5 is used only as an S3 content checksum/ETag, not for security
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/platacard/cacheprog/internal/app/cacheprog"
)

// LocationInline is the configuration value selecting the inline carrier.
const LocationInline = "inline"

// inline container layout (all integers big-endian):
//
//	magic        "CPS1"            4 bytes
//	manifestLen  uint32            4 bytes
//	sigLen       uint16            2 bytes
//	manifest     manifestLen bytes
//	signature    sigLen bytes
//	payload      the compressed object bytes
const (
	inlineMagic      = "CPS1"
	inlineHeaderSize = len(inlineMagic) + 4 + 2 // magic + manifestLen + sigLen
	maxInlineSig     = 1 << 16                  // sigLen is a uint16
)

// InlineCarrier frames the manifest and signature in-band, ahead of the
// payload. Cached objects are small and the upload path already buffers them in
// memory, so wrapping reads the body fully and recomputes the content
// checksums over the resulting container.
type InlineCarrier struct{}

func (InlineCarrier) Name() string { return LocationInline }

func (InlineCarrier) WrapPut(req *cacheprog.PutRequest, manifest, sig []byte) error {
	if len(manifest) > maxFieldLen {
		return fmt.Errorf("manifest too large for inline container: %d bytes", len(manifest))
	}
	if len(sig) >= maxInlineSig {
		return fmt.Errorf("signature too large for inline container: %d bytes", len(sig))
	}

	payload, err := io.ReadAll(req.Body)
	if err != nil {
		return fmt.Errorf("read payload: %w", err)
	}

	container := make([]byte, 0, inlineHeaderSize+len(manifest)+len(sig)+len(payload))
	container = append(container, inlineMagic...)
	container = binary.BigEndian.AppendUint32(container, uint32(len(manifest))) //nolint:gosec // bounded above by maxFieldLen
	container = binary.BigEndian.AppendUint16(container, uint16(len(sig)))      //nolint:gosec // bounded above by maxInlineSig
	container = append(container, manifest...)
	container = append(container, sig...)
	container = append(container, payload...)

	// The stored body is now the container, so the S3 checksum/ETag must cover
	// the container, not just the payload. Recompute both.
	md5sum := md5.Sum(container) //nolint:gosec // see import note
	sha := sha256.Sum256(container)

	req.Body = bytes.NewReader(container)
	req.Size = int64(len(container))
	req.MD5Sum = md5sum[:]
	req.Sha256Sum = sha[:]
	return nil
}

func (InlineCarrier) UnwrapGet(resp *cacheprog.GetResponse) (manifest, sig []byte, payload io.ReadCloser, signed bool, err error) {
	body := resp.Body

	magic := make([]byte, len(inlineMagic))
	n, err := io.ReadFull(body, magic)
	switch {
	case err == nil && string(magic) == inlineMagic:
		// signed container, parse the rest of the header below
	case err == io.EOF, err == io.ErrUnexpectedEOF, err == nil:
		// too short to be a container, or no magic: an unsigned object. Stitch
		// the bytes we consumed back in front of the remaining body.
		rest := io.MultiReader(bytes.NewReader(magic[:n]), body)
		return nil, nil, readCloser{Reader: rest, Closer: body}, false, nil
	default:
		_ = body.Close()
		return nil, nil, nil, false, fmt.Errorf("read magic: %w", err)
	}

	var lens [6]byte
	if _, err := io.ReadFull(body, lens[:]); err != nil {
		_ = body.Close()
		return nil, nil, nil, false, fmt.Errorf("read header: %w", err)
	}
	manifestLen := binary.BigEndian.Uint32(lens[0:4])
	sigLen := binary.BigEndian.Uint16(lens[4:6])

	if manifestLen > maxFieldLen {
		_ = body.Close()
		return nil, nil, nil, false, fmt.Errorf("manifest length %d exceeds maximum", manifestLen)
	}

	manifest = make([]byte, manifestLen)
	if _, err := io.ReadFull(body, manifest); err != nil {
		_ = body.Close()
		return nil, nil, nil, false, fmt.Errorf("read manifest: %w", err)
	}

	sig = make([]byte, sigLen)
	if _, err := io.ReadFull(body, sig); err != nil {
		_ = body.Close()
		return nil, nil, nil, false, fmt.Errorf("read signature: %w", err)
	}

	// whatever remains is the payload
	return manifest, sig, body, true, nil
}

// readCloser pairs an arbitrary reader with a separate closer so a wrapped
// stream still closes the underlying body.
type readCloser struct {
	io.Reader
	io.Closer
}
