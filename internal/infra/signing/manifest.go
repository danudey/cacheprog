// Package signing provides authenticity for cached objects. A small,
// fixed-size Manifest binds a cache key (ActionID) to its output (OutputID)
// and a digest of the stored bytes; that manifest is signed on upload and
// verified on download. Because the manifest — not the payload — is what gets
// signed, the per-object signing cost is negligible: the only payload-sized
// work is a single SHA-256 pass that the upload path already performs.
package signing

import (
	"encoding/binary"
	"fmt"
	"math"
)

const (
	// manifestVersion is the current manifest format version.
	manifestVersion uint8 = 1

	// maxFieldLen bounds every length-prefixed field so a malformed or hostile
	// manifest can't trigger huge allocations during Unmarshal.
	maxFieldLen = 64 * 1024
)

// Signature algorithm identifiers, stored inside the manifest so that the
// signature also authenticates the algorithm (prevents downgrade/confusion).
const (
	AlgInvalid    uint8 = 0
	AlgHMACSHA256 uint8 = 1
	AlgEd25519    uint8 = 2 // reserved for the asymmetric follow-up
)

// Manifest is the authenticated description of a cached object. Every field is
// covered by the signature, so an attacker cannot alter the key→output binding,
// the compression parameters, or the content digest without invalidating it.
type Manifest struct {
	Version          uint8
	AlgID            uint8
	KeyID            string // non-secret id of the signing key (for rotation)
	ActionID         []byte // the cache key
	OutputID         []byte // Go's output id (SHA-256 of the uncompressed output)
	CompressionAlgo  string // e.g. "zstd" or "" for none
	UncompressedSize int64
	CompressedSize   int64
	CompressedSHA256 []byte // digest of the stored (compressed) payload
}

// Marshal returns a deterministic, canonical byte encoding of the manifest.
// The same manifest always produces the same bytes, which is what makes
// signing/verification and the Put dedup optimization stable.
func (m *Manifest) Marshal() []byte {
	buf := make([]byte, 0, 96)
	buf = append(buf, m.Version, m.AlgID)
	buf = appendLP(buf, []byte(m.KeyID))
	buf = appendLP(buf, m.ActionID)
	buf = appendLP(buf, m.OutputID)
	buf = appendLP(buf, []byte(m.CompressionAlgo))
	buf = binary.BigEndian.AppendUint64(buf, uint64(m.UncompressedSize)) //nolint:gosec // object sizes are non-negative
	buf = binary.BigEndian.AppendUint64(buf, uint64(m.CompressedSize))   //nolint:gosec // object sizes are non-negative
	buf = appendLP(buf, m.CompressedSHA256)
	return buf
}

// UnmarshalManifest parses bytes produced by Marshal. It is strict: trailing
// bytes, truncation, or oversized fields are errors.
func UnmarshalManifest(b []byte) (*Manifest, error) {
	r := &reader{b: b}

	var m Manifest
	m.Version = r.byteVal()
	m.AlgID = r.byteVal()
	m.KeyID = string(r.lp())
	m.ActionID = r.lp()
	m.OutputID = r.lp()
	m.CompressionAlgo = string(r.lp())
	m.UncompressedSize = r.size()
	m.CompressedSize = r.size()
	m.CompressedSHA256 = r.lp()

	if r.err != nil {
		return nil, r.err
	}
	if r.off != len(r.b) {
		return nil, fmt.Errorf("manifest: %d trailing bytes", len(r.b)-r.off)
	}
	if m.Version != manifestVersion {
		return nil, fmt.Errorf("manifest: unsupported version %d", m.Version)
	}
	return &m, nil
}

func appendLP(dst, field []byte) []byte {
	// field lengths are small (ids, hashes) and bounded by maxFieldLen on read
	dst = binary.BigEndian.AppendUint16(dst, uint16(len(field))) //nolint:gosec // bounded, see comment
	return append(dst, field...)
}

// size reads a uint64 length/size and converts it to a non-negative int64,
// rejecting values that would overflow.
func (r *reader) size() int64 {
	v := r.uint64()
	if r.err != nil {
		return 0
	}
	if v > math.MaxInt64 {
		r.err = fmt.Errorf("manifest: size %d out of range", v)
		return 0
	}
	return int64(v)
}

// reader is a small cursor over a byte slice that records the first error and
// turns all subsequent reads into no-ops, so parsing stays linear and simple.
type reader struct {
	b   []byte
	off int
	err error
}

func (r *reader) byteVal() uint8 {
	if r.err != nil {
		return 0
	}
	if r.off+1 > len(r.b) {
		r.err = fmt.Errorf("manifest: unexpected end of data")
		return 0
	}
	v := r.b[r.off]
	r.off++
	return v
}

func (r *reader) uint64() uint64 {
	if r.err != nil {
		return 0
	}
	if r.off+8 > len(r.b) {
		r.err = fmt.Errorf("manifest: unexpected end of data")
		return 0
	}
	v := binary.BigEndian.Uint64(r.b[r.off:])
	r.off += 8
	return v
}

func (r *reader) lp() []byte {
	if r.err != nil {
		return nil
	}
	if r.off+2 > len(r.b) {
		r.err = fmt.Errorf("manifest: unexpected end of data")
		return nil
	}
	n := int(binary.BigEndian.Uint16(r.b[r.off:]))
	r.off += 2
	if n > maxFieldLen {
		r.err = fmt.Errorf("manifest: field length %d exceeds maximum", n)
		return nil
	}
	if r.off+n > len(r.b) {
		r.err = fmt.Errorf("manifest: unexpected end of data")
		return nil
	}
	v := make([]byte, n)
	copy(v, r.b[r.off:r.off+n])
	r.off += n
	return v
}
