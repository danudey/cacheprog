package signing

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"log/slog"

	"github.com/platacard/cacheprog/internal/app/cacheprog"
	"github.com/platacard/cacheprog/internal/infra/logging"
)

// RemoteStorage decorates a cacheprog.RemoteStorage, signing objects on upload
// and verifying them on download. It implements cacheprog.RemoteStorage so it
// slots in alongside the circuit-breaker and observer decorators.
//
// Verification failures never fail the build: they are logged and reported as a
// cache miss (ErrNotFound), so the compiler rebuilds instead of trusting — or
// choking on — an unverifiable object.
type RemoteStorage struct {
	inner   cacheprog.RemoteStorage
	signer  Signer
	carrier Carrier
	require bool
}

// NewRemoteStorage wraps inner. When require is true, objects that carry
// no signature are also treated as a miss (use false during rollout so a cache
// of pre-existing unsigned objects keeps working while it refills).
func NewRemoteStorage(inner cacheprog.RemoteStorage, signer Signer, carrier Carrier, require bool) *RemoteStorage {
	return &RemoteStorage{inner: inner, signer: signer, carrier: carrier, require: require}
}

func (s *RemoteStorage) Put(ctx context.Context, req *cacheprog.PutRequest) (*cacheprog.PutResponse, error) {
	if !s.signer.CanSign() {
		// Verify-only deployment (e.g. an asymmetric reader): never publish
		// objects we can't sign, they'd be unverifiable for everyone else.
		slog.DebugContext(ctx, "Signer is verify-only, skipping remote put")
		return &cacheprog.PutResponse{}, nil
	}

	manifest := (&Manifest{
		Version:          manifestVersion,
		AlgID:            s.signer.AlgID(),
		KeyID:            s.signer.KeyID(),
		ActionID:         req.ActionID,
		OutputID:         req.OutputID,
		CompressionAlgo:  req.CompressionAlgorithm,
		UncompressedSize: req.UncompressedSize,
		CompressedSize:   req.Size,
		CompressedSHA256: req.Sha256Sum, // digest of the compressed payload
	}).Marshal()

	sig, err := s.signer.Sign(manifest)
	if err != nil {
		return nil, fmt.Errorf("sign object: %w", err)
	}

	if err := s.carrier.WrapPut(req, manifest, sig); err != nil {
		return nil, fmt.Errorf("wrap object: %w", err)
	}

	return s.inner.Put(ctx, req)
}

func (s *RemoteStorage) Get(ctx context.Context, req *cacheprog.GetRequest) (*cacheprog.GetResponse, error) {
	resp, err := s.inner.Get(ctx, req)
	if err != nil {
		return nil, err
	}

	manifestBytes, sig, payload, signed, err := s.carrier.UnwrapGet(resp)
	if err != nil {
		// resp.Body is already closed by the carrier on error
		return nil, s.reject(ctx, "malformed signed object", err)
	}

	if !signed {
		if s.require {
			_ = payload.Close()
			return nil, s.reject(ctx, "object is unsigned but signatures are required", nil)
		}
		// Transition mode: pass the unsigned object through untouched.
		resp.Body = payload
		return resp, nil
	}

	verified, err := s.verify(manifestBytes, sig, payload)
	_ = payload.Close()
	if err != nil {
		return nil, s.reject(ctx, "signature verification failed", err)
	}

	// The manifest is now authenticated, so it — not any out-of-band metadata —
	// is the source of truth for the object's properties.
	resp.OutputID = verified.manifest.OutputID
	resp.CompressionAlgorithm = verified.manifest.CompressionAlgo
	resp.UncompressedSize = verified.manifest.UncompressedSize
	resp.Size = verified.manifest.CompressedSize
	resp.Body = io.NopCloser(bytes.NewReader(verified.payload))
	return resp, nil
}

type verifiedObject struct {
	manifest *Manifest
	payload  []byte
}

func (s *RemoteStorage) verify(manifestBytes, sig []byte, payload io.Reader) (*verifiedObject, error) {
	manifest, err := UnmarshalManifest(manifestBytes)
	if err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}
	if manifest.AlgID != s.signer.AlgID() {
		return nil, fmt.Errorf("unexpected signature algorithm %d", manifest.AlgID)
	}
	if err := s.signer.Verify(manifest.KeyID, manifestBytes, sig); err != nil {
		return nil, fmt.Errorf("verify signature: %w", err)
	}

	// The compressed size is authenticated, so it is a trustworthy bound on how
	// much we read into memory (one extra byte to detect an oversized payload).
	buf, err := io.ReadAll(io.LimitReader(payload, manifest.CompressedSize+1))
	if err != nil {
		return nil, fmt.Errorf("read payload: %w", err)
	}
	if int64(len(buf)) != manifest.CompressedSize {
		return nil, fmt.Errorf("payload size %d does not match manifest %d", len(buf), manifest.CompressedSize)
	}
	if sum := sha256.Sum256(buf); !bytes.Equal(sum[:], manifest.CompressedSHA256) {
		return nil, fmt.Errorf("payload digest does not match manifest")
	}

	return &verifiedObject{manifest: manifest, payload: buf}, nil
}

// reject logs the reason and returns ErrNotFound so the handler reports a cache
// miss and the compiler rebuilds, rather than failing the build.
func (s *RemoteStorage) reject(ctx context.Context, reason string, err error) error {
	slog.WarnContext(ctx, "Rejecting remote object, treating as cache miss", "reason", reason, logging.Error(err))
	return cacheprog.ErrNotFound
}
