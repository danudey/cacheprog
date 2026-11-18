package cacheprog

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/platacard/cacheprog/internal/infra/logging"
)

// RemoteStorageCircuitBreaker disables remote storage operations after too many
// consecutive errors. Gets and puts are tracked separately and degrade in steps:
//   - failing puts disable puts only, so the remote is still used for gets;
//   - failing gets disable the remote entirely (gets and puts), leaving local storage only.
type RemoteStorageCircuitBreaker struct {
	upstream RemoteStorage

	get breakerState
	put breakerState
}

func NewRemoteStorageCircuitBreaker(upstream RemoteStorage, maxConsecutiveErrors int64, retryAfter time.Duration) *RemoteStorageCircuitBreaker {
	return &RemoteStorageCircuitBreaker{
		upstream: upstream,
		get:      breakerState{maxConsecutiveErrors: maxConsecutiveErrors, retryAfter: retryAfter},
		put:      breakerState{maxConsecutiveErrors: maxConsecutiveErrors, retryAfter: retryAfter},
	}
}

type breakerState struct {
	maxConsecutiveErrors int64
	retryAfter           time.Duration

	currentConsecutiveErrors atomic.Int64
	lastTrippedNano          atomic.Int64
}

// tripped reports whether the error threshold is reached, without considering recovery.
func (s *breakerState) tripped() bool {
	return s.currentConsecutiveErrors.Load() >= s.maxConsecutiveErrors
}

// isOpen reports whether the circuit is open (tripped).
// If a retryAfter duration is configured and enough time has passed since the last trip,
// it allows a single probe request through by resetting the trip timestamp.
func (s *breakerState) isOpen() bool {
	if !s.tripped() {
		return false
	}

	if s.retryAfter <= 0 {
		return true
	}

	lastTripped := s.lastTrippedNano.Load()
	now := time.Now().UnixNano()
	if now-lastTripped >= s.retryAfter.Nanoseconds() {
		// Use CompareAndSwap so only one concurrent caller wins the probe
		if s.lastTrippedNano.CompareAndSwap(lastTripped, now) {
			slog.Info("Circuit breaker half-open: allowing probe request")
			return false
		}
	}

	return true
}

func (s *breakerState) success() {
	s.currentConsecutiveErrors.Store(0)
}

// failure registers an error and reports whether the circuit has been tripped by it.
func (s *breakerState) failure() bool {
	if s.currentConsecutiveErrors.Add(1) < s.maxConsecutiveErrors {
		return false
	}
	s.lastTrippedNano.Store(time.Now().UnixNano())
	return true
}

func (b *RemoteStorageCircuitBreaker) Get(ctx context.Context, request *GetRequest) (*GetResponse, error) {
	if b.get.isOpen() {
		return nil, ErrNotFound // report as "not found" to avoid logging
	}

	resp, err := b.upstream.Get(ctx, request)
	switch {
	case errors.Is(err, nil):
		b.get.success()
		return resp, nil
	case errors.Is(err, ErrNotFound):
		// do not touch error counter because it's expected error but may be a problem with upstream
		return nil, err
	}

	if b.get.failure() {
		// this may be logged multiple times because of concurrent requests but it's not a problem
		slog.ErrorContext(ctx, "Remote storage has been disabled because of too many consecutive errors, falling back to local storage only",
			"operation", "get", logging.Error(err))
		return nil, ErrNotFound
	}

	return nil, err
}

func (b *RemoteStorageCircuitBreaker) Put(ctx context.Context, request *PutRequest) (*PutResponse, error) {
	// Failing gets disable the remote entirely. Check it without probing:
	// recovery of gets is driven by get requests only.
	if b.get.tripped() || b.put.isOpen() {
		_, _ = io.Copy(io.Discard, request.Body)
		return &PutResponse{}, nil // just discard the request
	}

	resp, err := b.upstream.Put(ctx, request)
	if err == nil {
		b.put.success()
		return resp, nil
	}

	if b.put.failure() {
		// this may be logged multiple times because of concurrent requests but it's not a problem
		slog.ErrorContext(ctx, "Remote storage puts have been disabled because of too many consecutive errors, continuing with gets only",
			"operation", "put", logging.Error(err))
		return &PutResponse{}, nil
	}

	return nil, err
}
