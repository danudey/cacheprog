package app

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"time"

	"github.com/platacard/cacheprog/internal/app/cacheprog"
	"github.com/platacard/cacheprog/internal/infra/cacheproto"
	"github.com/platacard/cacheprog/internal/infra/compression"
	"github.com/platacard/cacheprog/internal/infra/logging"
	"github.com/platacard/cacheprog/internal/infra/metrics"
	"github.com/platacard/cacheprog/internal/infra/signing"
	"github.com/platacard/cacheprog/internal/infra/storage"
)

type CacheprogAppArgs struct {
	RemoteStorageArgs
	MetricsPushArgs

	RootDirectory           string        `arg:"--root-directory,env:ROOT_DIRECTORY" placeholder:"PATH" help:"Root directory to local storage of objects. Must be read-write accessible by user and read-accessible by 'go' compiler. If not provided, subdirectory in system temporary directory will be used."`
	MaxConcurrentRemoteGets int           `arg:"--max-concurrent-remote-gets,env:MAX_CONCURRENT_REMOTE_GETS" placeholder:"NUM" help:"Max number of concurrent remote gets, unlimited if not provided"`
	MaxConcurrentRemotePuts int           `arg:"--max-concurrent-remote-puts,env:MAX_CONCURRENT_REMOTE_PUTS" placeholder:"NUM" help:"Max number of concurrent remote puts, unlimited if not provided"`
	MaxBackgroundWait       time.Duration `arg:"--max-background-wait,env:MAX_BACKGROUND_WAIT" placeholder:"DURATION" default:"10s" help:"Max time to wait for waiting of background operations to complete"`
	MinRemotePutSize        int64         `arg:"--min-remote-put-size,env:MIN_REMOTE_PUT_SIZE" placeholder:"SIZE" help:"Min size of object to push to remote storage, no size limit if not provided"`
	DisableGet              bool          `arg:"--disable-get,env:DISABLE_GET" help:"Disable getting objects from any storage, useful to force rebuild of the project and rewrite cache"`
	DisablePut              bool          `arg:"--disable-put,env:DISABLE_PUT" help:"Disable writing to remote storage"`
}

type RemoteStorageArgs struct {
	S3Args
	HTTPStorageArgs
	SigningArgs

	RemoteStorageType    string        `arg:"--remote-storage-type,env:REMOTE_STORAGE_TYPE" placeholder:"TYPE" default:"disabled" help:"Remote storage type. Available: s3, http, disabled"`
	MaxConsecutiveErrors int64         `arg:"--max-consecutive-errors,env:REMOTE_STORAGE_MAX_CONSECUTIVE_ERRORS" default:"10" placeholder:"NUM" help:"Max number of consecutive errors to tolerate before disabling the remote storage, zero or negative value means unlimited"`
	RetryAfter           time.Duration `arg:"--retry-after,env:REMOTE_STORAGE_RETRY_AFTER" default:"15s" placeholder:"DURATION" help:"How long to wait before probing remote storage after circuit breaker trips, zero disables recovery"`

	AllowInsecureHTTPRemotes bool `arg:"--allow-insecure-http-remotes,env:ALLOW_INSECURE_HTTP_REMOTES" help:"Allow plaintext http:// (and minio+http://) remote storage and credentials endpoints. Insecure: traffic can be read or tampered with in transit, poisoning builds. Intended only for local testing."`
}

type SigningArgs struct {
	SigningAlgorithm  string `arg:"--signing-algorithm,env:SIGNING_ALGORITHM" placeholder:"ALG" help:"Sign uploaded objects and verify fetched ones. Available: hmac-sha256, ed25519. Empty disables signing."`
	SigningKey        string `arg:"--signing-key,env:SIGNING_KEY" placeholder:"KEY" help:"Signing key material (HMAC secret, or PEM ed25519 private key). Prefer --signing-key-file to keep secrets out of the process environment."`
	SigningKeyFile    string `arg:"--signing-key-file,env:SIGNING_KEY_FILE" placeholder:"PATH" help:"Path to a file containing the signing key. For HMAC a single trailing newline is stripped."`
	SigningKeyID      string `arg:"--signing-key-id,env:SIGNING_KEY_ID" placeholder:"ID" help:"Non-secret identifier of the signing key, used for rotation (HMAC only; ed25519 derives ids from the public key). Defaults to a digest of the key."`
	VerifyKeys        string `arg:"--verify-keys,env:VERIFY_KEYS" placeholder:"PEM" help:"ed25519 only: PEM-encoded public keys to trust on verification. Used by verify-only readers and for key rotation."`
	VerifyKeysFile    string `arg:"--verify-keys-file,env:VERIFY_KEYS_FILE" placeholder:"PATH" help:"Path to a file containing PEM-encoded ed25519 public keys to trust on verification."`
	SignatureLocation string `arg:"--signature-location,env:SIGNATURE_LOCATION" placeholder:"LOC" default:"inline" help:"Where the signature is stored. Available: inline, metadata."`
	RequireSignature  bool   `arg:"--require-signature,env:REQUIRE_SIGNATURE" help:"Reject unsigned objects on fetch instead of passing them through. Enable once the cache has refilled with signed objects."`
}

type S3Args struct {
	Endpoint                  *url.URL      `arg:"--s3-endpoint,env:S3_ENDPOINT" placeholder:"URL" help:"Endpoint for S3-compatible storages, use schemes minio+http://, minio+https://, etc. for minio compatibility."`
	ForcePathStyle            bool          `arg:"--s3-force-path-style,env:S3_FORCE_PATH_STYLE" placeholder:"true/false" help:"Forces path style endpoints, useful for some S3-compatible storages."`
	Region                    string        `arg:"--s3-region,env:S3_REGION" placeholder:"REGION" help:"S3 region name. If not provided will be detected automatically via GetBucketLocation API."`
	Bucket                    string        `arg:"--s3-bucket,env:S3_BUCKET" placeholder:"BUCKET" help:"S3 bucket name."`
	ExcludeHeadersFromSigning []string      `arg:"--s3-exclude-headers-from-signing,env:S3_EXCLUDE_HEADERS_FROM_SIGNING" placeholder:"[header]" help:"Headers to exclude from signing, comma separated list"`
	Prefix                    string        `arg:"--s3-prefix,env:S3_PREFIX" placeholder:"PREFIX" help:"Prefix for S3 keys, useful to run multiple apps on same bucket. Templated, GOOS, GOARCH and env.<env var> are available. Template format: {% GOOS %}"`
	Expiration                time.Duration `arg:"--s3-expiration,env:S3_EXPIRATION" placeholder:"DURATION" help:"Sets expiration for each S3 object during Put, 0 - no expiration."`
	CredentialsEndpoint       string        `arg:"--s3-credentials-endpoint,env:S3_CREDENTIALS_ENDPOINT" placeholder:"URL" help:"Credentials endpoint for S3-compatible storages."`
	AccessKeyID               string        `arg:"--s3-access-key-id,env:S3_ACCESS_KEY_ID" placeholder:"ID" help:"S3 access key id."`
	AccessKeySecret           string        `arg:"--s3-access-key-secret,env:S3_ACCESS_KEY_SECRET" placeholder:"SECRET" help:"S3 access key secret."`
	SessionToken              string        `arg:"--s3-session-token,env:S3_SESSION_TOKEN" placeholder:"TOKEN" help:"S3 session token."`
}

type HTTPStorageArgs struct {
	BaseURL      *url.URL     `arg:"--http-storage-base-url,env:HTTP_STORAGE_BASE_URL" placeholder:"URL" help:"Base URL for HTTP storage."`
	ExtraHeaders []httpHeader `arg:"--http-storage-extra-headers,env:HTTP_STORAGE_EXTRA_HEADERS" placeholder:"[key:value]" help:"Extra headers to be added to each request."`
}

type MetricsPushArgs struct {
	Endpoint     *url.URL          `arg:"--metrics-push-endpoint,env:METRICS_PUSH_ENDPOINT" placeholder:"URL" help:"Metrics endpoint, metrics will be pushed if provided"`
	Method       string            `arg:"--metrics-push-method,env:METRICS_PUSH_METHOD" placeholder:"METHOD" default:"GET" help:"HTTP method to use for sending metrics"`
	ExtraLabels  map[string]string `arg:"--metrics-push-extra-labels,env:METRICS_PUSH_EXTRA_LABELS" placeholder:"[key=value]" help:"Extra labels to be added to each metric, format: key=value"`
	ExtraHeaders []httpHeader      `arg:"--metrics-push-extra-headers,env:METRICS_PUSH_EXTRA_HEADERS" placeholder:"[key:value]" help:"Extra headers to be added to each request."`
}

func (r *RemoteStorageArgs) configureRemoteStorage() (cacheprog.RemoteStorage, error) {
	base, err := r.configureBaseStorage()
	if err != nil || base == nil {
		return base, err
	}
	return r.wrapWithSigning(base)
}

func (r *RemoteStorageArgs) configureBaseStorage() (cacheprog.RemoteStorage, error) {
	switch r.RemoteStorageType {
	case "s3":
		slog.Info("Using S3 remote storage")
		return storage.ConfigureS3(storage.S3Config{
			KeyPrefix:                 r.Prefix,
			Expiration:                r.Expiration,
			Bucket:                    r.Bucket,
			Region:                    r.Region,
			ExcludeHeadersFromSigning: r.ExcludeHeadersFromSigning,
			Endpoint:                  urlOrEmpty(r.Endpoint),
			ForcePathStyle:            r.ForcePathStyle,
			CredentialsEndpoint:       r.CredentialsEndpoint,
			AccessKeyID:               r.AccessKeyID,
			AccessKeySecret:           r.AccessKeySecret,
			SessionToken:              r.SessionToken,
			AllowInsecureHTTP:         r.AllowInsecureHTTPRemotes,
		})
	case "http":
		slog.Info("Using HTTP remote storage")
		return storage.ConfigureHTTP(urlOrEmpty(r.BaseURL), headerValuesToHTTP(r.ExtraHeaders), r.AllowInsecureHTTPRemotes)
	case "disabled":
		slog.Info("Disabled remote storage")
		return nil, nil
	default:
		return nil, fmt.Errorf("invalid remote storage type: %s", r.RemoteStorageType)
	}
}

func (r *RemoteStorageArgs) wrapWithSigning(base cacheprog.RemoteStorage) (cacheprog.RemoteStorage, error) {
	key, err := r.loadSigningKey()
	if err != nil {
		return nil, err
	}
	verifyKeys, err := r.loadVerifyKeys()
	if err != nil {
		return nil, err
	}

	signer, carrier, enabled, err := signing.Configure(signing.Config{
		Algorithm:  r.SigningAlgorithm,
		Key:        key,
		KeyID:      r.SigningKeyID,
		VerifyKeys: verifyKeys,
		Location:   r.SignatureLocation,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to configure signing: %w", err)
	}
	if !enabled {
		return base, nil
	}

	slog.Info("Object signing enabled",
		"algorithm", r.SigningAlgorithm,
		"location", carrier.Name(),
		"key_id", signer.KeyID(),
		"require", r.RequireSignature,
	)
	return signing.NewRemoteStorage(base, signer, carrier, r.RequireSignature), nil
}

func (r *RemoteStorageArgs) loadSigningKey() ([]byte, error) {
	if r.SigningKeyFile != "" {
		data, err := os.ReadFile(r.SigningKeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read signing key file: %w", err)
		}
		// strip a single trailing newline that editors/shells commonly add
		data = bytes.TrimRight(data, "\n")
		data = bytes.TrimRight(data, "\r")
		return data, nil
	}
	if r.SigningKey != "" {
		return []byte(r.SigningKey), nil
	}
	return nil, nil
}

func (r *RemoteStorageArgs) loadVerifyKeys() ([]byte, error) {
	if r.VerifyKeysFile != "" {
		data, err := os.ReadFile(r.VerifyKeysFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read verify keys file: %w", err)
		}
		return data, nil
	}
	if r.VerifyKeys != "" {
		return []byte(r.VerifyKeys), nil
	}
	return nil, nil
}

func (a *CacheprogAppArgs) Run(ctx context.Context) error {
	defer func() {
		if err := metrics.PushMetrics(ctx, metrics.PushConfig{
			Endpoint:     urlOrEmpty(a.Endpoint),
			ExtraLabels:  a.ExtraLabels,
			ExtraHeaders: headerValuesToHTTP(a.ExtraHeaders),
			Method:       a.Method,
		}); err != nil {
			slog.Warn("Failed to push metrics", "error", err)
		}
	}()

	defer metrics.ObserveOverallRunTime()()

	remoteStorage, err := a.configureRemoteStorage()
	if err != nil {
		return fmt.Errorf("failed to configure remote storage: %w", err)
	}

	if remoteStorage != nil && a.MaxConsecutiveErrors > 0 {
		remoteStorage = cacheprog.NewRemoteStorageCircuitBreaker(remoteStorage, a.MaxConsecutiveErrors, a.RetryAfter)
	}

	if remoteStorage != nil {
		remoteStorage = cacheprog.ObservingRemoteStorage{RemoteStorage: remoteStorage}
	}

	diskStorage, err := storage.ConfigureDisk(a.RootDirectory)
	if err != nil {
		return fmt.Errorf("failed to configure disk storage: %w", err)
	}

	h := cacheprog.NewHandler(cacheprog.HandlerOptions{
		RemoteStorage:           remoteStorage,
		MaxConcurrentRemoteGets: a.MaxConcurrentRemoteGets,
		MaxConcurrentRemotePuts: a.MaxConcurrentRemotePuts,
		LocalStorage:            cacheprog.ObservingLocalStorage{LocalStorage: diskStorage},
		CloseTimeout:            a.MaxBackgroundWait,
		CompressionCodec:        compression.NewCodec(),
		DisableGet:              a.DisableGet,
		DisablePut:              a.DisablePut,
	})
	defer func() {
		statistics := h.GetStatistics()
		slog.Info("cacheprog statistics",
			"get_calls", statistics.GetCalls,
			"get_hits", statistics.GetHits,
			"get_hit_ratio", fmt.Sprintf("%.2f", float64(statistics.GetHits)/float64(statistics.GetCalls)),
			"put_calls", statistics.PutCalls,
			"downloaded", logging.HumanBytes(statistics.BytesDownloaded),
			"uploaded", logging.HumanBytes(statistics.BytesUploaded),
		)
	}()

	server := cacheproto.NewServer(cacheproto.ServerOptions{
		Reader:  os.Stdin,
		Writer:  os.Stdout,
		Handler: h,
	})

	defer context.AfterFunc(ctx, server.Stop)()

	slog.Info("Starting cacheprog")

	return server.Run()
}
