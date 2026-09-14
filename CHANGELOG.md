# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The guideline for versioning is as follows:

- If the change is breaking, increase major version (e.g. `v1.3.0` -> `v2.0.0`).
- If the change is a new non-breaking feature, increase minor version (e.g. `v1.2.1` -> `v1.3.0`).
- If the change is not related to new features i.e. bugfixes, dependency upgrades, etc., increase patch version (e.g. `v1.2.0` -> `v1.2.1`).

## [Unreleased]
- Signing now degrades gracefully for shared CI configs: a blank signing key (e.g. an empty secret) is ignored with a warning and continues verification-only, and when verification keys are configured without a signing key cacheprog switches to read-only mode (remote puts disabled) instead of silently dropping uploads. Lets you ship verification keys to every environment and add signing keys only where the cache should be written
- **Security**: optional object signing. A signed manifest binds the cache key (`ActionID`) to its output (`OutputID`) and a digest of the stored bytes; objects are signed on upload and verified on download, and an object that fails verification is treated as a cache miss. Supports `hmac-sha256` (symmetric) and `ed25519` (asymmetric — private key signs, public keys verify, so untrusted readers can verify but not forge), with the signature carried either `inline` (in a self-describing container) or in `metadata` (S3 metadata / HTTP headers). Configure via `CACHEPROG_SIGNING_*` / `CACHEPROG_VERIFY_KEYS*` / `CACHEPROG_SIGNATURE_LOCATION` / `CACHEPROG_REQUIRE_SIGNATURE` (see [README](./README.md#object-signing))
- **Security**: verify the integrity of objects downloaded from remote storage by checking that their content hashes to the claimed `OutputID` (SHA-256); objects that fail verification are treated as a cache miss instead of being served to the compiler
- **Security**: bound writes to disk by the declared object size to prevent decompression bombs from untrusted remote storage exhausting disk; oversized objects are rejected and treated as a cache miss
- **Security**: reject plaintext `http://` / `minio+http://` remote storage and credentials endpoints by default; add `--allow-insecure-http-remotes` / `CACHEPROG_ALLOW_INSECURE_HTTP_REMOTES` to opt back in for local testing. **Breaking for plaintext HTTP setups, including `proxy` mode** — set the override (see [README](./README.md#transport-security))
- **Security**: `cacheprog proxy` now listens on loopback (`127.0.0.1:8080`) by default instead of all interfaces, and warns when bound to a non-loopback address. **Breaking if you relied on the previous `:8080` default** — set `CACHEPROG_PROXY_LISTEN_ADDRESS` explicitly
- S3 `AccessDenied` errors are no longer silently treated as cache misses; they are surfaced (and logged) so misconfigured credentials are visible

## [1.2.0] - 2026-03-31
- Added half-open state to circuit breaker: after `retryAfter` elapses, a single probe request is allowed through to test if the upstream has recovered
- Added `--disable-put` / `DISABLE_PUT` flag to disable writing to remote storage

## [1.1.1] - 2026-03-13
- Fix some goroutine leaks and deadlocks: https://github.com/platacard/cacheprog/pull/30
- Use `synctest` for concurrency-related tests to make them more reliable
- Upgrade dependencies

## [1.1.0] - 2026-02-18

- Added ability to exclude specified http headers from request signing in S3 client. Mainly to support Google Cloud Storage, see [README.md](./README.md#s3-compatible-storage-configuration) for more details.
- Added consecutive error threshold based circuit-breaker for remote storage
- Introduce CHANGELOG.md

## [1.0.3] - 2026-02-12

- Upgrade to Go 1.26 in tests and release process
- Upgrade dependencies

## [1.0.2] - 2026-01-08

- Refactor to use `waitgroup.Go()` across codebase
- Upgrade dependencies

## [1.0.1] - 2025-11-28

- Fixed ignoring of provided `http.Client` in `internal/infra/storage.NewHTTP()`
- Fixed file opening flags for metadata files of disk storage to avoid its' truncation.

## [1.0.0] - 2025-11-24

Initial release.
