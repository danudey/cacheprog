# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The guideline for versioning is as follows:

- If the change is breaking, increase major version (e.g. `v1.3.0` -> `v2.0.0`).
- If the change is a new non-breaking feature, increase minor version (e.g. `v1.2.1` -> `v1.3.0`).
- If the change is not related to new features i.e. bugfixes, dependency upgrades, etc., increase patch version (e.g. `v1.2.0` -> `v1.2.1`).

## [0.2.0](https://github.com/danudey/cacheprog/compare/v0.1.0...v0.2.0) (2026-09-14)


### Features

* add --disable-put flag to disable writing to remote storage ([b00901b](https://github.com/danudey/cacheprog/commit/b00901bc04d7d5dab84877917a7a882e2a7e6c81))
* add ability to exlude headers from signing in s3 client ([34bd085](https://github.com/danudey/cacheprog/commit/34bd085bba2608e14c5e510f436f751321faa4d3))
* add circuit-breaker for remote storage that trips on consecuitive errors ([a705b7a](https://github.com/danudey/cacheprog/commit/a705b7a38bfd93551248f82066ab8ef5ab6834d4))
* add half-open state to circuit breaker ([22feeb4](https://github.com/danudey/cacheprog/commit/22feeb43dc139fd4f869ab0fbfcfc2c6b3c17f5a))
* add half-open state to circuit breaker for remote storage recovery ([dede777](https://github.com/danudey/cacheprog/commit/dede777f4ec603c3ab6fe6b3728f7bfd376d674d))
* add read-only mode to disable writing to remote storage ([da59cb1](https://github.com/danudey/cacheprog/commit/da59cb1206f7e3b90eb78eb4933af71814bbcac2))
* address PR feedback for read-only mode ([0dea099](https://github.com/danudey/cacheprog/commit/0dea099113483a1d522429befb09d129cc9e589c))
* rename read-only to disable-put, disable put support at protocol level ([b7427f4](https://github.com/danudey/cacheprog/commit/b7427f42b5046ba0125649b1f909fba7fc9c5dc4))


### Bug Fixes

* fix goroutine leak and server deadlock ([8d54c3e](https://github.com/danudey/cacheprog/commit/8d54c3e726b6365276cb9fcb6cca88a6abd16c97))
* fix goroutine leak and server deadlock ([85ffe2c](https://github.com/danudey/cacheprog/commit/85ffe2cb73c30d13d1a07dfda753f48f01955b08))


### Documentation

* describe how to run e2e tests using docker cli ([76934be](https://github.com/danudey/cacheprog/commit/76934bec2b8798537f895c25c9fabe52ebc2cf58))
* introduce CHANGELOG.md ([3b60106](https://github.com/danudey/cacheprog/commit/3b60106798456a1c6446b5a9aa4d3bac72e15bb9))
* typo in README ([69c5758](https://github.com/danudey/cacheprog/commit/69c5758d4ecea0fdefeff3dfdff68c6c2e90a61a))

## [Unreleased]
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
