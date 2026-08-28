# Changelog

## 5.0.0

Rewrite sslstrip as a Python 3.14-only, typed, `src/`-layout Linux application.

### Added

- `sslstrip run`, `sslstrip doctor`, `sslstrip cleanup`, and `sslstrip --version` (5.0.0).
- Shared Twisted `Agent` with a verified TLS policy, connection pool, and native `async def` orchestration via `Deferred.fromCoroutine`.
- gzip, Brotli 1.2.0, and stdlib Zstandard, including stacked encodings and an 8 MiB decoded-body limit.
- TTL (30 minutes) and LRU (10,000) bounds on the secure-link store.
- Managed nftables lifecycle: exclusive `/run/sslstrip` lock, atomic JSON `nft` operations, privilege drop, forwarding restore.
- `--ca-file` for extra lab certificate authorities. No insecure TLS option.
- Gated unredacted traffic logs (`--traffic-log` plus `--traffic-log-file`).
- pytest suite (unit, loopback subprocess, optional nftables namespace), Ruff, strict ty, uv lock, and a Python 3.14 quality workflow.

### Changed

- Packaging uses `uv_build`, `requires-python = ">=3.14"`, and exact pins for `Twisted[tls]` and `Brotli`. Transitive TLS libraries are locked in `uv.lock`.
- CLI defaults to loopback in manual mode; managed mode binds the selected interface address.
- Missing Host → 400, CONNECT → 405, protocol upgrades → 426, upstream/DNS/TLS failures → 502, timeouts → 504.

### Removed

- Favicon substitution and the hard-coded E\*TRADE expression.
- Twisted `HTTPClient` / factory / `DnsCache` client stack and global singletons.
- Dynamic import shim, top-level `sslstrip.py`, camelCase modules, mypy.
- iptables-only documentation as the managed path (nftables is first-class).
