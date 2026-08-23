# CHANGELOG

## v3.0.1
- Docs-only release: README fully rewritten for v3 — honest IS/IS-NOT
  positioning, three-backend architecture, fingerprint system / diagnostics /
  adaptive engine / CLI sections, benchmarks and docs index. No code changes.

# v3.0.0 — released 2026-08-23

## Phase 8 — Native Backend Implementation)
- Added `transport/primp_backend.py` (`PrimpTransport`, backend name
  `"native"`, alias `"primp"`): optional backend on the primp/rustls-fork
  impersonation stack, per docs/NATIVE_BACKEND_RESEARCH.md Stage A.
  - New extra `[native]` (`pip install tls-chameleon[native]`,
    `primp>=1.3,<2` pinned).
  - Factory preference order is now `curl -> native -> httpx`; behavior is
    unchanged unless the new extra is installed.
  - Profile `impersonate` hints map to nearest available primp target within
    the same browser family (larger-or-equal fallback), never a wrong-family
    guess; unknown families run unspoofed and are logged.
  - Duck-typed session adapter (headers/cookies/close semantics) including a
    URL-scoped cookie shim over primp's `cookie_store` API so
    save/export/import keep working unchanged.
- Live verification performed through our capture tooling against a TLS echo
  endpoint: computed JA3 hashes match wire-reported hashes, and Chrome vs
  Firefox produce distinct, correctly-family-shaped JA4 fingerprints.
- Benchmark registry gains `tls-chameleon(native)` and `primp(raw)` rows
  (local http1: native wrapper ~567 rps, faster than both existing wrappers).
- Isolation guard extended to cover `primp`; degradation tests updated for
  three-backend reality (curl missing now degrades to native when present).

## Phase 7 — Native Backend Research
- Added `docs/NATIVE_BACKEND_RESEARCH.md`: evaluation of native-backend
  candidates (primp/rustls stack, tls-client/utls via CFFI, curl_cffi
  re-evaluation, aioquic for H3, rejected options) against the project's
  criteria; recommends adopting **primp** as an optional `[native]` backend
  behind the existing Transport interface in Phase 8, with concrete
  acceptance criteria (fingerprint verification via our capture tooling,
  wheel matrix, benchmark tolerance, version pinning).
- No implementation changes: research-before-implementation gate respected.

## Phase 6 — Benchmarks
- Added `tls_chameleon.benchmark`: reproducible local benchmark harness.
  - Scenarios: `http1` (plain HTTP/1.1 throughput/latency) and `tls`
    (self-signed ephemeral cert via `cryptography`; first-request vs pooled
    warm requests yields estimated handshake overhead).
  - Participants: tls-chameleon (both engines), raw curl_cffi, raw httpx,
    raw aiohttp (async). Missing dependencies appear as explicit
    `"status": "skipped"` rows with reasons -- never silently omitted,
    never fabricated.
  - Every report embeds environment metadata (versions, platform, timestamp)
    and run parameters; memory figures are tracemalloc-based lower bounds
    (Python allocations only) as documented.
  - HTTP/2 & HTTP/3 scenarios intentionally unavailable until a defensible
    protocol-capable fixture exists -- reported as unavailable rather than
    faked.
- `chameleon benchmark` now runs real measurements:
  `--scenario/--requests/--warmup/--save PATH/--json`; exit 0 when any client
  produced measurements.
- Added `docs/BENCHMARK_METHODOLOGY.md` defining measurement semantics and
  stated limitations (absolute numbers are machine-specific).
- Architecture guard updated: `benchmark.py` is an explicitly allow-listed
  exception to backend isolation (it must import libraries directly to
  measure them); a second stricter test now pins the request path
  (client/fingerprint/diagnostics/security) to remain backend-free forever.

## Phase 5 — CLI
- Added `tls_chameleon.cli` package + `chameleon` console script
  (`pyproject [project.scripts]`) and `python -m tls_chameleon` entry point.
  Stdlib argparse only -- no new dependencies.
- Commands (all major ones support stable, documented `--json`):
  - `chameleon get URL` (-X method, repeatable -H headers, --max-body,
    --trace) with redacted output;
  - `chameleon inspect URL [--echo-endpoint URL]` (stable
    `tls-chameleon.inspect/1` schema);
  - `chameleon doctor URL [--echo-endpoint URL]` (exit 1 only on verdict
    `fail`; warns stay informational);
  - `chameleon capture [URL] --raw` (redacted raw payload opt-in);
  - `chameleon diff FILE1 FILE2` (accepts capture files, registry exports,
    or bare fingerprint dicts);
  - `chameleon fingerprint list|show|validate` (validate understands all
    layouts and runs header-consistency checks; exit code reflects validity);
  - `chameleon benchmark` honest stub (exit 3, no invented numbers);
  - `chameleon version [--json]`.
- Documented exit codes: 0 ok / 1 error or failed check / 2 usage /
  3 not implemented.
- Shared client flags across commands: `--engine`, `--profile`, `--timeout`,
  `--verify/--no-verify`, `--random-seed`.
- CLI test suite uses a real local HTTP server (127.0.0.1) plus a
  network-access guard fixture: zero external requests in CI.

## Phase 4 — Adaptive Engine
- Added `tls_chameleon.adaptive.DomainMemory`: bounded (LRU), expiring
  (`ttl_seconds`), thread-safe, explainable per-domain profile memory.
  Stores only `domain -> profile name` + non-sensitive metadata; never
  credentials. Legacy aliases `_DOMAIN_MEMORY/_DOMAIN_MEMORY_LOCK/
  _DOMAIN_MEMORY_MAX` remain as views over the same storage.
- New public API on clients:
  - `client.profile_for(domain)` -> `{profile, reason, confidence,
    last_used}` explaining adaptive selection;
  - `adaptive=True/False` constructor flag (disables learning AND switching);
  - `adaptive_ttl` seconds for memory expiry.
- Deterministic randomization:
  - `random_seed=...` constructor param on sync and async clients; same seed +
    config reproduces identical profile variants, cipher order, ghost-mode
    jitter and retry jitter. Seed derivation is process-stable (SHA-256 of
    `repr(seed)`, never Python's salted `hash()`).
  - `randomizer.derive_seed_rng(seed)` helper exported publicly.
  - `randomize_profile(profile, rng=None)` and `FingerprintRandomizer(profile,
    rng=None)` accept an optional seeded RNG (backward compatible).
- Header consistency engine (`fingerprint.headers`):
  - detects contradictions such as Chrome UA + Firefox Sec-CH-UA brands,
    Firefox profiles carrying client hints, mobile claims on desktop
    platforms, UA-OS vs Sec-CH-UA-Platform mismatches, missing client hints
    on Chrome >= 90;
  - errors are prefixed "Profile inconsistency detected";
  - integrated into `doctor()` as a new "Header consistency" check.
- Fixed latent bug: module-level helpers dropped the `http3` session kwarg
  (it leaked into request kwargs); also added new kwargs to the split list.

## Phase 3 — Diagnostics
- Added `tls_chameleon.diagnostics` package:
  - `trace`: structured `NetworkTrace` (backend, profile, protocol, IPs,
    timing, redacted request/response headers, optional observed fingerprint).
    Honesty rule: unobservable fields stay `None` and are listed in `notes`.
    Protocol indicators normalized across backends (`h2`, `http/1.1`, `h3`).
  - `inspect`: `inspect_url()` one-request inspection with stable JSON
    (`to_dict`) and human text (`to_text`); optional `echo_endpoint` merges
    the network-observed JA3/JA4/ALPN into the result.
  - `doctor`: `doctor()` runs connection / backend-capability / profile
    validity / security checks with ok-warn-fail-skip verdicts and concrete
    recommendations; `echo_endpoint=True` compares observed JA4 and HTTP/2
    SETTINGS against the active profile. ASCII-safe symbols for legacy
    terminals.
- Client integration: `client.get/post/...(..., trace=True)` attaches a
  redacted `NetworkTrace` to the response via `response.trace`; the `trace`
  kwarg never leaks to backends. Supported on both sync and async clients.
- Added `tls_chameleon.security.redaction`: deterministic `[REDACTED]`
  replacement for sensitive headers (Authorization/Cookie/Set-Cookie/API-key/
  token families), deep dict/list scrubbing by key patterns, and URL userinfo
  stripping. All diagnostic outputs pass through it.
- Fixed missing `CaptureResult` export from `tls_chameleon.fingerprint`
  (its absence silently voided the whole fingerprint export block).

## Phase 2 — Fingerprint System
- Added `tls_chameleon.fingerprint` package:
  - `model`: structured `Fingerprint` = `TLSFingerprint` (JA3 components, ALPN,
    JA4) + `HTTP2Fingerprint` (SETTINGS) + `HeaderFingerprint` + provenance
    `Metadata` (`captured` / `documented` / `synthetic`).
  - `adapter`: lossless conversion between legacy gallery dicts and the model;
    non-numeric JA3 tokens preserved via `extra["ja3_raw"]`.
  - `registry`: thread-safe `FingerprintRegistry` over all 48 built-in profiles
    plus custom entries; `list/get/search/add/remove/export/import_`; local-only.
  - `validator`: rejects duplicate IDs, empty ciphers, TLS 1.3 ciphers under a
    pre-1.2 record version, unknown sources, and **synthetic fingerprints marked
    verified**; warns on captures lacking timestamps and unmapped cipher names.
  - `similarity`: configurable weighted layer scores (tls/http2/headers),
    per-field detail, changed fields, plain-language explanation, confidence.
    Measures structural similarity only -- explicitly NOT detectability.
  - `diff`: field-by-field SAME/DIFFERENT report with deterministic text and
    stable JSON rendering (`diff_fingerprints(a, b)`).
  - `capture`: live capture through TLS echo endpoints (default
    `https://tls.peet.ws/api/all`) routed via the pluggable transport layer;
    maps observed JA3/JA4/ALPN/HTTP2 SETTINGS with honest `captured` provenance.

## Phase 1 — Pluggable Transport Architecture
- **Architecture:**
  - Added `tls_chameleon.transport` package: `Transport` interface, `Capabilities`,
    `SessionConfig`, backend factory with `auto`/`curl`/`httpx` selection.
  - Isolated ALL `curl_cffi` usage into `transport/curl_backend.py` and all `httpx`
    usage into `transport/httpx_backend.py`; enforced by a source-scan regression test.
    The library now runs without curl_cffi installed (honest httpx fallback).
  - Added honest per-backend capability reporting: `client.capabilities.http3`,
    `.tls_fingerprint_spoofing`, etc. (also included in `get_fingerprint_info()`).
  - Restored custom cipher-suite ordering on modern curl_cffi (>=0.7): the old
    `CURLOPT_SSL_CIPHER_LIST` constant no longer exists; now uses `CurlOpt.SSL_CIPHER_LIST`.
- **Bug Fixes:**
  - Fixed httpx sync proxies being silently ignored (httpx >=0.28 removed the
    attribute-based API; proxies are now applied at client construction).
  - Fixed proxy rotation crashing on httpx >=0.28 (`proxies=` request kwarg is no
    longer accepted by httpx; the transport rebuilds the client instead).
  - Fixed `AsyncSession.__aexit__` never awaiting curl_cffi's coroutine `close()`.
  - Unknown `engine=` values now log a warning instead of failing silently.
- **Docs/CI:**
  - Added `docs/ARCHITECTURE_AUDIT.md` (Phase 0 audit + migration plan).
  - CI now installs `pytest-asyncio` and intentionally omits curl_cffi to cover the
    degraded-backend path.

## v2.1.0 
- **Bug Fixes:**
  - Fixed `get_forms()` in Magnet silently returning `None`.
  - Fixed bare `except:` clauses swallowing valid exceptions like `KeyboardInterrupt`.
  - Fixed `_DOMAIN_MEMORY` thread-safety issue under high concurrency via thread lock.
  - Fixed convenience functions (`get`, `post`, etc.) improperly parsing request vs session kwargs.
  - Fixed false-positive block detection for pages mentioning Cloudflare/blocking but returning 200.
  - Fixed `httpx` engine not properly applying custom cipher suites.
  - Fixed duplicate/unnecessary library imports (`json`).
- **Feature Enhancements:**
  - Added new **`AsyncTLSChameleon` / `AsyncSession`** via `tls_chameleon.async_client` for native `asyncio` scraping.
  - Updated legacy profile loading: consolidated manual profiles dictionary into single-source gallery.
  - Added new standard Chrome profiles up to **Chrome 130**.
  - Added placeholder JA4 strings to prepare for next-generation fingerprinting.
  - Added `rate_limit` parameter to limit requests per second per domain.
  - Added `on_retry` callback hook (provides attempt, response, and profile context).
- **Architecture & Polish:**
  - Migrated `Magnet` to use cached properties so they avoid re-parsing overhead.
  - Added `py.typed` marker enabling Type Hinting support for library consumers.
  - Added missing `.gitignore` and MIT `LICENSE` files.

## v2.0.0
- Rewrote engine to support both `curl_cffi` and `httpx`.
- Introduced Fingerprint Gallery with 45+ profiles.
- Added extensive HTTP/2 simulation support.
- Introduced AI-Urllib4 Adaptive Features (header morphing, WAF bypass).
- Added `Magnet` for data extraction.
