# Architecture Audit — TLS-Chameleon 3.0.1 (against the 3.1 specification)

> Date: 2026-08-23 · Audited version: 3.0.1 (commit `55b20d4`)
> Baseline before any 3.1 change: **213 passed** (full) / **211** (no-curl) / **202** (bare install)
> Purpose: map the "TLS-Chameleon 3.1 — Architecture Evolution & Independence"
> specification onto the existing codebase, and identify ONLY the remaining gaps.

---

## 0. Headline

v3.0.0 already implemented the majority of the 3.1 specification during its
phase-based development (Phases 0–10). This audit therefore classifies each
specification requirement as DONE / PARTIAL / MISSING and lists the minimum
changes required for a 3.1.0 release. **No rewrite is needed or planned.**

## A. What works (verified)

| Spec § | Requirement | Status in 3.0.1 |
|---|---|---|
| 6 | Transport interface + truthful capabilities | ✅ `transport/base.py` (`Capabilities`, `SessionConfig`, `Transport`) |
| 7 | curl_cffi isolated in one module | ✅ `transport/curl_backend.py`; enforced by source-scan tests |
| 10 | Multi-layer fingerprint model (TLS/H2/Headers/meta) | ✅ `fingerprint/model.py` |
| 12 | Source metadata: captured/documented/synthetic | ✅ `Metadata`; synthetic+verified rejected by validator |
| 13 | Local registry list/get/search/add/remove/export/import | ✅ `FingerprintRegistry` |
| 14 | Capture subsystem (`client.capture`, CLI `capture --raw`) | ✅ via TLS echo endpoints |
| 15/16 | Diff + explainable similarity, documented weights | ✅ `diff.py`, `similarity.py` |
| 17 | `trace=True` → structured trace, redacted | ✅ sync + async |
| 18/19 | `chameleon inspect` / `doctor` (+`--json`) | ✅ |
| 20 | Adaptive domain memory above transport, bounded/expiring/thread-safe/explainable | ✅ `adaptive.py` |
| 21 | Header-consistency engine ("Profile inconsistency detected") | ✅ `fingerprint/headers.py` + doctor check |
| 22 | Deterministic randomization (`random_seed`) | ✅ SHA-256-derived RNG |
| 23 | HTTP/2 represented independently of curl_cffi | ✅ `HTTP2Fingerprint` + `http2_simulator` |
| 24 | HTTP/3 reported only when real | ✅ honest `False` today |
| 25 | Proxy support across backends | ✅ behavior-wise (dicts) |
| 26 | Persistence without serializing curl objects | ✅ export/import_session |
| 27 | Redaction of secrets in all outputs | ✅ `security/redaction.py` |
| 28/29/30 | Magnet optional; AI lazy-imported inside `ask()`; core light | ✅ verified (imports at lines 174/192/214 are function-local) |
| 31 | curl_cffi optional packaging (`[curl]`) | ✅ since v3.0.0 |
| 32 | Native backend research + implementation | ✅ `docs/NATIVE_BACKEND_RESEARCH.md` + `PrimpTransport` `[native]` |
| 33/35 | Truthful capabilities; stable `--json` schemas | ✅ |
| 34 | Benchmark comparing backends | ✅ `chameleon benchmark` |
| 36 | Local test servers, no external dependence | ✅ full/native/bare suites |
| 37 | Backward compatibility | ✅ v2 names intact |
| 38 | README repositioning (honest IS/IS-NOT) | ✅ rewritten in 3.0.1 |

## B. What is incomplete / MISSING (the actual 3.1 work)

| # | Spec § | Gap | Plan for 3.1.0 |
|---|---|---|---|
| M1 | 8 | High-level `Chameleon` API does not exist (only `TLSSession`/`Session`/`AsyncSession`) | Add `Chameleon` + `AsyncChameleon` as first-class public classes (thin subclasses); add `seed=` alias for `random_seed` |
| M2 | 9 | `ChameleonResponse` still proxies unknown attributes to raw backend responses (`__getattr__` fallback) — backend types can leak | Replace with an owned response: explicit attribute surface (`status_code/text/content/headers/cookies/url/encoding/history/ok/json()/raise_for_status()` + `.magnet/.trace`); unknown attributes raise `AttributeError` listing supported fields |
| M3 | 6/33 | Capability vocabulary narrower than spec: missing `http1`, `tls_customization`, `fingerprint_capture`, `websocket` | Extend frozen `Capabilities`; set per-backend truthfully (websocket True on curl only; fingerprint_capture False everywhere until an in-band capture path exists) |
| M4 | 25 | No `ProxyConfig` abstraction (requests-style dicts reach backends directly) | Add `ProxyConfig` dataclass; clients accept `str \| dict \| ProxyConfig`, normalize centrally |
| M5 | 26 | No formal `SessionState` separation from backend state | Add `SessionState` dataclass used by `export_session`/`import_session` (same JSON keys; additive) |
| M6 | 34 | `chameleon compare-backends` name absent (functionality exists as `benchmark`) | Alias subcommand to the benchmark runner |
| M7 | 39 | `docs/research/` section absent | Create index + starter analyses derived from our own captures/snapshots (JA4 family signatures, H2 SETTINGS comparison, benchmark snapshot link) |
| M8 | 22 | `seed=` parameter name from spec examples | Accept `seed=` as alias of `random_seed=` |

## C. Coupled to curl_cffi

* `transport/curl_backend.py` — sanctioned (only import site).
* `benchmark.py` — sanctioned comparison harness (documented exception,
  guarded by dedicated request-path isolation test).
* Profile data contains `impersonate` hint strings ("chrome124") — these are
  *hints consumed by backends*, not backend objects; mapping lives in each
  backend (`map_impersonate_hint`). Acceptable; documented.
* Nothing else. Enforced mechanically by two isolation tests.

## D. Already backend-independent

client/fingerprint/profiles/diagnostics/security/adaptive/magnet/cli — pinned
by `test_request_path_modules_stay_backend_free`.

## E. Should remain unchanged

Public names (`TLSSession`, `AsyncSession`, `get/post/...`, `Magnet`,
profile dicts, gallery helpers), domain-memory legacy aliases, CLI exit codes,
JSON schema versions, benchmark methodology.

## F. Needs refactoring (minimal, listed)

`ChameleonResponse.__getattr__` → owned surface (M2). Everything else is
additive.

## G. New subsystems introduced by 3.1

`Chameleon`/`AsyncChameleon` API layer · `ProxyConfig` · `SessionState` ·
expanded capability vocabulary · `docs/research/`.

## H. Migration risks

1. Owned response could break users who reached through to backend internals
   (e.g., `resp.http_version` on curl) — mitigated by a generous explicit
   surface + clear `AttributeError` message naming supported fields.
2. `Chameleon` subclassing must not drift from `TLSSession` behavior —
   implemented as subclass, not copy.
3. Capability additions must keep `to_dict()` backward-compatible (additive
   keys only).
4. ProxyConfig normalization must preserve exact current semantics for
   strings/dicts (covered by existing proxy tests).

## Decision

Proceed with M1–M8 only. All other specification items are already satisfied;
re-implementing them would violate the spec's own §2 ("do not rewrite").
