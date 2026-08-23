# TLS-Chameleon — Architecture Audit (Phase 0)

> Date: 2026-08-23 · Version audited: 2.2.0 · Python: 3.11.15
> Scope: full repository inspection before any Phase-1 change.
> Baseline test result before any modification: **11 passed / 0 failed** (`pytest tests/`).

---

## 1. Current Architecture

```
tls_chameleon/
├── __init__.py            # Public API surface, defensive try/except imports
├── client.py              # 1055 lines. Sync client + engine selection + response wrapper + module-level helpers
├── async_client.py        # 259 lines. Async client, duplicates engine logic from client.py
├── profiles.py            # Legacy profile aliases -> fingerprint_gallery
├── fingerprint_gallery.py # 30+ browser profiles (dict-based)
├── gen_fingerprint.py     # Deterministic generative fingerprints ("gen://..." scheme)
├── randomizer.py          # FingerprintRandomizer, create_variant_profile
├── http2_simulator.py     # HTTP2Profile metadata (documentation-level, not wire-level)
├── fingerprint_updater.py # Remote profile updates
└── magnet.py              # HTML parsing/extraction utilities (emails, forms, secrets)
```

### Public API today

| Export | Kind | Notes |
|---|---|---|
| `TLSChameleon` / `Session` / `TLSSession` | class | Sync client |
| `AsyncTLSChameleon` / `AsyncSession` | class | Async client |
| `ChameleonResponse` | class | Thin proxy over backend response (+`.magnet`) |
| `request/get/post/put/delete/head/patch/options` | functions | Module-level helpers |
| `Magnet`, `FINGERPRINT_GALLERY`, `get_profile`, `randomize_profile`, ... | misc | Profile & extraction utilities |
| `generate_fingerprint`, `gen://` scheme | misc | Generative engine |

## 2. Dependency Graph

```
client.py ──► profiles.py ──► fingerprint_gallery.py
    │  ├─────► magnet.py
    │  ├─────► http2_simulator.py (optional)
    │  ├─────► curl_cffi   ← DIRECT import (try/except at module scope)
    │  └─────► httpx       ← DIRECT import (try/except at module scope)
async_client.py ──► client.py (_DOMAIN_MEMORY, _select_engine, ChameleonResponse)
    │         ──► curl_cffi   ← DUPLICATED direct import
    │         ──► httpx       ← DUPLICATED direct import
```

Declared dependencies (`pyproject.toml`):
- core: `httpx>=0.26`, `cryptography>=3.4`
- extras: `curl` (`curl_cffi>=0.6`), `ai`, `updater`, `http3`, `all`

**Inconsistency:** the README says curl_cffi powers realistic TLS signatures and is an *extra*, but the code treats it as the preferred default engine whenever installed, and there is no honest capability reporting about which engine actually serves a request.

## 3. curl_cffi Usage Map

| File | Line(s) | Usage |
|---|---|---|
| `client.py` | 50–54 | `from curl_cffi import requests as crequests; from curl_cffi import curl as ccurl` (guarded) |
| `client.py` | 281–303 | Session construction, `impersonate=`, `CURLOPT_SSL_CIPHER_LIST` cipher override |
| `client.py` | 466, 530 | Engine-branch in proxy rotation (`request_kwargs["proxies"]`) |
| `async_client.py` | 23–26 | Duplicate guarded import |
| `async_client.py` | 128–136 | `crequests.AsyncSession(impersonate=...)` |
| `fingerprint_gallery.py` | 342, 445, 586 | `impersonate` hint strings in profile data (data, not code) |
| `gen_fingerprint.py` | 643–650 | Docstring/comment references to impersonation limits |

Engine selection (`_select_engine`, client.py:62–71): prefers `curl` if importable, else `httpx`; explicit preference silently falls back when the dependency is missing; **an unknown `engine=` value is silently mapped to the default**.

## 4. Existing Feature Inventory

1. Profile gallery (30+), legacy aliases, unified `get_profile`
2. Deterministic generative fingerprints (`gen://family/os/major/tier/seed`)
3. Randomization (profile variants, cipher shuffle)
4. Domain memory (adaptive per-domain profile learning, bounded LRU=1000, thread-safe)
5. Block detection + retry with backoff/jitter, profile/proxy rotation, `on_retry` hook
6. Rate limiting per domain, ghost mode (timing jitter, payload padding)
7. Header morphing (case/order per profile)
8. WAF detection → adaptation (cloudflare/akamai/datadome/cloudfront)
9. Cookie persistence (Netscape/JSON), session export/import
10. Magnet HTML extraction; form autofill (`submit_form`); asset prefetch pool
11. HTTP/2 *simulation* (metadata only) and optional `http3=True` flag for httpx

## 5. Test Inventory

- `tests/test_features.py` (6): gen determinism, gen spec parse, cipher shuffle, domain-memory bound, profile retrieval, magnet extract
- `tests/test_tls_chameleon.py` (4): magnet forms, response magnet cache, convenience kwargs split, `_is_block` false positives
- `tests/test_http3_support.py` (1): httpx `http3=True` constructor smoke test
- Root-level scripts (`test_realworld.py`, `probe_*.py`, etc.) are manual probes, not CI tests.
- **Gaps:** no transport-selection tests, no missing-dependency degradation tests, no async tests, no isolation enforcement, no local-server integration tests.

## 6. Technical Debt / Defects Found

| # | Severity | Finding |
|---|---|---|
| D1 | High | Engine logic duplicated between `client.py` and `async_client.py` (two sources of truth that have already drifted). |
| D2 | High | `curl_cffi` imported directly in two modules; no single choke point; impossible to add a third backend or drop curl later without surgery. |
| D3 | Medium | **httpx sync proxies are silently ignored**: `self.session.proxies = {...}` (client.py:341) sets an attribute httpx 0.28 does not use (proxies were removed from httpx ≥0.28; must be `proxy=`/mounts at construction). |
| D4 | Medium | Per-request proxy rotation passes `proxies=` kwarg into `httpx.Client.request(...)`, which raises `TypeError` on httpx ≥0.28 → rotation loop burns retries then re-raises. |
| D5 | Medium | Unknown/garbage `engine=` values are silently accepted and mapped to default (no warning). |
| D6 | Low | `_select_engine("httpx")` with neither package installed returns `"httpx"` anyway → confusing late `RuntimeError` deep inside `_init_session`. |
| D7 | Low | `ChameleonResponse.__getattr__` proxies everything to raw backend responses → backend types leak into user code (e.g., `.cookies` type differs by engine). Acceptable short-term; formal Response model belongs to a later phase. |
| D8 | Low | No capability introspection: users cannot ask "does this session really do HTTP/3 / real TLS spoofing?" |

## 7. Migration Risks

- Silent-fallback semantics of `engine=` are observable behavior (tests/examples construct with `engine='httpx'` while curl is installed). Must preserve fallback-with-warning, not hard errors.
- `export_session()`/`import_session()` persist `engine` names — name compatibility must be kept (`"curl"`, `"httpx"`).
- `ChameleonResponse` duck-typing relies on backend responses exposing `.status_code/.text/.headers/.content/.cookies` — both current backends satisfy this.
- `save_cookies`/`load_cookies` handle both cookie-jar styles already; keep working unchanged.

## 8. Recommended Migration Path (Phase 1 — smallest safe step)

1. New `tls_chameleon.transport` package:
   - `base.py`: `Capabilities` (honest, per-backend), `SessionConfig` (owned dataclass), abstract `Transport`.
   - `curl_backend.py`: **the only module allowed to import `curl_cffi`**.
   - `httpx_backend.py`: only module importing `httpx`.
   - `factory.py`: registry + selection with preserved fallback order and warnings.
2. `client.py` / `async_client.py`: delete direct imports; build sessions via factory+transport; keep `engine` attribute, `_select_engine` shim, and all public names.
3. Fix D3/D4 inside `HttpxTransport` (proxies honored via constructor `proxy=`/mounts; rotated proxies handled at request layer).
4. Expose honest capabilities (`client.capabilities.http3`, `.tls_spoofing`, `.backend_name`, ...).
5. Add regression tests: selection/fallback, missing-curl degradation, capability honesty, source-isolation scan.
6. Defer to later phases: formal Request/Trace/Fingerprint models, CLI, native backend research.

## 9. Post-Phase-1 Target Shape

```
Public API (unchanged names)
        │
   TLSChameleon / AsyncTLSChameleon      ← fingerprint + policy logic only
        │
 tls_chameleon.transport.factory         ← selection: auto/curl/httpx
        │
 Transport interface (base.Transport)
   ├── CurlTransport   (isolated curl_cffi)
   └── HttpxTransport  (isolated httpx)
   └── future backends plug in here
```

Success criterion for Phase 1: all existing tests pass unchanged, new tests pass, and removing `curl_cffi` from the environment still yields a working (honestly degraded) library via httpx.
