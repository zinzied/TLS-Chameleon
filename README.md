# TLS-Chameleon

<img width="2816" height="1536" alt="TLSChameleom" src="https://github.com/user-attachments/assets/aa4fe457-30c5-49f6-ba7b-1d8604816d81" />

[![PyPI version](https://badge.fury.io/py/tls-chameleon.svg)](https://badge.fury.io/py/tls-chameleon)
[![CI](https://github.com/zinzied/TLS-Chameleon/actions/workflows/ci.yml/badge.svg)](https://github.com/zinzied/TLS-Chameleon/actions/workflows/ci.yml)

**TLS-Chameleon** is a modern Python HTTP networking stack with pluggable
browser-fingerprint backends, structured fingerprint research tooling,
diagnostics, and reproducible experiments — behind a simple,
requests-like API.

> **What it IS:** an HTTP client · a fingerprint-aware networking toolkit ·
> a diagnostic system · a protocol-research framework.
>
> **What it is NOT:** a Cloudflare/WAF bypass guarantee · a CAPTCHA solver ·
> an anonymity or stealth product. Detection outcomes depend on many factors
> outside any client library's control.

## 🆕 What's New in v3.1.0

- **`Chameleon` / `AsyncChameleon`** — the spec'd high-level API: WHAT vs HOW separation.

  ```python
  from tls_chameleon import Chameleon
  client = Chameleon(profile="chrome_124_linux", backend="curl", seed=42)
  r = client.get("https://example.com")
  ```

- **Owned response objects** — responses no longer proxy backend internals;
  an explicit surface (`status_code/text/content/headers/cookies/url/history/
  ok/json()/raise_for_status()` + `.magnet/.trace`) with self-documenting errors.
- **`ProxyConfig`** — typed proxy description (`str` | dict | dataclass), normalized once.
- **`SessionState`** — backend-independent session snapshots.
- **Expanded truthful capabilities** — every backend now reports
  `http1`, `tls_customization`, `websocket`, `fingerprint_capture` too.
- **`chameleon compare-backends`** — alias of the benchmark runner for
  curl/native/httpx comparison.
- **`docs/research/`** — protocol & fingerprint analyses produced with our own tooling.
- `seed=` accepted everywhere as alias of `random_seed=`.

## 🆕 What's New in v3.0.0

- **Pluggable transport architecture** — `curl`, `native` (primp/rustls) and
  `httpx` backends behind one interface, auto-selected (`curl → native → httpx`)
  with graceful degradation. curl_cffi is optional, never architectural.
- **Structured fingerprint system** — typed models, registry over 48 profiles,
  validator (rejects impossible/inconsistent configs), explainable similarity
  scoring, field-level diffing, live capture via TLS echo endpoints.
- **Diagnostics** — `response.trace`, `inspect_url()`, `doctor()` with
  check-by-check verdicts; every output automatically redacted.
- **Adaptive engine** — bounded/expiring/thread-safe domain memory with
  explainable selection (`client.profile_for(domain)`); header-consistency
  engine; deterministic randomization via `random_seed`.
- **CLI** — `chameleon get / inspect / doctor / capture / diff /
  fingerprint / benchmark / version`, all major commands with stable `--json`.
- **Reproducible benchmarks** — real local-server harness, stored methodology,
  no invented numbers.
- **Honest capability reporting** — `client.capabilities.tls_fingerprint_spoofing`,
  `.http3`, ... always reflect what the active backend actually does.

## 🚀 Features

- **Three interchangeable backends**
  - `curl` — curl-impersonate (curl_cffi): full JA3/JA4/H2 fingerprint control
  - `native` — primp/rustls stack: browser impersonation without libcurl
  - `httpx` — honest fallback: standard OpenSSL TLS (no JA3 spoofing)
- **48+ versioned profiles**: Chrome, Firefox, Safari, Edge across
  Windows 10/11, macOS, Linux, iOS, Android — plus a deterministic
  generative engine (`gen://family/os/major/tier/seed`)
- **Fingerprint research toolkit**: registry · validation · similarity ·
  diff · live capture
- **Diagnostics & doctor**: protocol/backend/timing traces, observed-vs-profile
  comparison, actionable recommendations
- **Adaptive behavior**: per-domain profile learning (bounded, expiring,
  thread-safe, disableable), header casing/order morphing, WAF detection
  with retry/backoff/rotation
- **Deterministic randomization**: same seed ⇒ identical variants, cipher
  order and jitter — reproducible experiments
- **Resilience**: proxy/profile pools, rate limiting, ghost mode, `on_retry` hooks
- **Magnet module 🧲**: emails, tables, forms, JSON-LD, deep extraction of
  JWTs/API keys; optional AI providers (`[ai]` extra)

## 📦 Install

```bash
pip install tls-chameleon            # core: works out of the box via httpx
pip install tls-chameleon[curl]      # + curl-impersonate backend (JA3 spoofing)
pip install tls-chameleon[native]    # + primp/rustls backend (JA3 spoofing, no curl)
pip install tls-chameleon[all]       # everything
```

> **Backend honesty:** without `[curl]` or `[native]` you get the httpx
> fallback — standard OpenSSL TLS, **no JA3 spoofing**. The active backend and
> its true capabilities are always inspectable:

```python
from tls_chameleon import TLSSession

client = TLSSession()
print(client.engine)                                  # "curl" | "native" | "httpx"
print(client.capabilities.http3)                      # only if truly available
print(client.capabilities.tls_fingerprint_spoofing)   # False on httpx!
```

### Pluggable architecture

```
Public API  (TLSSession / AsyncSession — unchanged names since v2)
     │
tls_chameleon.transport.factory      # auto / curl / native / httpx (+ custom)
     │
Transport interface                  # duck-typed sessions, capability reports
 ├─ CurlTransport    ← only module importing curl_cffi
 ├─ PrimpTransport   ← only module importing primp
 └─ HttpxTransport   ← only module importing httpx
```

Backends are strictly isolated (enforced by tests). Custom backends plug in
via `tls_chameleon.transport.register_transport`.

## ⚡ Quick Start

```python
from tls_chameleon import Chameleon          # v3.1 high-level API

client = Chameleon(profile="chrome_130_win11")   # WHAT: the fingerprint
                                                 # backend auto-selected: HOW
with client:
    r = client.get("https://example.com", trace=True)
    print(r.status_code, r.trace.protocol)
    print(client.capabilities.to_dict())
```

Classic aliases still work: `TLSSession` / `Session` / `AsyncSession`.

Async:

```python
import asyncio
from tls_chameleon import AsyncSession

async def main():
    async with AsyncSession(profile="chrome_130_win11") as session:
        r = await session.get("https://example.com", trace=True)
        print(r.trace.protocol, r.trace.timing_ms)

asyncio.run(main())
```

CLI:

```bash
chameleon inspect https://example.com --json
chameleon doctor https://example.com --echo-endpoint https://tls.peet.ws/api/clean
chameleon capture https://tls.peet.ws/api/all --raw --json
chameleon fingerprint list --browser chrome
chameleon diff capture_a.json capture_b.json
```

## 🔬 Fingerprint System

```python
from tls_chameleon import (
    FingerprintRegistry, validate_fingerprint,
    FingerprintSimilarity, diff_fingerprints, capture,
)

reg = FingerprintRegistry()
fp = reg.get("chrome_120_win11")          # lazy lookup over all built-ins

issues = validate_fingerprint(fp)          # structural + provenance checks

result = FingerprintSimilarity().compare(fp, reg.get("firefox_120_win11"))
print(result.total, result.layers)         # explainable, weighted scoring

report = diff_fingerprints(fp, reg.get("firefox_120_win11"))
print(report.to_text())                    # SAME/DIFFERENT per field + score

# Live capture: what does the network ACTUALLY see?
res = capture(session=client.session)      # via TLS echo endpoint
print(res.fingerprint.tls.ja3_hash)        # source="captured", timestamped
```

Provenance is explicit — every fingerprint is labeled
`captured`, `documented` or `synthetic`; synthetic data can never be marked
verified (enforced by the validator).

## 🩺 Diagnostics

```python
from tls_chameleon import inspect_url, doctor

print(inspect_url("https://example.com", client).to_text())

report = doctor("https://example.com",
                echo_endpoint="https://tls.peet.ws/api/clean")
print(report.to_text())
# [ ✓] Connection: h2 response 200 in 76ms
# [ ✓] Backend: backend 'curl' performs real TLS impersonation
# [ ⚠] Fingerprint (JA4): observed JA4 differs from profile ...
# Verdict: WARN
```

Traces attach to responses on demand — headers always redacted:

```python
r = client.get(url, trace=True)
r.trace.backend / .protocol / .timing_ms / .request_headers
```

Unobservable fields stay `None` with an explanatory note — never guessed.

## 🧠 Adaptive Engine

```python
client = TLSSession(adaptive=True, adaptive_ttl=3600, random_seed=12345)

client.profile_for("example.com")
# {'profile': 'chrome_130_win11', 'reason': 'learned after 3 successful
#  request(s); 12s ago', 'confidence': 0.6, 'last_used': ...}
```

Domain memory is LRU-bounded, TTL-expiring, thread-safe, stores only
`domain → profile` (never credentials), and explains itself. Same seed +
config ⇒ byte-identical fingerprint choices for reproducible runs.

## 📚 Profiles

| Browser | Versions | OS |
|---------|----------|----|
| Chrome | 120–130, android, latest | win10/win11/macos/linux/android |
| Firefox | 120–124 | win10/win11/macos/linux |
| Safari | iOS 16/17, macOS 13/14 | ios/macos |
| Edge | 120, 124 | win10/win11 |

```bash
chameleon fingerprint list                # or: list_available_profiles()
chameleon fingerprint show chrome_130_win11 --json
chameleon fingerprint validate my_profile.json
```

Generative fingerprints for research/fuzzing:
`TLSSession(profile="gen://chrome/win11/124/balanced/7")` — deterministic
per seed, always labeled `synthetic`.

## 🛠 API Reference (selection)

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `profile` | `str` | `None` | Profile name (e.g., `'chrome_124_linux'`) — the WHAT |
| `backend` / `engine` | `str` | `'auto'` | The HOW: `'curl'`, `'native'`, `'httpx'`; auto-selects best installed (`backend=` on `Chameleon`, `engine=` everywhere) |
| `random_seed` / `seed` | `Any` | `None` | Deterministic randomization seed (`seed=` on `Chameleon`) |
| `randomize` / `randomize_ciphers` | `bool` | `False` | Variant generation / cipher-order shuffle |
| `adaptive` / `adaptive_ttl` | `bool` / `float` | `True` / `None` | Domain-memory learning + expiry seconds |
| `http2` / `http3` | `bool` | `None` | Protocol preferences (backend-dependent) |
| `verify` | `bool` | `True` | Certificate verification (never disabled silently) |
| `proxies` / `proxies_pool` | `dict/str/list` | `None` | Proxy config / rotation pool |
| `rotate_profiles` / `on_block` | `list` / `str` | `None` / `'rotate'` | Block recovery: rotate/proxy/both/none |
| `rate_limit` | `float` | `None` | Max req/sec per domain |
| `ghost_mode` | `bool` | `False` | Timing jitter + payload padding |

Handy members: `client.capabilities`, `client.profile_for(domain)`,
`session.get_fingerprint_info()`, `response.trace`,
`save_cookies/load_cookies/export_session/import_session`,
plus the Magnet extractors (`response.magnet.*`) and `submit_form()`.

## 🖥 CLI

| Command | Purpose | Exit codes |
|---|---|---|
| `chameleon get URL [--trace]` | Spoofed request, redacted output | 0 ok / 1 error |
| `chameleon inspect URL` | One-request structured report | 0 / 1 |
| `chameleon doctor URL` | Connection/backend/profile/header checks | 0 (warn ok) / 1 fail |
| `chameleon capture [URL]` | Network-observed fingerprint | 0 / 1 |
| `chameleon diff A.json B.json` | Field-level fingerprint diff | 0 / 1 |
| `chameleon fingerprint list\|show\|validate` | Registry operations | 0 / 1 |
| `chameleon benchmark` | Reproducible local benchmarks | 0 / 3* |
| `chameleon compare-backends` | Same runner — curl vs native vs httpx | 0 / 3* |
| `chameleon version` | Version info | 0 |

All major commands accept `--json` with stable, documented schemas.
(*3 = feature pending its phase.)

## 📊 Benchmarks

Real local-server measurements only — methodology and limitations in
[`docs/BENCHMARK_METHODOLOGY.md`](docs/BENCHMARK_METHODOLOGY.md), a labeled
sample run in [`docs/BENCHMARK_SNAPSHOT.md`](docs/BENCHMARK_SNAPSHOT.md).
Absolute numbers are machine-specific; compare within a single report.

## 📖 Documentation

| Doc | Contents |
|---|---|
| [`docs/ARCHITECTURE_AUDIT_3_0_1.md`](docs/ARCHITECTURE_AUDIT_3_0_1.md) | 3.1 spec-to-code audit (gaps M1–M8) |
| [`docs/ARCHITECTURE_AUDIT.md`](docs/ARCHITECTURE_AUDIT.md) | v2 audit + v3 migration plan |
| [`docs/research/index.md`](docs/research/index.md) | fingerprint & protocol analyses (JA4, H2) |
| [`docs/NATIVE_BACKEND_RESEARCH.md`](docs/NATIVE_BACKEND_RESEARCH.md) | backend candidates, decision record |
| [`docs/BENCHMARK_METHODOLOGY.md`](docs/BENCHMARK_METHODOLOGY.md) | what the benchmark measures |
| [`docs/migration/curl_cffi.md`](docs/migration/curl_cffi.md) | coming from raw curl_cffi |
| `CHANGELOG.md` | full v3.x change list |

## 🤝 Contributing
Issues and Pull Requests welcome!

## 🌟 Credits
Built on [curl_cffi](https://github.com/lexiforest/curl_cffi),
[primp](https://github.com/deedy5/primp), and
[httpx](https://github.com/encode/httpx).

## ☕ Support / Donate
If you found this library useful, buy me a coffee!

<a href="https://www.buymeacoffee.com/zied">
    <img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" height="50" width="210" alt="zied" />
</a>

## 📜 License
MIT

## 🚨 Is this library failing on a specific site?
Please [open an issue](https://github.com/zinzied/TLS-Chameleon/issues) with the URL! I need test cases to improve the fingerprinting logic.
