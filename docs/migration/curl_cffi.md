# Migrating from curl_cffi to TLS-Chameleon

TLS-Chameleon v3 uses curl_cffi as an *optional, replaceable backend*. If you
already use curl_cffi, adopting TLS-Chameleon adds fingerprint profiles,
adaptive behavior, diagnostics, and research tooling on top of a stable API —
without exposing curl_cffi types.

## Installation

```bash
pip install tls-chameleon[curl]      # curl-impersonate backend (recommended)
pip install tls-chameleon[native]    # primp/rustls backend, no curl needed
pip install tls-chameleon[all]       # both
```

The base install (`pip install tls-chameleon`) works without either extra via
the httpx fallback — honestly degraded: standard OpenSSL TLS, **no JA3
spoofing**. The active backend is always inspectable:

```python
client.engine                        # "curl" | "native" | "httpx"
client.capabilities.tls_fingerprint_spoofing
```

## API mapping

| curl_cffi | TLS-Chameleon |
|---|---|
| `from curl_cffi import requests` | `import tls_chameleon` |
| `requests.Session(impersonate="chrome124")` | `TLSSession(profile="chrome_124_win11")` or `Session(engine="curl")` |
| `session.get(url)` / `.post(url, json=...)` | identical call shapes; returns `ChameleonResponse` |
| `resp.status_code / .text / .content / .headers / .cookies` | same attributes (proxied) |
| `AsyncSession` + `await session.get(url)` | `from tls_chameleon import AsyncSession`; same await shape |
| `impersonate=` per request | set once via `profile=`; rotate with `rotate_profiles=[...]` |
| `curl_options={...}` | handled internally by the transport layer |
| proxies dict `{"http": ..., "https": ...}` | same shape on `proxies=` |

## What you gain

* 48+ versioned browser profiles with header order/case and HTTP/2 SETTINGS
* Deterministic randomization (`random_seed=`), block detection with
  backoff/retry/rotation, per-domain adaptive profile memory
* Diagnostics: `response.trace`, `inspect_url()`, `doctor()`, live
  fingerprint `capture()` — all redacted, all JSON-exportable
* CLI: `chameleon get/inspect/doctor/capture/diff/fingerprint --json`

## What does NOT change

* Certificate verification stays ON by default (`verify=True`)
* No curl_cffi classes ever appear in the public API
* Removing curl_cffi from your environment never breaks imports — the
  factory falls back (`curl → native → httpx`) with a warning

## Backend selection

```python
Session(engine=None)     # auto: curl if installed, else native, else httpx
Session(engine="curl")   # force (warns+falls back when missing)
Session(engine="native") # primp/rustls impersonation stack
Session(engine="httpx")  # honest baseline, no JA3 spoofing
```
