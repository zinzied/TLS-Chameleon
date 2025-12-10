# TLS-Chameleon

![TLS-Chameleon](TLSChameleom.png)

Anti-Fingerprinting HTTP client that spoofs real browser TLS fingerprints with a simple, requests-like API.

## Features

- One-liner TLS fingerprint spoofing via built-in browser profiles
- Prefers `curl_cffi` for realistic JA3; falls back to `httpx`
- Optional cipher randomization per request
- Smart block detection with profile/proxy rotation and backoff
- Site presets for Cloudflare/Akamai

## Install

```bash
pip install tls-chameleon
# Optional: install curl_cffi for true browser impersonation
pip install tls-chameleon[curl]
```

Alternatively, from source:

```bash
pip install -e .
```

Requirements:

- Python >= 3.8
- `httpx` (required)
- `curl_cffi` (optional, recommended)

## Quick Start

```python
from tls_chameleon import get
r = get("https://httpbin.org/get", fingerprint="chrome_124")
print(r.status_code)
print(r.text[:200])
```

Session wrapper:

```python
from tls_chameleon import TLSChameleon
client = TLSChameleon(
    fingerprint="chrome_120",
    site="cloudflare",
    on_block="both",
    rotate_profiles=["chrome_124","chrome_120","mobile_safari_17"],
    randomize_ciphers=True,
    http2=True,
)
r = client.get("https://example.com")
print(r.status_code)
```

## Examples

Run the included examples:

```bash
python examples/run_example.py https://httpbin.org/get --fingerprint chrome_124
python examples/cloudflare_rotate.py --max-retries 3
```

## API

- `TLSChameleon(fingerprint="chrome_124", site=None, on_block="rotate", rotate_profiles=None, proxies_pool=None, randomize_ciphers=False, max_retries=2, http2=None, header_order=None)`
- Methods: `get`, `post`, `put`, `delete`, `head`, `patch`, `request`
- Top-level helpers: `get`, `post`, `put`, `delete`, `head`, `patch`, `request`

## Profiles

Built-in fingerprints in `tls_chameleon/profiles.py`:

- `chrome_120`, `chrome_124`, `firefox_120`, `mobile_safari_17`, `ios_safari_17`

## Notes

- For best results on protected sites, install `curl_cffi` and use Chrome/Safari profiles
- Respect site terms and laws; this library is for legitimate automation and research

## Version

`1.0.0`

## Services and Use Cases

- Developer automation
  - Realistic browser TLS impersonation for scraping and testing flows
  - Automatic block detection with profile and proxy rotation
  - Site presets (Cloudflare/Akamai) for sensible defaults and HTTP/2 hints
  - Header ordering and cipher randomization to study impact on acceptance
  - Drop-in `requests`-style API for quick migration
- Diagnostics
  - Surface engine, profile, and effective `User-Agent` for reproducibility
  - Optional logs on retries, profile/proxy rotation, and status transitions
- Pentesting and research
  - Evaluate bot mitigation thresholds against varied TLS fingerprints
  - JA3/TLS parameter fuzzing via profile and cipher adjustments
  - WAF rule sensitivity exploration with header order and HTTP/2 toggles
  - Proxy pool behavior analysis and session consistency tests
