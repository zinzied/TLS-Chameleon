# TLS-Chameleon

<img width="2816" height="1536" alt="TLSChameleom" src="https://github.com/user-attachments/assets/aa4fe457-30c5-49f6-ba7b-1d8604816d81" />

[![PyPI version](https://badge.fury.io/py/tls-chameleon.svg)](https://badge.fury.io/py/tls-chameleon)

Anti-Fingerprinting HTTP client that spoofs real browser TLS fingerprints with a simple, requests-like API.

## 🆕 What's New in v2.0

- **AI-Urllib4 Adaptive Features**:
    - **Domain Memory**: "Learns" which profile works for a specific domain and remembers it.
    - **Adaptive Headers**: Dynamically adjusts header casing and order (e.g., Title-Case for Firefox, lowercase for Chrome) to match the selected profile perfectly.
- **45 Browser Profiles**: Chrome, Firefox, Safari, Edge across Windows 10, Windows 11, macOS, Linux, iOS, Android.
- **Fingerprint Randomization**: Slight variations to avoid pattern detection.
- **HTTP/2 Priority Simulation**: Browser-specific HTTP/2 SETTINGS.
- **Auto-Update System**: Fetch latest JA3 fingerprints from online sources.
- **Enhanced API**: New `TLSSession` class with `profile`, `randomize`, `http2_priority` parameters.

## 🎯 Ideal For

- **Professional Scraping**: Bypass Cloudflare, Akamai, and DataDome on E-commerce/Finance sites.
- **Stealth Automation**: Mimic human behavior to avoid ML-based traffic analysis.
- **Cybersecurity / OSINT**: Extract hidden JWTs, API keys, and metadata from protected portals.
- **Price Intelligence**: Track competitors without being flagged or served "bot-only" prices.

## 🚀 Features

- **TLS Fingerprint Spoofing**: Built-in profiles for Chrome, Firefox, Safari, Edge (uses `curl_cffi` for realistic signatures).
- **Multi-OS Support**: Profiles for Windows 10, Windows 11, macOS, Linux, iOS, and Android.
- **Persistent Sessions**: Proper cookie handling and connection pooling (just like `requests.Session`).
- **Magnet Module 🧲**: One-line data extraction (Emails, Tables, Forms, JSON-LD, Links).
- **Smart Static ⚡**: Automatically fetch page assets (CSS/JS/Images) to mimic real browser traffic.
- **Auto-Form 📝**: Find and submit forms automatically, handling hidden inputs and CSRF tokens.
- **Humanize 🧠**: Built-in delays to mimic human reading/typing speed.
- **Resilience**: Auto-rotation of proxies/profiles upon blocking (403/429/Cloudflare).
- **Ghost Mode (Pro) 👻**: Stealth traffic shaping with randomized timing and payload padding.
- **WAF Shield (Pro) 🛡️**: Automatic detection and adaptation for Cloudflare, Akamai, and DataDome.
- **Header Morphing (Pro) 🧬**: Dynamic casing and ordering to match specific browser signatures perfectly.
- **Deep Extract (Pro) 🕵️**: Find hidden JWTs, API keys, and JS configs in any page.

### What's New in v2.1.0
*   **AI-Urllib4 Adaptive Features:** Domain Memory (auto-profile learning) and Adaptive Headers (dynamic casing/ordering to match profile).
*   **Fingerprint Gallery:** Over 45+ meticulously crafted browser profiles (Chrome 120-130, Firefox 120-124, Safari, Edge) across Windows, macOS, Linux, and Mobile.
*   **HTTP/2 Simulator:** Browser-specific HTTP/2 `SETTINGS`, Window sizes, and Priority frames.
*   **Ghost Mode:** Stealth traffic shaping with randomized delays and payload padding.
*   **WAF Adaptation:** Automatically detects and mitigates Cloudflare, Akamai, and DataDome.
*   **Async Support:** Native `asyncio` support via `tls_chameleon.AsyncSession`.

## 📦 Install

You can install `TLS-Chameleon` directly from PyPI:

```bash
pip install tls-chameleon[curl]
```

> **Note**: The `[curl]` extra is required for TLS fingerprint spoofing.

## ⚡ Quick Start

### 1. Simple Requests (Drop-in)

```python
from tls_chameleon import get

# One-line spoofing
r = get("https://httpbin.org/get", fingerprint="chrome_124")
print(r.json())
```

### 2. Persistent Session (Recommended)

Use `Session` (alias for `TLSChameleon`) to maintain cookies across requests:

```python
from tls_chameleon import Session

with Session(fingerprint="chrome_120") as client:
    # First request sets cookies
    client.get("https://github.com/login")
    
    # Second request sends them back!
    r = client.get("https://github.com/settings")
```

### 3. New v2.1 API with OS-Specific Profiles 🆕

```python
from tls_chameleon import TLSSession

# Select specific browser + OS combination
session = TLSSession(
    profile='chrome_124_linux',     # Linux Chrome 124
    randomize=True,                  # Enable fingerprint randomization
    http2_priority='chrome'          # Match HTTP/2 behavior
)

# Make requests
response = session.get("https://example.com")

# Debug: see what fingerprint is being used
print(session.get_fingerprint_info())
# {
#     'profile_name': 'chrome_124_linux',
#     'user_agent': 'Mozilla/5.0 (X11; Linux x86_64)...',
#     'ja3_hash': 'cd08e31494f9531f560d64c695473da9',
#     'randomized': True,
#     ...
# }
```

## 📚 Available Profiles (v2.1)

### By Browser

| Browser | Versions | OS Support |
|---------|----------|------------|
| **Chrome** | 120, 124, 125 | Windows 10, Windows 11, macOS, Linux, Android |
| **Firefox** | 120, 124 | Windows 10, Windows 11, macOS, Linux |
| **Safari** | iOS 16, iOS 17, macOS 13, macOS 14 | iOS, macOS |
| **Edge** | 120, 124 | Windows 10, Windows 11 |

### Profile Naming Convention

```
{browser}_{version}_{os}
```

Examples:
- `chrome_124_win11` - Chrome 124 on Windows 11
- `chrome_124_linux` - Chrome 124 on Linux
- `firefox_120_macos` - Firefox 120 on macOS
- `safari_ios17` - Safari on iOS 17
- `edge_124_win10` - Edge 124 on Windows 10
- `chrome_android_124` - Chrome 124 on Android

### Convenience Aliases

```python
# Latest versions
'chrome_latest'        # Latest Chrome on Windows 11
'chrome_latest_linux'  # Latest Chrome on Linux
'firefox_latest'       # Latest Firefox
'safari_latest'        # Latest Safari
'edge_latest'          # Latest Edge

# Mobile
'mobile_safari'        # Safari iOS 17
'mobile_chrome'        # Chrome Android 124
```

### List Available Profiles

```python
from tls_chameleon import (
    list_available_profiles,
    get_profiles_by_browser,
    get_profiles_by_os
)

# All 45 profiles
all_profiles = list_available_profiles()
print(f"Total: {len(all_profiles)} profiles")

# Filter by browser
chrome_profiles = get_profiles_by_browser("chrome")
# ['chrome_120_win11', 'chrome_120_win10', 'chrome_120_linux', ...]

# Filter by OS
linux_profiles = get_profiles_by_os("linux")
# ['chrome_120_linux', 'chrome_124_linux', 'firefox_120_linux', ...]
```

## 🎲 Fingerprint Randomization

Enable slight variations to avoid pattern detection:

```python
from tls_chameleon import TLSSession

# Each session gets a slightly different fingerprint
session = TLSSession(
    profile='chrome_124_win11',
    randomize=True  # Enable randomization
)

# Variations include:
# - Minor User-Agent version changes
# - TLS extension order shuffles (where browsers allow)
# - Slight cipher order variations
```

### Manual Randomization

```python
from tls_chameleon import FingerprintRandomizer, get_profile

# Get base profile
profile = get_profile("chrome_124_win11")

# Create randomizer
randomizer = FingerprintRandomizer(profile)

# Generate unique variants
variant1 = randomizer.generate_variant()
variant2 = randomizer.generate_variant()
# Each variant is slightly different but still looks like Chrome 124
```

## 🛠 API Reference

### `TLSSession` / `Session` Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `profile` | `str` | `None` | Profile name (e.g., `'chrome_124_linux'`). **New in v2.0** |
| `fingerprint` | `str` | `'chrome_120'` | Legacy profile name (use `profile` for v2.0 profiles) |
| `randomize` | `bool` | `False` | Enable fingerprint randomization. **New in v2.0** |
| `http2_priority` | `str` | `None` | HTTP/2 priority simulation (`'chrome'`, `'firefox'`, `'safari'`). **New in v2.0** |
| `engine` | `str` | `'curl'` | HTTP engine (`'curl'` or `'httpx'`) |
| `randomize_ciphers` | `bool` | `False` | Shuffle cipher suite order |
| `timeout` | `float` | `30.0` | Request timeout in seconds |
| `headers` | `dict` | `None` | Custom headers to add |
| `proxies` | `dict/str` | `None` | Proxy configuration |
| `rotate_profiles` | `list` | `None` | List of profiles to rotate through on blocks |
| `on_block` | `str` | `'rotate'` | Action on block (`'rotate'`, `'proxy'`, `'both'`, `'none'`) |
| `max_retries` | `int` | `2` | Max retry attempts |
| `site` | `str` | `None` | Site preset (`'cloudflare'`, `'akamai'`) |
| `proxies_pool` | `list` | `None` | Pool of proxies to rotate |
| `http2` | `bool` | `None` | Force HTTP/2 |
| `verify` | `bool` | `True` | Verify SSL certificates |
| `ghost_mode` | `bool` | `False` | Enable stealth traffic shaping |
| `rate_limit` | `float` | `None` | Maximum number of requests per second per domain (e.g., `rate_limit=2.0` means up to 2 req/sec). Default is None. |
| `on_retry` | `callable` | `None` | Callback hook `def on_retry(attempt, response, next_profile):` to log or track rotation events. Default is None. |

### Session Methods

```python
session = TLSSession(profile='chrome_124_win11')

# HTTP Methods
session.get(url, **kwargs)
session.post(url, **kwargs)
session.put(url, **kwargs)
session.delete(url, **kwargs)
session.head(url, **kwargs)
session.patch(url, **kwargs)
session.options(url, **kwargs)

# v2.0 Methods
session.get_fingerprint_info()  # Returns dict with profile details
session.sync_fingerprint(ja3=..., user_agent=...)  # Manually sync fingerprint

# Cookie Management
session.save_cookies("cookies.txt")
session.load_cookies("cookies.txt")

# Session State
session.export_session()  # Returns dict for persistence
session.import_session(state)  # Restore from dict

# Forms
session.submit_form(url, {"username": "x", "password": "y"})

# Human Delays
session.human_delay(reading_speed="normal")  # 'fast', 'normal', 'slow'
```

##  AI-Urllib4 Adaptive Features (New!)

TLS-Chameleon now includes "AI-Urllib4" capabilities to intelligently adapt to target sites.

### Domain Memory
The client automatically "learns" which browser profile works best for a specific domain. If a request succeeds with a specific profile (e.g., `chrome_124_win11`), the client remembers this association. Subsequent requests to the same domain will automatically switch to the known-good profile, regardless of the initial setting.

```python
from tls_chameleon import TLSSession

# First request: Tries with default profile (e.g., Chrome)
# If it fails/rotates and eventually succeeds with Firefox, it remembers "example.com -> Firefox"
with TLSSession() as client:
    client.get("https://example.com")

# Later...
# Automatically switches to Firefox for example.com
with TLSSession() as client:
    client.get("https://example.com")
```

### Adaptive Headers
Headers are no longer static. The client dynamically "morphs" header casing and ordering to match the specific browser profile being used.

- **Chrome/Edge**: Headers are sent in `lowercase` (HTTP/2 standard behavior for Chromium).
- **Firefox/Safari**: Headers utilize `Title-Case` where appropriate and follow specific ordering (e.g., `Host` first vs. `User-Agent` location).

This prevents detection systems from flagging mismatches between the TLS fingerprint (JA3) and the HTTP header structure.

## 🧲 Magnet Extraction

### AI Extraction (New! ✨)
Use **Gemini**, **Claude**, or **OpenAI (ChatGPT/Grok)** to extract data intelligently without regex.

```bash
# Install AI support
pip install tls-chameleon[ai]
```

```python
r = client.get("https://news.ycombinator.com")

# 1. Google Gemini (Default)
print(r.magnet.ask("Summary", provider="gemini"))

# 2. Anthropic Claude
print(r.magnet.ask("Summary", provider="anthropic", model="claude-3-opus-20240229"))

# 3. OpenAI / Grok
# (Set OPENAI_API_KEY or pass api_key=...)
print(r.magnet.ask("Summary", provider="openai", model="gpt-4o"))
```

### Standard Extractors
Don't write regex. Let Magnet do it.

```python
r = client.get("https://example.com/contact")

emails = r.magnet.emails()        # ['support@example.com']
tables = r.magnet.tables()        # [['Row1', 'Val1'], ...]
links  = r.magnet.links()
forms  = r.magnet.get_forms()     # List of parsed forms
json_data = r.magnet.json_ld()    # Schema.org data
```

## 🍪 Cookie Persistence

Save your session to a Netscape-formatted file (compatible with wget/curl) to use later.

```python
# Save
client.save_cookies("cookies.txt")

# Load later
client.load_cookies("cookies.txt")
```

## 🔄 Auto-Update Fingerprints (Optional)

Fetch the latest fingerprints from online sources:

```python
from tls_chameleon import FingerprintUpdater

updater = FingerprintUpdater()

# Check for updates (downloads to ~/.tls_chameleon/cache/)
updated_count = updater.update_gallery()
print(f"Updated {updated_count} profiles")

# Get cache info
print(updater.get_cache_info())
```

## 🆚 Why use this vs curl_cffi?

| Feature | Raw curl_cffi | TLS-Chameleon |
| :--- | :--- | :--- |
| **TLS Spoofing** | You must manually set `impersonate="chrome110"` | **45 profiles** with OS-specific variants |
| **Profile Selection** | Manual | `profile='chrome_124_linux'` |
| **Fingerprint Variation** | None | `randomize=True` avoids pattern detection |
| **Asset Loading** | You just get the HTML. | `mimic_assets=True`: Fetches CSS/JS/Images |
| **Forms** | You must manually parse CSRF tokens | `client.submit_form()`: Auto-handles tokens |
| **Data Extraction** | Use BeautifulSoup manually | **Magnet Module**: emails, tables, json_ld |
| **Blocking Recovery** | Manual retry | Auto-rotation on 403/429 |

## 🔧 Advanced Usage

### Multi-OS Scraping

```python
from tls_chameleon import TLSSession

# Rotate between different OS fingerprints
profiles = [
    'chrome_124_win11',
    'chrome_124_linux',
    'chrome_124_macos',
]

for profile in profiles:
    session = TLSSession(profile=profile, randomize=True)
    response = session.get("https://target-site.com")
    print(f"{profile}: {response.status_code}")
    session.close()
```

### Cloudflare Bypass with Profile Rotation

```python
from tls_chameleon import TLSSession

session = TLSSession(
    profile='chrome_124_win11',
    site='cloudflare',  # Preset for Cloudflare sites
    rotate_profiles=[
        'chrome_124_win11',
        'chrome_120_linux',
        'firefox_124_win11',
    ],
    on_block='rotate',
    max_retries=3
)

response = session.get("https://cloudflare-protected-site.com")
```

### Async Example

TLS-Chameleon fully supports `asyncio` using `AsyncSession`:

```python
import asyncio
from tls_chameleon import AsyncSession

async def main():
    async with AsyncSession(profile="chrome_130_win11", engine="curl") as session:
        resp = await session.get("https://tls.peet.ws/api/all")
        print(resp.json())

asyncio.run(main())
```

### Ghost Mode for Stealth

```python
session = TLSSession(ghost_mode=True)
# Automatic random delays (0.5s - 2.0s) between requests
# Automatic random padding payloads (X-Ghost headers)
response = session.get("https://example.com")
```

### Advanced Recipes

#### 1. Response Caching
For heavy scraping tasks, caching reduces load and saves bandwidth. You can easily wrap `TLS-Chameleon` with `requests-cache`:

```python
import requests_cache
from tls_chameleon import TLSSession

# TLSChameleon subclasses requests.Session, making it compatible
session = TLSSession(profile="chrome_130_win11")
cached_session = requests_cache.CachedSession(
    'scraper_cache',
    backend='sqlite',
    expire_after=3600
)
cached_session.send = session.send  # Bind the chameleon engine
```

#### 2. Playwright Fallback Hook
When curl_cffi cannot solve a complex JavaScript challenge (like Turnstile), you can use the `on_retry` hook to escalate to Playwright:

```python
from tls_chameleon import get
from playwright.sync_api import sync_playwright

def escalate_to_browser(attempt, response, profile):
    if attempt >= 2 and response.status_code in (403, 429):
        print("Falling back to Playwright...")
        with sync_playwright() as p:
            browser = p.chromium.launch()
            page = browser.new_page()
            page.goto(response.url)
            # Extracted cookies can be fed back into the session

get("https://protected.cf", on_retry=escalate_to_browser)
```

#### 3. Connection Pool Sharing
To share connection pools across multiple profiles (saving memory and sockets), pass a pre-initialized `proxies_pool` or share the underlying `curl_cffi` session:

```python
# Share same proxy pool and rotate automatically
pool = ["http://p1", "http://p2", "http://p3"]
s1 = TLSSession(profile="chrome_120", proxies_pool=pool)
s2 = TLSSession(profile="firefox_120", proxies_pool=pool)
```

## 🏗️ Architecture

## 🤝 Contributing
Issues and Pull Requests welcome!

## 🌟 Credits
Special thanks to [curl_cffi](https://github.com/lexiforest/curl_cffi) for the amazing low-level TLS spoofing capabilities that power this library.

## ☕ Support / Donate
If you found this library useful, buy me a coffee!

<a href="https://www.buymeacoffee.com/zied">
    <img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" height="50" width="210" alt="zied" />
</a>

## 📜 License
MIT

## 🚨 Is this library failing on a specific site?
Please [open an issue](https://github.com/zinzied/TLS-Chameleon/issues) with the URL! I need test cases to improve the fingerprinting logic.
