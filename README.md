# TLS-Chameleon

<img width="2816" height="1536" alt="TLSChameleom" src="https://github.com/user-attachments/assets/aa4fe457-30c5-49f6-ba7b-1d8604816d81" />


Anti-Fingerprinting HTTP client that spoofs real browser TLS fingerprints with a simple, requests-like API.

## 🚀 Features

- **TLS Fingerprint Spoofing**: Built-in profiles for Chrome, Firefox, Safari (uses `curl_cffi` for realistic signatures).
- **Persistent Sessions**: Proper cookie handling and connection pooling (just like `requests.Session`).
- **Magnet Module 🧲**: One-line data extraction (Emails, Tables, Forms, JSON-LD, Links).
- **Smart Static ⚡**: Automatically fetch page assets (CSS/JS/Images) to mimic real browser traffic.
- **Auto-Form 📝**: Find and submit forms automatically, handling hidden inputs and CSRF tokens.
- **Humanize 🧠**: Built-in delays to mimic human reading/typing speed.
- **Resilience**: Auto-rotation of proxies/profiles upon blocking (403/429/Cloudflare).

## 🆚 Why use this vs curl_cffi?

| Feature | Raw curl_cffi | TLS-Chameleon |
| :--- | :--- | :--- |
| **TLS Spoofing** | You must manually set `impersonate="chrome110"` | **Auto-Rotation**: It likely has logic to rotate these so you don't get stuck on one. |
| **Asset Loading** | You just get the HTML. | `mimic_assets=True`: It parses the HTML and fetches CSS/JS/Images to look like a "real" browser visit (very important for some anti-bots). |
| **Forms** | You must manually parse CSRF tokens and hidden fields. | `client.submit_form()`: It finds the form, keeps the hidden tokens, and submits for you. |
| **Data Extraction** | You need to use BeautifulSoup manually. | **Magnet Module**: It has built-in extractors for emails, tables, and json_ld. |

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

### 3. Magnet Extraction 🧲

Don't write regex. Let Magnet do it.

```python
r = client.get("https://example.com/contact")

emails = r.magnet.emails()        # ['support@example.com']
tables = r.magnet.tables()        # [['Row1', 'Val1'], ...]
links  = r.magnet.links()
forms  = r.magnet.get_forms()     # List of parsed forms
json_data = r.magnet.json_ld()    # Schema.org data
```

### 4. Smart Features

**Mimic Real Browser Traffic** (Fetches static assets in background):
```python
client.get("https://example.com", mimic_assets=True)
```

**Auto-Submit Forms** (Handles hidden fields automatically):
```python
# Finds <form>, fills 'user'/'pass', keeps hidden tokens, POSTs to action.
client.submit_form("https://site.com/login", {
    "username": "myuser",
    "password": "mypassword"
})
```

**Humanize Delays**:
```python
client.human_delay(reading_speed="fast") # Sleeps randomly based on speed
```

## 🛠 API Reference

### `Session(fingerprint=..., site=..., ...)`
- `fingerprint`: "chrome_120", "firefox_120", "mobile_safari_17".
- `site`: "cloudflare" or "akamai" (presets for retries/headers).
- `randomize_ciphers`: True/False (shuffles cipher suite order).
- `proxies`: `http://user:pass@host:port`

### Response Object
The response object wraps `curl_cffi.Response` or `httpx.Response` but adds:
- `.magnet`: Access extraction tools.
- `.json_fuzzy()`: Parse broken/JSONP responses.

## 🤝 Contributing
Issues and Pull Requests welcome!

## 📜 License
MIT

## 🚨 Is this library failing on a specific site?
Please [open an issue](https://github.com/zinzied/TLS-Chameleon/issues) with the URL! I need test cases to improve the fingerprinting logic.
