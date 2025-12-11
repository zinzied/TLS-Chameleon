# TLS-Chameleon

<img width="2816" height="1536" alt="TLSChameleom" src="https://github.com/user-attachments/assets/aa4fe457-30c5-49f6-ba7b-1d8604816d81" />

[![PyPI version](https://badge.fury.io/py/tls-chameleon.svg)](https://badge.fury.io/py/tls-chameleon)


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

#### AI Extraction (New! ✨)
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

#### Standard Extractors
Don't write regex. Let Magnet do it.

```python
r = client.get("https://example.com/contact")

emails = r.magnet.emails()        # ['support@example.com']
tables = r.magnet.tables()        # [['Row1', 'Val1'], ...]
links  = r.magnet.links()
forms  = r.magnet.get_forms()     # List of parsed forms
json_data = r.magnet.json_ld()    # Schema.org data
```

### 4. Cookie Persistence 🍪
Save your session to a Netscape-formatted file (compatible with wget/curl) to use later.

```python
# Save
client.save_cookies("cookies.txt")

# Load later
client.load_cookies("cookies.txt")
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
