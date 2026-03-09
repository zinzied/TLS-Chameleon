# CHANGELOG

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
