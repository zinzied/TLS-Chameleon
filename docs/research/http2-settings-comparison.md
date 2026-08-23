# HTTP/2 SETTINGS Comparison Across Profile Families

Source: built-in profile gallery (`fingerprint_gallery.py`), compared with
`tls_chameleon.fingerprint.diff_fingerprints` / `HTTP2Fingerprint`.

## Chrome family (e.g. `chrome_120_win11`)

| SETTINGS | Value |
|---|---|
| HEADER_TABLE_SIZE | 65536 |
| ENABLE_PUSH | 0 |
| MAX_CONCURRENT_STREAMS | 1000 |
| INITIAL_WINDOW_SIZE | 6291456 |
| MAX_FRAME_SIZE | 16384 |
| MAX_HEADER_LIST_SIZE | 262144 |

## Firefox family (e.g. `firefox_120_win11`)

Same table shape, but with the well-known Firefox divergences:

* `INITIAL_WINDOW_SIZE`: **131072** (Chrome: 6291456 — a 48× difference)
* No `MAX_FRAME_SIZE` / `MAX_HEADER_LIST_SIZE` entries advertised the same way

## Analysis

1. **Window sizing is the strongest single H2 discriminator** between the two
   families: Chrome's multi-megabyte initial window vs Firefox's 128 KiB is
   observable in the first frames and cannot be hidden by header mimicry.
   Any stack claiming cross-family fidelity must control flow-control windows,
   which is why honest capability reporting matters (`capabilities.http2`
   says nothing about *window control*; the native backend's
   WINDOW_UPDATE tuning is tracked in its upstream release notes).
2. **ENABLE_PUSH=0 is universal** across modern profiles — it carries no
   family signal.
3. The gallery's H2 layer is *documentation-level*: backends differ in how
   much of it they can enforce on the wire (curl-impersonate applies H2
   fingerprints natively; httpx cannot). `chameleon doctor --echo-endpoint …`
   reports observed-vs-profile divergence per field instead of guessing.

## Reproduce

```python
from tls_chameleon.fingerprint import FingerprintRegistry, diff_fingerprints
reg = FingerprintRegistry()
print(diff_fingerprints(reg.get("chrome_120_win11"),
                        reg.get("firefox_120_win11")).to_text())
```
