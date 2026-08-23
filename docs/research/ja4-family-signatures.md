# Observed JA4 Family Signatures (native backend, 2026-08-23)

Captures performed with `tls_chameleon.fingerprint.capture` against
`https://tls.peet.ws/api/clean`, through the **native** (primp/rustls)
backend on Windows 10 x64, TLS-Chameleon 3.0.1.

| Profile family | Impersonation target | Observed JA4 | JA3 hash (wire) |
|---|---|---|---|
| chrome_130_win11 | `chrome_144` (nearest ≤ hint mapping) | `t13d1516h2_8daaf6152771_d8a2da3f94cd` | `091b5b7b79dabfb28d2e6d498acabcfd` |
| firefox_120_win11 | `firefox_140` | `t13d1717h2_5b57614c22b0_3cbfd9057e0d` | `6f7889b9fb1a62a9577e685c1fcfa919` |

## Observations

1. **Family separation is structural, not cosmetic.** The Chrome-shaped
   ClientHello advertises 51 extensions (`...h2_8daaf…` cipher segment shared
   with Chromium-family captures across backends), while the Firefox shape
   shows 71 extensions (`t13d1717h2_5b57614c22b0_…`) — matching real
   Firefox's larger extension surface.
2. **JA4's middle segment (cipher hash) is family-stable**: both Chrome
   captures across *different backends* (curl and native) share
   `_8daaf6152771_`, while the extension-hash tail differs per backend.
   Practical takeaway: JA4's first two segments are good family detectors;
   the third segment is a stack detector.
3. **Version-mapping caveat.** The native backend maps hint `chrome130` to
   its nearest available target (`chrome_144`); observed JA4 therefore
   reflects Chrome 144's ClientHello, not 130's. Profiles store the
   historical value; `chameleon doctor --echo-endpoint …` surfaces exactly
   this class of divergence.

## Reproduce

```bash
python - <<'PY'
from tls_chameleon import TLSChameleon
from tls_chameleon.fingerprint import capture
c = TLSChameleon(profile="chrome_130_win11", engine="native", timeout=45)
print(capture(url="https://tls.peet.ws/api/clean",
              session=c.session, timeout=40).to_dict())
PY
```

Numbers above are point-in-time observations of external echo services;
re-run to confirm current behavior before relying on them.
