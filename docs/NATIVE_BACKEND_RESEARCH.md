# Native Backend Research

> Date: 2026-08-23 · Status: **Research complete — no implementation performed**
> (Phase 7 gate: implement nothing before this document exists.)
>
> Definition adopted from the project specification: "native" does NOT mean
> writing our own TLS. It means TLS-Chameleon must not require `curl_cffi`
> as its networking abstraction. We prefer mature underlying libraries over
> cryptographic self-implementation, always.

---

## 1. Goals

Provide a second, independent transport so that:

1. `pip install tls-chameleon` works with real TLS-fingerprint capability
   even without `curl_cffi`;
2. the pluggable `Transport` interface is proven against a third backend;
3. HTTP/3 becomes honestly available where a backend truly supports it.

## 2. Evaluation criteria (from the project specification)

| Criterion | Weight |
|---|---|
| TLS fingerprint configurability (ClientHello-level) | Critical |
| HTTP/1.1 + HTTP/2 correctness | Critical |
| HTTP/3 / QUIC | High (capability-honest) |
| Performance | High |
| Platform support (wheels, not "build it yourself") | High |
| Maintenance activity & bus factor | High |
| License | Medium-High |
| Security posture (patch cadence, supply chain) | High |
| Async support | Medium |
| Fit with our `Transport` duck-typed session contract | Medium |

## 3. Candidates evaluated

### 3.1 primp (Rust → PyO3 binding) — **recommended primary candidate**

* Stack: forked-Rust crates maintained upstream — `primp-reqwest`
  (reqwest fork), `primp-hyper`, `primp-h2`,
  **`primp-rustls` (rustls fork with JA3/JA4 fingerprinting)**.
  Pure-Rust TLS: no BoringSSL/OpenSSL C toolchain in the build path.
* Impersonation profiles (verified 2026-05 releases): Chrome 144–148,
  Firefox 140–148, Safari 26.x, Edge 144–148, Opera 126–131, per-OS
  selection, header ordering, HTTP/2 SETTINGS/window control,
  WINDOW_UPDATE tuning, DNS-over-HTTPS resolver options.
* Packaging: prebuilt wheels — linux glibc/musl amd64+aarch64,
  Windows amd64, macOS amd64/arm64. MIT license.
* Activity: crate updated 2026-05; release notes show steady feature work
  through 2026 (cached emulators, brand-list fixes, WASM gating).
* Risks: effectively single-maintainer; API still moving (pin versions);
  cookie-store semantics differ from requests-like sessions; sync-first
  Python API — async parity must be verified during implementation.

### 3.2 tls-client / tls-client-python (Go → CFFI shared library)

* Stack: Go `bogdanfinn/tls-client` on a utls fork — utls remains the
  reference implementation for ClientHello mimicry. v1.15.1 released
  2026-06; 9 platform binaries bundled; HTTP/3 via quic-go fork;
  WebSocket exposure in progress.
* Strengths: deepest profile catalog; very active; battle-tested at scale.
* Risks: ships ~11–25 MB Go shared libraries per platform; Go runtime
  memory footprint per process; upstream Go repo is BSD-4-Clause (the
  old 4-clause license with advertising clause — legal review required
  before we *bundle*; runtime dependency via pip package may be
  acceptable, confirm with counsel); binding quality varies across the
  several competing Python wrapper packages (the CFFI one reviewed here
  is the most serious).

### 3.3 curl_cffi (current default backend) — re-evaluated

* v0.16.x (2026): curl-impersonate 2.1, Chrome 150-class fingerprints,
  **HTTP/3 fingerprints**, UDP-SOCKS5 proxy support for H3, header-order
  option, static builds, free-threaded builds, Android target.
  Actively maintained.
* New consideration: the fingerprint database can now auto-update via an
  external service whose extended tiers are commercial. Core presets
  remain open. This does not block our use, but reinforces the strategic
  value of a second, independently-licensed fingerprint source.
* Verdict: keep as preferred backend whenever installed. It is not the
  architecture's dependency anymore — that was Phase 1's purpose.

### 3.4 aiohttp (raw comparison target)

* Excellent raw performance (fastest in our local harness), but no
  ClientHello-level fingerprint configurability (it uses stdlib ssl /
  OpenSSL defaults). Remains a benchmark participant only.

### 3.5 aioquic (pure-Python QUIC/H3)

* Implements QUIC and its own TLS 1.3 handshake atop `cryptography` —
  the only credible pure-Python route to genuine HTTP/3 with observable,
  tunable QUIC parameters.
* Does not provide HTTP/1.1 or HTTP/2, so it can serve exclusively as a
  future **H3-scoped transport** behind capability flags
  (`capabilities.http3=True`, everything else false), never as a general
  backend.
* Verdict: defer to a dedicated `[http3]` transport after Stages A/B.

### 3.6 Rejected options

| Option | Reason for rejection |
|---|---|
| pycurl (libcurl binding) | Same libcurl engine as curl_cffi but *without* the impersonation patches: no ClientHello control worth speaking of. Adds a dependency without adding capability. |
| pyOpenSSL / GnuTLS / mbedTLS bindings | No practical access to ClientHello extension order, GREASE, ALPN framing details at the fidelity browsers require. |
| Hand-rolled TLS via ctypes/cffi on OpenSSL/BoringSSL | Violates the explicit project rule ("do not implement crypto primitives yourself"); enormous security/maintenance surface; duplicates what utls/curl-impersonate/primp-rustls already solved. |
| Custom PyO3/Rust extension built by us | primp demonstrates the pattern but maintaining our own forked hyper/h2/rustls stack is out of scope for this project's mission. Adopt, don't rebuild. |
| Subprocess/sidecar bridging to Go tools | IPC overhead, lifecycle complexity, poor library ergonomics. |

## 4. Comparison matrix

Scores are relative (0–5) within this evaluation, grounded in Section 3.

| Criterion | primp | tls-client (Go) | curl_cffi (today) | aioquic | stdlib-httpx (current fallback) |
|---|---|---|---|---|---|
| TLS fingerprint configurability | 4 | 5 | 5 | 3 (QUIC-TLS only) | 1 |
| HTTP/1.1 + HTTP/2 | 5 | 4 | 5 | 0 (H3 only) | 5 |
| HTTP/3 / QUIC | 3 (feature present, immature) | 3 | 4 (H3 fingerprints) | 5 | 0 |
| Performance (local harness context) | expected ≥ curl-class; verify | good; FFI overhead unknown | proven | n/a for TCP paths | proven |
| Wheels / platforms | 5 targets | 9 targets (big binaries) | widest incl. Android/free-threading | pure-python | pure-python |
| Maintenance | active 2026, 1 maintainer | active 2026, 1 core maintainer | very active | active | very active |
| License | MIT | BSD-4-Clause (review) | MIT | BSD-3-Clause | BSD |
| Async | verify in Phase 8 | yes | yes | asyncio-native | yes |

## 5. Recommendation

**Adopt primp as the first "native" backend, behind our existing Transport
interface, as an optional extra. Nothing about the public API changes.**

Staged plan:

* **Stage A (Phase 8 target)** — `PrimpTransport`
  (`transport/primp_backend.py`, the only module importing `primp`),
  extra name `[native]`: `pip install tls-chameleon[native]`.
  Factory preference becomes: `curl` → `primp` ("native") → `httpx`.
  Capabilities reported honestly: `tls_fingerprint_spoofing=True`,
  `custom_cipher_order=False` (profile-driven instead),
  `http2=True`, `http3` only if verified at runtime.
* **Stage B** — optional `TlsClientTransport` (`[utls]`) for utls-specific
  profile coverage, contingent on the BSD-4 licensing review and a wheels/
  size budget decision.
* **Stage C** — `AioquicTransport` scoped strictly to HTTP/3 under the
  existing `[http3]` extra, gated by capabilities and clearly marked
  experimental.

curl_cffi remains supported indefinitely; the goal is optionality, not
removal (spec §50).

## 6. Acceptance criteria for Phase 8 implementation (Stage A)

1. `PrimpTransport` passes the full existing test matrix, including the
   backend-isolation scan (allow-list gains exactly one new file).
2. Live verification via our own `capture()`/doctor tooling:
   observed JA3/JA4 must match the mapped profile for at least one Chrome
   and one Firefox profile on Windows/Linux/macOS CI images.
3. Wheel coverage check runs in CI for linux-amd64, linux-arm64,
   windows-amd64, macos-arm64; other platforms degrade to skipped-with-
   reason rows in the same style as the benchmark harness.
4. Sync + async sessions satisfy the documented duck-typed contract;
   cookies round-trip through save/load unchanged.
5. Benchmark entries added for the native backend; regression tolerance
   defined as ≤ 25 % median-latency delta versus raw curl_cffi on the
   local http1 scenario (initial gate, revisit with data).
6. Version pinning: `primp>=X,<Y` recorded with rationale; upgrade policy
   documented in the transport module docstring.

## 7. Open questions

1. primp async API shape and stability (verify before Stage A coding).
2. Cookie-jar interoperability details (primp cookie store ↔ our
   export/import state format).
3. Whether primp's rustls fork will track upstream rustls CVEs fast
   enough for our security bar; define a monitoring step.
4. Legal confirmation that runtime-dependency (not bundling) of
   BSD-4-Clause tls-client binaries is acceptable, should Stage B proceed.

### 7.1 Discovered during Stage A implementation

5. **primp 1.3.x ignores `verify=False` when an impersonation profile is
   active** (the impersonation path rebuilds the rustls client config with
   default verification). Verified experimentally 2026-08-23. Our policy:
   keep impersonation, keep verification enforced, warn loudly once per
   process. Upstream report recommended before Phase 10 release.
6. primp cookies are URL-scoped (`get_cookies(url)` raises when empty);
   our transport shim tracks visited URLs to present a merged view.
7. `primp.Client` exposes no `close()`; resources free via Rust Drop —
   adapter provides no-op closers for contract parity.

## 8. Sources consulted (2026-08-23)

* github.com/deedy5/primp (+ releases, crates.io/primp, docs.rs/primp,
  pypi.org/project/primp) — profiles up to Chrome 147/148, custom
  primp-rustls stack, wheel matrix, MIT license.
* github.com/lexiforest/curl_cffi (+ releases v0.13–v0.16.1) —
  curl-impersonate 2.1/Chrome 150, H3 fingerprints, header-order option,
  impersonate.pro fingerprint-update service tiers.
* github.com/bogdanfinn/tls-client (+ releases v1.15.x) and
  pypi.org/project/tls-client-python — CFFI binding, 9 platform binaries,
  quic-go based H3, BSD-4-Clause upstream license.
