# Benchmark Snapshot — 2026-08-23

Raw machine-readable results: [`BENCHMARK_SNAPSHOT.json`](BENCHMARK_SNAPSHOT.json)
(schema `tls-chameleon.benchmark/2`, produced by `chameleon benchmark --save`).

**Environment:** Windows 10 (AMD64) · Python 3.11.15 · httpx 0.28.1 ·
curl_cffi 0.15.0 · primp 1.3.1 · aiohttp 3.13.3 ·
25 measured requests / 5 warm-ups per client.

These numbers are **machine- and time-specific** — see
[`BENCHMARK_METHODOLOGY.md`](BENCHMARK_METHODOLOGY.md). Only same-run,
same-machine comparisons are meaningful.

## Headlines (this machine, this run)

* Wrapper overhead is real but small: `tls-chameleon(native)` tracked its raw
  primp backend closely (~412 vs ~410 rps on http1).
* On http1, the native wrapper was the fastest spoofing-capable option
  (~412 rps), ahead of both curl-based options (~269 rps).
* TLS handshake estimates: native/primp ~3.6 ms, curl-class ~9–11 ms,
  httpx-class ~13–15 ms.
* Known issue surfaced by the harness: `tls-chameleon(native)` is skipped in
  the TLS scenario when `verify=False` + impersonation combine, due to a primp
  upstream limitation (see NATIVE_BACKEND_RESEARCH.md §7.1).
