# Benchmark Methodology

This document defines exactly what `chameleon benchmark` measures. It exists
so results are interpretable and so nothing is ever invented: every reported
number comes from a live run on the executing machine.

## What is measured

### Scenario `http1` — HTTP/1.1 throughput & latency (plain text)
A local HTTP/1.1 server (`127.0.0.1`, ephemeral port, stdlib `http.server`)
answers small fixed-size responses. Each participating client performs
`W` warm-up requests (discarded) followed by `N` measured requests over a
reused connection pool.

Per client we record wall time, computed requests/second, and per-request
latency distribution (min / mean / median / p95 / max).

### Scenario `tls` — TLS handshake overhead (self-signed, verification off)
A local HTTPS server using an ephemeral RSA-2048 self-signed certificate
(generated at run time with `cryptography`). Certificate verification is
DISABLED for all clients equally.

We report:
* `first_request_ms` — includes TCP connect + TLS handshake + request
* `median_warm_ms` — median of pooled (reused-connection) requests
* `handshake_overhead_ms` — `first_request_ms − median_warm_ms`
  (an estimate; see limitations)

## What participates

| Client | Condition |
|---|---|
| `tls-chameleon(engine=curl)` | only if `curl_cffi` installed |
| `tls-chameleon(engine=httpx)` | always (httpx is a core dependency) |
| `curl_cffi` (raw) | only if installed |
| `httpx` (raw) | always |
| `aiohttp` (raw, asyncio) | only if installed |

Backends that are not installed appear in results as
`"status": "skipped"` with the reason — they are never silently omitted.

## Environment metadata (stored with every result)

`tls-chameleon` version, Python version/platform/machine, timestamps,
installed versions of httpx / curl_cffi / h2 / aiohttp, scenario parameters
(`N`, warm-ups, timeouts). A run without this block is invalid.

## Known limitations (stated up front)

1. **Absolute numbers are machine-specific.** Only relative comparisons
   within a single report (same machine, same run) are meaningful.
2. **Memory figures come from `tracemalloc`**, which sees Python-side
   allocations only. Native allocator memory (libcurl, OpenSSL) is NOT
   visible; treat `memory_peak_mb` as a lower bound.
3. **Handshake overhead is derived**, not packet-observed:
   first-request latency minus warm-request median. Background noise can
   distort it; the harness reports it as an estimate.
4. **Local servers remove network variance** but also mean results say
   nothing about real-internet conditions (RTT, CDN behavior, etc.).
5. **HTTP/2 and HTTP/3 scenarios are not included** because a faithful H2/H3
   local fixture would require a protocol-capable server that itself
   dominates measurements. They will be added only with a defensible
   fixture; until then they are reported as unavailable rather than faked.

## Reproducing

```bash
python -m tls_chameleon benchmark --json > results.json
```
Results embed their parameters; re-running on different hardware and
comparing absolute values across machines is explicitly unsupported.
