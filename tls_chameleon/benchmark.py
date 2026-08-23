"""Reproducible benchmark harness.

Every number produced here comes from a live local-server run on the
executing machine; see docs/BENCHMARK_METHODOLOGY.md for the exact
methodology and its stated limitations. Results are never fabricated:
backends that cannot participate are reported as skipped.
"""

import asyncio
import datetime
import json
import platform
import ssl
import statistics
import sys
import tempfile
import threading
import time
import tracemalloc
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

import httpx

from . import __version__

__all__ = ["run_benchmark", "BenchmarkReport"]


# ---------------------------------------------------------------------------
# Local fixtures
# ---------------------------------------------------------------------------

_BODY = b"x" * 512


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):  # silence
        pass

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(_BODY)))
        self.end_headers()
        self.wfile.write(_BODY)


def _start_server(tls_context: Optional[ssl.SSLContext] = None):
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    if tls_context is not None:
        server.socket = tls_context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    scheme = "https" if tls_context else "http"
    url = f"{scheme}://127.0.0.1:{server.server_address[1]}/bench"
    return server, url


def _stop_server(server) -> None:
    """Stop a fixture server without ever hanging the process.

    ``socketserver.BaseServer.shutdown()`` waits on an event set by the
    serve_forever loop; on Windows this has been observed to deadlock
    intermittently when keep-alive handler threads are still parked.
    Run shutdown under a watchdog and always release the port.
    """
    watchdog = threading.Thread(target=server.shutdown, daemon=True)
    watchdog.start()
    watchdog.join(timeout=3.0)
    try:
        server.server_close()
    except Exception:  # pragma: no cover - best effort
        pass


def _make_tls_context() -> ssl.SSLContext:
    import datetime as _dt
    import ipaddress

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    now = _dt.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - _dt.timedelta(days=1))
        .not_valid_after(now + _dt.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    with tempfile.TemporaryDirectory() as tmp:
        cert_path = Path(tmp) / "cert.pem"
        key_path = Path(tmp) / "key.pem"
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        )
        context.load_cert_chain(str(cert_path), str(key_path))
    return context


# ---------------------------------------------------------------------------
# Measurement primitives
# ---------------------------------------------------------------------------

def _time_batch(make_request: Callable[[], Any], warmup: int,
                requests: int) -> Dict[str, Any]:
    for _ in range(warmup):
        make_request()
    latencies: List[float] = []
    tracemalloc.start()
    baseline = tracemalloc.get_traced_memory()[0]
    started = time.perf_counter()
    try:
        for _ in range(requests):
            t0 = time.perf_counter()
            make_request()
            latencies.append((time.perf_counter() - t0) * 1000.0)
        wall = time.perf_counter() - started
    finally:
        peak = tracemalloc.get_traced_memory()[1]
        tracemalloc.stop()

    def _pct(p: float) -> float:
        ordered = sorted(latencies)
        idx = min(len(ordered) - 1, int(round(p * (len(ordered) - 1))))
        return ordered[idx]

    return {
        "requests": requests,
        "wall_seconds": round(wall, 4),
        "rps": round(requests / wall, 1) if wall > 0 else 0.0,
        "latency_ms": {
            "min": round(min(latencies), 3),
            "mean": round(statistics.fmean(latencies), 3),
            "median": round(statistics.median(latencies), 3),
            "p95": round(_pct(0.95), 3),
            "max": round(max(latencies), 3),
        },
        "memory_python_peak_delta_mb": round(
            max(0.0, (peak - baseline) / (1024 * 1024)), 3
        ),
    }


def _first_vs_warm(session: Any, url: str, timeout: float) -> Dict[str, float]:
    """First request (cold pool) vs median pooled request, same session."""
    t0 = time.perf_counter()
    session.request("GET", url, timeout=timeout)
    first_ms = (time.perf_counter() - t0) * 1000.0
    warm = []
    for _ in range(5):
        t0 = time.perf_counter()
        session.request("GET", url, timeout=timeout)
        warm.append((time.perf_counter() - t0) * 1000.0)
    return {
        "first_request_ms": round(first_ms, 3),
        "median_warm_ms": round(statistics.median(warm), 3),
        "handshake_overhead_ms_est": round(first_ms - statistics.median(warm), 3),
    }


def _aio_batch(url: str, timeout: float, warmup: int, requests: int):
    async def _run():
        import aiohttp

        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=timeout)
        ) as session:
            async def one():
                t0 = time.perf_counter()
                async with session.get(url) as resp:
                    await resp.read()
                return (time.perf_counter() - t0) * 1000.0

            for _ in range(warmup):
                await one()
            latencies = [await one() for _ in range(requests)]
        return latencies

    return asyncio.run(_run())


def _summarize_latencies(name: str, latencies: List[float], requests: int,
                         wall: float, memory_mb=None) -> Dict[str, Any]:
    ordered = sorted(latencies)
    entry = {
        "client": name,
        "status": "ok",
        "requests": requests,
        "wall_seconds": round(wall, 4),
        "rps": round(requests / wall, 1) if wall > 0 else 0.0,
        "latency_ms": {
            "min": round(min(latencies), 3),
            "mean": round(statistics.fmean(latencies), 3),
            "median": round(statistics.median(latencies), 3),
            "p95": round(ordered[int(round(0.95 * (len(ordered) - 1)))], 3),
            "max": round(max(latencies), 3),
        },
        "memory_python_peak_delta_mb": memory_mb,
    }
    return entry


# ---------------------------------------------------------------------------
# Client registry
# ---------------------------------------------------------------------------

def _available_clients(include_aiohttp: bool) -> List[Dict[str, Any]]:
    from .client import TLSChameleon

    clients: List[Dict[str, Any]] = []

    class _CloseGuard:
        """Adds a no-op close() for clients without one (e.g. primp.Client)."""

        def __init__(self, inner: Any) -> None:
            self._inner = inner

        def __getattr__(self, item: str) -> Any:
            return getattr(self._inner, item)

        def request(self, method: str, url: str, **kwargs: Any) -> Any:
            return self._inner.request(method, url, **kwargs)

        def close(self) -> None:
            pass  # primp frees via Rust Drop

    def add_curl(name: str, factory: Callable[[], Any]) -> None:
        try:
            import curl_cffi.requests  # noqa: F401
        except Exception:
            clients.append({"client": name, "status": "skipped",
                            "reason": "curl_cffi not installed"})
            return
        clients.append({"client": name, "status": "ok", "factory": factory})


    def add(name: str, factory: Callable[[], Any]) -> None:
        clients.append({"client": name, "status": "ok", "factory": factory})

    add_curl("tls-chameleon(curl)",
             lambda: TLSChameleon(engine="curl", verify=False, timeout=10))
    add("tls-chameleon(httpx)",
        lambda: TLSChameleon(engine="httpx", verify=False, timeout=10))
    add_curl("curl_cffi(raw)",
             lambda: __import__("curl_cffi").requests.Session(
                 verify=False, timeout=10))
    def add_native(name: str, factory: Callable[[], Any]) -> None:
        try:
            import primp  # noqa: F401
        except Exception:
            clients.append({"client": name, "status": "skipped",
                            "reason": "primp not installed"})
            return
        clients.append({"client": name, "status": "ok", "factory": factory})

    add("httpx(raw)", lambda: httpx.Client(verify=False, timeout=10))

    add_native("tls-chameleon(native)",
               lambda: TLSChameleon(engine="native", verify=False, timeout=10))
    add_native("primp(raw)",
               lambda: _CloseGuard(__import__("primp").Client(verify=False,
                                                               timeout=10)))

    if include_aiohttp:
        try:
            import aiohttp  # noqa: F401

            clients.append({"client": "aiohttp(raw)", "status": "ok_async",
                            "factory": None})
        except Exception:
            clients.append({"client": "aiohttp(raw)", "status": "skipped",
                            "reason": "aiohttp not installed"})
    return clients


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

@dataclass
class BenchmarkReport:
    parameters: Dict[str, Any] = field(default_factory=dict)
    environment: Dict[str, Any] = field(default_factory=dict)
    scenarios: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": "tls-chameleon.benchmark/2",
            "status": "ok",
            "environment": self.environment,
            "parameters": self.parameters,
            "scenarios": self.scenarios,
        }

    def to_text(self) -> str:
        lines = ["TLS-Chameleon Benchmark", ""]
        for scenario, entries in self.scenarios.items():
            lines.append(f"[{scenario}]")
            for entry in entries:
                name = entry["client"]
                if entry["status"] == "skipped":
                    lines.append(f"  {name:<24} SKIPPED ({entry['reason']})")
                    continue
                lat = entry["latency_ms"]
                extra = ""
                if "handshake_overhead_ms_est" in entry:
                    extra = f" handshake~{entry['handshake_overhead_ms_est']}ms"
                lines.append(
                    f"  {name:<24} {entry['rps']:>8} rps "
                    f"median={lat['median']}ms p95={lat['p95']}ms{extra}"
                )
            lines.append("")
        lines.append("Methodology: docs/BENCHMARK_METHODOLOGY.md "
                     "(absolute numbers are machine-specific)")
        return "\n".join(lines)


def _environment() -> Dict[str, Any]:
    def _ver(module_name: str):
        try:
            module = __import__(module_name)
            return getattr(module, "__version__", "unknown")
        except Exception:
            return None

    return {
        "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(
            timespec="seconds"
        ),
        "tls_chameleon": __version__,
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "machine": platform.machine(),
        "httpx": _ver("httpx"),
        "curl_cffi": _ver("curl_cffi"),
        "aiohttp": _ver("aiohttp"),
    }


def run_benchmark(
    scenarios: Optional[List[str]] = None,
    *,
    requests: int = 30,
    warmup: int = 5,
    timeout: float = 10.0,
    include_aiohttp: bool = True,
) -> BenchmarkReport:
    """Execute the benchmark scenarios and return a full report."""
    scenarios = list(scenarios or ["http1", "tls"])
    report = BenchmarkReport(
        parameters={
            "requests_per_client": requests,
            "warmup_requests": warmup,
            "timeout_seconds": timeout,
            "scenarios": list(scenarios),
        },
        environment=_environment(),
    )

    clients = _available_clients(include_aiohttp=include_aiohttp)

    if "http1" in scenarios:
        server, url = _start_server()
        try:
            entries: List[Dict[str, Any]] = []
            for client in clients:
                try:
                    entries.append(_measure_client(
                        client, url, requests, warmup, timeout
                    ))
                except Exception as exc:
                    entries.append({"client": client["client"],
                                    "status": "skipped",
                                    "reason": f"{type(exc).__name__}: {exc}"})
            report.scenarios["http1"] = entries
        finally:
            _stop_server(server)

    if "tls" in scenarios:
        context = _make_tls_context()
        server, url = _start_server(context)
        try:
            entries = []
            for client in clients:
                # Async-only clients participate only in http1 today.
                if client["status"] != "ok":
                    skipped = {"client": client["client"],
                               "status": "skipped"}
                    reason = client.get("reason") or (
                        "TLS scenario not supported for this client type"
                        if client["status"] == "ok_async" else "unavailable"
                    )
                    skipped["reason"] = reason
                    entries.append(skipped)
                    continue
                try:
                    make_session = client["factory"]
                    session = make_session()
                    cold_warm = _first_vs_warm(session, url, timeout)
                    session.close()

                    batch_session = make_session()
                    try:
                        stats = _time_batch(
                            lambda: batch_session.request("GET", url,
                                                          timeout=timeout),
                            warmup, requests,
                        )
                    finally:
                        batch_session.close()
                    merged = {"client": client["client"], "status": "ok"}
                    merged.update(stats)
                    merged.update(cold_warm)
                    entries.append(merged)
                except Exception as exc:
                    entries.append({"client": client["client"],
                                    "status": "skipped",
                                    "reason": f"{type(exc).__name__}: {exc}"})
            report.scenarios["tls"] = entries
        finally:
            _stop_server(server)

    return report


def _measure_client(client: Dict[str, Any], url: str, requests: int,
                    warmup: int, timeout: float) -> Dict[str, Any]:
    if client["status"] == "skipped":
        return {k: v for k, v in client.items()
                if k in ("client", "status", "reason")}

    name = client["client"]
    if client["status"] == "ok_async":
        started = time.perf_counter()
        latencies = _aio_batch(url, timeout, warmup, requests)
        wall = time.perf_counter() - started
        return _summarize_latencies(name, latencies, requests, wall,
                                    memory_mb=None)

    session = client["factory"]()
    try:
        return _time_batch_entry(name, session, url, requests, warmup, timeout)
    finally:
        session.close()


def _time_batch_entry(name: str, session: Any, url: str, requests: int,
                      warmup: int, timeout: float) -> Dict[str, Any]:
    stats = _time_batch(
        lambda: session.request("GET", url, timeout=timeout),
        warmup, requests,
    )
    merged = {"client": name, "status": "ok"}
    merged.update(stats)
    return merged


if __name__ == "__main__":  # pragma: no cover
    print(json.dumps(run_benchmark().to_dict(), indent=2))
