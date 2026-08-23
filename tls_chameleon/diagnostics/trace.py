"""Structured, machine-readable network trace.

Honesty rule: every field that could not be observed stays ``None``.
A trace never guesses TLS versions or ALPN it did not actually see.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, Optional

from ..security.redaction import redact_headers

__all__ = ["NetworkTrace", "collect_trace", "normalize_http_version"]

# curl_cffi exposes CurlHttpVersion as a small int (libcurl numbering).
_CURL_HTTP_VERSIONS = {
    1: "http/1.0",
    2: "http/1.1",
    3: "h2",
    30: "h3",
}


def normalize_http_version(value: Any) -> Optional[str]:
    """Normalize any backend's protocol indicator to 'h2' / 'http/1.1' / ..."""
    if value is None:
        return None
    if isinstance(value, int) and not isinstance(value, bool):
        return _CURL_HTTP_VERSIONS.get(value)
    text = value.decode() if isinstance(value, bytes) else str(value)
    text = text.strip().lower()
    if text.startswith("http/"):
        text = text[5:]
    aliases = {
        "1.0": "http/1.0",
        "1.1": "http/1.1",
        "2": "h2",
        "2.0": "h2",
        "h2": "h2",
        "3": "h3",
        "h3": "h3",
    }
    return aliases.get(text)


@dataclass
class NetworkTrace:
    """Observation of one request/response cycle."""

    backend: Optional[str] = None
    profile: Optional[str] = None
    method: Optional[str] = None
    url: Optional[str] = None
    status_code: Optional[int] = None
    protocol: Optional[str] = None          # "h2" | "http/1.1" | "h3" | ...
    remote_ip: Optional[str] = None
    local_ip: Optional[str] = None
    tls_version: Optional[str] = None       # only when actually observed
    alpn: Optional[list] = None             # only when actually observed
    timing_ms: Dict[str, float] = field(default_factory=dict)
    request_headers: Dict[str, str] = field(default_factory=dict)
    response_headers: Dict[str, str] = field(default_factory=dict)
    redirect_count: Optional[int] = None
    fingerprint: Optional[Dict[str, Any]] = None  # echo/capture mode only
    notes: list = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Stable JSON-serializable representation (headers pre-redacted)."""
        return {
            "backend": self.backend,
            "profile": self.profile,
            "request": {"method": self.method, "url": self.url,
                        "headers": dict(self.request_headers)},
            "response": {"status_code": self.status_code,
                         "headers": dict(self.response_headers)},
            "connection": {
                "protocol": self.protocol,
                "remote_ip": self.remote_ip,
                "local_ip": self.local_ip,
                "tls_version": self.tls_version,
                "alpn": list(self.alpn) if self.alpn is not None else None,
                "redirect_count": self.redirect_count,
            },
            "timing_ms": {k: round(v, 2) for k, v in self.timing_ms.items()},
            "fingerprint": self.fingerprint,
            "notes": list(self.notes),
        }

    def to_text(self) -> str:
        lines = [
            f"{self.method} {self.url} -> {self.status_code}",
            f"backend={self.backend} profile={self.profile} "
            f"protocol={self.protocol or 'unknown'}",
        ]
        if self.remote_ip:
            lines.append(f"remote={self.remote_ip}")
        if self.tls_version:
            lines.append(f"tls={self.tls_version}")
        for key, value in self.timing_ms.items():
            lines.append(f"{key}: {value:.1f}ms")
        for note in self.notes:
            lines.append(f"note: {note}")
        return "\n".join(lines)


def _extract_protocol(response: Any) -> Optional[str]:
    version = getattr(response, "http_version", None)
    if isinstance(version, int):
        return normalize_http_version(version)
    extensions = getattr(response, "extensions", None)
    if isinstance(extensions, Mapping):
        return normalize_http_version(extensions.get("http_version"))
    return normalize_http_version(version) if version else None


def _extract_remote_ip(response: Any) -> Optional[str]:
    ip = getattr(response, "primary_ip", None)
    if ip:
        return str(ip)
    stream = (getattr(response, "extensions", None) or {}).get("network_stream")
    getter = getattr(stream, "get_extra_info", None) if stream else None
    if callable(getter):
        try:
            addr = getter("server_addr")
            if addr:
                host = addr[0]
                return f"[{host}]" if ":" in host and not host.startswith("[") else host
        except Exception:  # pragma: no cover - backend dependent
            pass
    return None


def collect_trace(
    method: str,
    url: str,
    response: Any = None,
    *,
    backend: Optional[str] = None,
    profile: Optional[str] = None,
    request_headers: Optional[Mapping[str, str]] = None,
    total_ms: Optional[float] = None,
    fingerprint: Optional[Dict[str, Any]] = None,
    error: Optional[Exception] = None,
) -> NetworkTrace:
    """Build a :class:`NetworkTrace` from whatever the backend exposed."""
    trace = NetworkTrace(
        backend=backend,
        profile=profile,
        method=method.upper(),
        url=url,
        request_headers=redact_headers(request_headers),
    )

    if error is not None:
        trace.notes.append(f"error: {type(error).__name__}: {error}")

    if response is not None:
        trace.status_code = getattr(response, "status_code", None)
        trace.protocol = _extract_protocol(response)
        trace.remote_ip = _extract_remote_ip(response)
        trace.local_ip = (
            str(getattr(response, "local_ip")) if getattr(response, "local_ip", None) else None
        )
        trace.redirect_count = getattr(response, "redirect_count", None)
        headers = getattr(response, "headers", None)
        if headers is not None:
            trace.response_headers = redact_headers(dict(headers))
        elapsed = getattr(response, "elapsed", None)
        has_seconds = hasattr(elapsed, "total_seconds")
        if has_seconds:
            trace.timing_ms["server_reported_total"] = elapsed.total_seconds() * 1000.0

    if total_ms is not None:
        trace.timing_ms["total"] = float(total_ms)

    if fingerprint is not None:
        trace.fingerprint = fingerprint

    # Explicit honesty markers when something was not observable.
    if trace.tls_version is None:
        trace.notes.append("tls_version not observable via this backend")
    if trace.alpn is None:
        trace.notes.append("alpn not observable via this backend")
    return trace
