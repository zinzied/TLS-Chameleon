"""``inspect``: one-request structured inspection.

Returns everything honestly observable about a single request: status,
negotiated protocol, backend, timing, and (optionally) the network-observed
fingerprint when an echo endpoint is supplied.
"""

from dataclasses import dataclass, field
from time import perf_counter
from typing import Any, Dict, Optional

from ..security.redaction import redact_url
from .trace import NetworkTrace, collect_trace

__all__ = ["InspectResult", "inspect_url"]


@dataclass
class InspectResult:
    """Structured result of :func:`inspect_url`."""

    url: str
    trace: NetworkTrace = field(default_factory=NetworkTrace)
    fingerprint_info: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Stable JSON output (AI-agent friendly)."""
        return {
            "schema": "tls-chameleon.inspect/1",
            "url": redact_url(self.url),
            "error": self.error,
            "trace": self.trace.to_dict(),
            "fingerprint": self.fingerprint_info,
        }

    def to_text(self) -> str:
        if self.error:
            return f"inspect failed: {self.error}"
        t = self.trace
        lines = [
            f"URL          {redact_url(self.url)}",
            f"Status       {t.status_code}",
            f"Protocol     {t.protocol or 'unknown'}",
            f"Backend      {t.backend or 'unknown'}",
            f"Profile      {t.profile or '-'}",
        ]
        if t.remote_ip:
            lines.append(f"Remote IP    {t.remote_ip}")
        if t.tls_version:
            lines.append(f"TLS          {t.tls_version}")
        if t.alpn:
            lines.append(f"ALPN         {', '.join(t.alpn)}")
        for key, value in t.timing_ms.items():
            lines.append(f"{key:<22}{value:.1f}ms")
        for note in t.notes:
            lines.append(f"note         {note}")
        return "\n".join(lines)


def inspect_url(
    url: str,
    client: Optional[Any] = None,
    *,
    method: str = "GET",
    timeout: float = 15.0,
    echo_endpoint: Optional[str] = None,
) -> InspectResult:
    """Perform one request and report structured observations.

    Args:
        url: Target URL.
        client: Existing ``TLSChameleon`` instance. When omitted a temporary
            default client is created and closed afterwards.
        timeout: Request timeout in seconds.
        echo_endpoint: Optional TLS-echo service URL. When given, a second
            request through the same session collects the network-observed
            JA3/JA4/ALPN and merges it into the result's fingerprint section.
    """
    close_after = False
    if client is None:  # lazy import to avoid cycles
        from ..client import TLSChameleon

        client = TLSChameleon(timeout=timeout)
        close_after = True

    result = InspectResult(url=url)
    started = perf_counter()
    try:
        response = client.session.request(method.upper(), url, timeout=timeout)
        total_ms = (perf_counter() - started) * 1000.0

        fingerprint_section: Optional[Dict[str, Any]] = None
        if echo_endpoint:
            fingerprint_section = _capture_fingerprint(client, echo_endpoint, timeout)

        result.trace = collect_trace(
            method,
            url,
            response,
            backend=getattr(client, "engine", None),
            profile=getattr(client, "profile_name", None),
            request_headers=dict(getattr(client, "headers", {}) or {}),
            total_ms=total_ms,
            fingerprint=fingerprint_section,
        )
        result.fingerprint_info = client.get_fingerprint_info()
    except Exception as exc:
        result.error = f"{type(exc).__name__}: {exc}"
        result.trace = collect_trace(
            method,
            url,
            backend=getattr(client, "engine", None),
            profile=getattr(client, "profile_name", None),
            total_ms=(perf_counter() - started) * 1000.0,
            error=exc,
        )
    finally:
        if close_after:
            try:
                client.close()
            except Exception:  # pragma: no cover - best effort
                pass
    return result


def _capture_fingerprint(client: Any, echo_endpoint: str, timeout: float) -> Optional[Dict[str, Any]]:
    """Run a capture through the same session; failures become notes."""
    from ..fingerprint import capture as run_capture

    try:
        capture_result = run_capture(
            url=echo_endpoint, session=client.session, timeout=timeout,
            name="inspect_echo",
        )
        return capture_result.fingerprint.to_dict()
    except Exception as exc:
        return {"capture_error": f"{type(exc).__name__}: {exc}"}
