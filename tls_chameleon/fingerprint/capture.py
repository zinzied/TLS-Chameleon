"""Live fingerprint capture via TLS echo endpoints.

A *capture* asks an echo service (default: https://tls.peet.ws/api/all) to
report what it actually observed about our connection, and maps the answer
into a :class:`Fingerprint` with ``source="captured"`` provenance.

Legitimate uses: protocol research, debugging, compatibility testing,
reproducible experiments. Captures are read-only diagnostics; this module
performs one ordinary HTTPS GET through the pluggable transport layer and
never imports a networking library directly.
"""

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from .adapter import _parse_ja3
from .model import Fingerprint, HeaderFingerprint, HTTP2Fingerprint, Metadata

__all__ = ["capture", "CaptureResult", "DEFAULT_ECHO_URL"]

DEFAULT_ECHO_URL = "https://tls.peet.ws/api/all"


@dataclass
class CaptureResult:
    """Outcome of a capture run."""

    endpoint: str
    fingerprint: Fingerprint
    raw: Dict[str, Any] = field(default_factory=dict)
    captured_at: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": "tls-chameleon.capture/1",
            "endpoint": self.endpoint,
            "captured_at": self.captured_at,
            "fingerprint": self.fingerprint.to_dict(),
        }


def _first(*values: Any) -> Any:
    """First non-empty value among candidates."""
    for value in values:
        if value:
            return value
    return None


def _map_response(raw: Dict[str, Any], name: str) -> Fingerprint:
    """Defensively map an echo-service JSON payload into the model."""
    tls_block = raw.get("tls") if isinstance(raw.get("tls"), dict) else {}

    ja3 = _first(tls_block.get("ja3"), raw.get("ja3"))
    tls_fp = _parse_ja3(ja3) if isinstance(ja3, str) else None
    if tls_fp is None:
        from .model import TLSFingerprint

        tls_fp = TLSFingerprint()

    ja3_hash = _first(tls_block.get("ja3_hash"), raw.get("ja3_hash"))
    extra: Dict[str, Any] = {}
    if ja3_hash:
        extra["reported_ja3_hash"] = ja3_hash

    ja4 = _first(tls_block.get("ja4"), raw.get("ja4"))
    if ja4:
        tls_fp.ja4 = str(ja4)

    alpn = _first(tls_block.get("alpn"), raw.get("alpn"))
    if isinstance(alpn, list):
        tls_fp.alpn = [str(p) for p in alpn]
    elif isinstance(alpn, str):
        tls_fp.alpn = [alpn]

    http_version = _first(raw.get("http_version"), raw.get("proto"))

    h2_block = raw.get("h2") if isinstance(raw.get("h2"), dict) else {}
    fingerprint_h2 = (
        h2_block.get("fingerprint") if isinstance(h2_block.get("fingerprint"), dict) else {}
    )
    settings: Dict[str, int] = {}
    sent_settings = _first(
        fingerprint_h2.get("sent_settings"), h2_block.get("sent_settings")
    )
    if isinstance(sent_settings, dict):
        for key, value in sent_settings.items():
            try:
                settings[str(key)] = int(value)
            except (TypeError, ValueError):
                continue

    http2 = HTTP2Fingerprint(settings=settings)
    headers = HeaderFingerprint()

    metadata = Metadata(
        source="captured",
        verified=True,
        captured_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        notes=f"http_version={http_version}" if http_version else None,
    )

    fingerprint = Fingerprint(
        name=name,
        tls=tls_fp,
        http2=http2,
        headers=headers,
        metadata=metadata,
        user_agent=raw.get("user_agent"),
        extra=extra,
    )
    # A capture IS the observation: mark the reported JA3 as authoritative by
    # keeping the exact string when present.
    if isinstance(ja3, str) and tls_fp.ja3 != ja3.strip():
        fingerprint.extra["ja3_raw"] = ja3
    return fingerprint


def capture(
    url: str = DEFAULT_ECHO_URL,
    session: Optional[Any] = None,
    timeout: float = 15.0,
    name: str = "live_capture",
) -> CaptureResult:
    """Capture the network-observed fingerprint of a session.

    Args:
        url: Echo endpoint returning JSON describing the observed connection.
        session: An existing duck-typed session (e.g. ``client.session``).
            When omitted, a temporary default-backend session is created.
        timeout: Request timeout in seconds.
        name: Name assigned to the resulting fingerprint.

    Returns:
        CaptureResult with the mapped fingerprint and raw endpoint payload.
    """
    close_after = False
    if session is None:
        from ..transport import SessionConfig, select_transport

        session = select_transport().create_session(SessionConfig(timeout=timeout))
        close_after = True

    try:
        response = session.request("GET", url, timeout=timeout)
        text = getattr(response, "text", "") or ""
        status = getattr(response, "status_code", None)
        if status is not None and int(status) >= 400:
            raise RuntimeError(
                f"Echo endpoint returned HTTP {status}; cannot capture fingerprint"
            )
        try:
            raw = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"Echo endpoint did not return valid JSON ({exc}); "
                f"pass a compatible 'url' or mock the response in tests"
            ) from exc
    finally:
        if close_after:
            try:
                session.close()
            except Exception:  # pragma: no cover - best effort
                pass

    fingerprint = _map_response(raw, name=name)
    return CaptureResult(
        endpoint=url,
        fingerprint=fingerprint,
        raw=raw,
        captured_at=fingerprint.metadata.captured_at or "",
    )
