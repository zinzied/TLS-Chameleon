"""Structured fingerprint model.

The canonical representation stores numeric TLS identifiers (the JA3-native
form). Human-readable cipher names are kept as optional extras.
"""

import hashlib
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

__all__ = [
    "TLSFingerprint",
    "HTTP2Fingerprint",
    "HeaderFingerprint",
    "Metadata",
    "Fingerprint",
]

#: Provenance of a fingerprint. Only ``captured``/``documented`` may claim to
#: describe a real browser; ``synthetic`` data exists for testing/research.
SOURCES = ("captured", "documented", "synthetic")


@dataclass
class TLSFingerprint:
    """TLS ClientHello-level fingerprint (JA3 components + extras).

    ``cipher_ids`` / ``extension_ids`` / ``curve_ids`` / ``point_format_ids``
    are decimal values in wire order. The JA3 string is derived from them.
    """

    version: str = "771"  # TLS record version used by the JA3 spec ("771" = TLS 1.2)
    cipher_ids: List[int] = field(default_factory=list)
    extension_ids: List[int] = field(default_factory=list)
    curve_ids: List[int] = field(default_factory=list)
    point_format_ids: List[int] = field(default_factory=list)
    signature_algorithm_ids: Optional[List[int]] = None
    alpn: List[str] = field(default_factory=list)
    supported_versions: Optional[List[str]] = None
    key_share_groups: Optional[List[int]] = None
    ja4: Optional[str] = None
    # Human-readable names, aligned with cipher_ids when available.
    cipher_names: Optional[List[str]] = None

    @property
    def ja3(self) -> str:
        """JA3 string: version,ciphers,extensions,curves,point-formats."""
        return ",".join(
            [
                self.version,
                "-".join(str(c) for c in self.cipher_ids),
                "-".join(str(e) for e in self.extension_ids),
                "-".join(str(c) for c in self.curve_ids),
                "-".join(str(p) for p in self.point_format_ids),
            ]
        )

    @property
    def ja3_hash(self) -> str:
        return hashlib.md5(self.ja3.encode("utf-8")).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        data: Dict[str, Any] = {
            "version": self.version,
            "cipher_ids": list(self.cipher_ids),
            "extension_ids": list(self.extension_ids),
            "curve_ids": list(self.curve_ids),
            "point_format_ids": list(self.point_format_ids),
            "alpn": list(self.alpn),
            "ja3": self.ja3,
            "ja3_hash": self.ja3_hash,
        }
        if self.signature_algorithm_ids is not None:
            data["signature_algorithm_ids"] = list(self.signature_algorithm_ids)
        if self.supported_versions is not None:
            data["supported_versions"] = list(self.supported_versions)
        if self.key_share_groups is not None:
            data["key_share_groups"] = list(self.key_share_groups)
        if self.ja4 is not None:
            data["ja4"] = self.ja4
        if self.cipher_names is not None:
            data["cipher_names"] = list(self.cipher_names)
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TLSFingerprint":
        return cls(
            version=str(data.get("version", "771")),
            cipher_ids=list(data.get("cipher_ids") or []),
            extension_ids=list(data.get("extension_ids") or []),
            curve_ids=list(data.get("curve_ids") or []),
            point_format_ids=list(data.get("point_format_ids") or []),
            signature_algorithm_ids=data.get("signature_algorithm_ids"),
            alpn=list(data.get("alpn") or []),
            supported_versions=data.get("supported_versions"),
            key_share_groups=data.get("key_share_groups"),
            ja4=data.get("ja4"),
            cipher_names=data.get("cipher_names"),
        )


@dataclass
class HTTP2Fingerprint:
    """Observable HTTP/2 behavior (SETTINGS and friends).

    Only fields that a backend can actually observe/report should be filled;
    ``None`` means "not observed".
    """

    settings: Dict[str, int] = field(default_factory=dict)
    window_update_size: Optional[int] = None
    pseudo_header_order: Optional[List[str]] = None
    priority: Optional[Dict[str, Any]] = None
    headers_order_aware: Optional[bool] = None

    def to_dict(self) -> Dict[str, Any]:
        data: Dict[str, Any] = {"settings": dict(self.settings)}
        if self.window_update_size is not None:
            data["window_update_size"] = self.window_update_size
        if self.pseudo_header_order is not None:
            data["pseudo_header_order"] = list(self.pseudo_header_order)
        if self.priority is not None:
            data["priority"] = dict(self.priority)
        if self.headers_order_aware is not None:
            data["headers_order_aware"] = self.headers_order_aware
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "HTTP2Fingerprint":
        return cls(
            settings=dict(data.get("settings") or {}),
            window_update_size=data.get("window_update_size"),
            pseudo_header_order=data.get("pseudo_header_order"),
            priority=data.get("priority"),
            headers_order_aware=data.get("headers_order_aware"),
        )


@dataclass
class HeaderFingerprint:
    """HTTP header ordering/casing characteristics."""

    order: List[str] = field(default_factory=list)
    case: str = "lower"  # "lower" | "title" | "preserve"

    def to_dict(self) -> Dict[str, Any]:
        return {"order": list(self.order), "case": self.case}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "HeaderFingerprint":
        return cls(
            order=list(data.get("order") or []),
            case=str(data.get("case", "lower")),
        )


@dataclass
class Metadata:
    """Provenance metadata. ``source`` must be one of :data:`SOURCES`."""

    source: str = "documented"
    verified: bool = False
    captured_at: Optional[str] = None
    browser: Optional[str] = None
    browser_version: Optional[str] = None
    platform: Optional[str] = None
    notes: Optional[str] = None

    def __post_init__(self) -> None:
        if self.source not in SOURCES:
            raise ValueError(
                f"source must be one of {SOURCES}, got '{self.source}'"
            )

    def to_dict(self) -> Dict[str, Any]:
        data: Dict[str, Any] = {"source": self.source, "verified": self.verified}
        for key in ("captured_at", "browser", "browser_version", "platform", "notes"):
            value = getattr(self, key)
            if value is not None:
                data[key] = value
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Metadata":
        return cls(
            source=str(data.get("source", "documented")),
            verified=bool(data.get("verified", False)),
            captured_at=data.get("captured_at"),
            browser=data.get("browser"),
            browser_version=data.get("browser_version"),
            platform=data.get("platform"),
            notes=data.get("notes"),
        )


@dataclass
class Fingerprint:
    """Complete, extensible fingerprint record."""

    name: str
    tls: TLSFingerprint = field(default_factory=TLSFingerprint)
    http2: HTTP2Fingerprint = field(default_factory=HTTP2Fingerprint)
    headers: HeaderFingerprint = field(default_factory=HeaderFingerprint)
    metadata: Metadata = field(default_factory=Metadata)
    user_agent: Optional[str] = None
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Stable JSON-serializable representation."""
        data: Dict[str, Any] = {
            "schema": "tls-chameleon.fingerprint/1",
            "name": self.name,
            "tls": self.tls.to_dict(),
            "http2": self.http2.to_dict(),
            "headers": self.headers.to_dict(),
            "metadata": self.metadata.to_dict(),
        }
        if self.user_agent is not None:
            data["user_agent"] = self.user_agent
        if self.extra:
            data["extra"] = dict(self.extra)
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Fingerprint":
        return cls(
            name=str(data.get("name", "")),
            tls=TLSFingerprint.from_dict(data.get("tls") or {}),
            http2=HTTP2Fingerprint.from_dict(data.get("http2") or {}),
            headers=HeaderFingerprint.from_dict(data.get("headers") or {}),
            metadata=Metadata.from_dict(data.get("metadata") or {}),
            user_agent=data.get("user_agent"),
            extra=dict(data.get("extra") or {}),
        )
