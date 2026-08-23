"""Adapters between legacy profile dicts and the structured model.

The rest of the library still speaks the gallery dict format; these helpers
keep both worlds in sync without duplicating data.
"""

import re
from typing import Any, Dict, List, Optional

from .model import Fingerprint, HeaderFingerprint, HTTP2Fingerprint, Metadata, TLSFingerprint

__all__ = ["fingerprint_from_legacy", "fingerprint_to_legacy"]

_JA3_PARTS = 5


def _parse_ja3(ja3: str) -> Optional[TLSFingerprint]:
    """Parse a JA3 string into a :class:`TLSFingerprint` (or None if malformed)."""
    parts = str(ja3).split(",")
    if len(parts) != _JA3_PARTS:
        return None

    def _ids(raw: str) -> List[int]:
        values: List[int] = []
        for token in raw.split("-"):
            token = token.strip()
            if not token:
                continue
            try:
                values.append(int(token))
            except ValueError:
                # GREASE-style or non-numeric tokens are ignored for the
                # numeric model; they remain part of the original ja3 string.
                continue
        return values

    tls = TLSFingerprint(
        version=parts[0].strip() or "771",
        cipher_ids=_ids(parts[1]),
        extension_ids=_ids(parts[2]),
        curve_ids=_ids(parts[3]),
        point_format_ids=_ids(parts[4]),
    )
    # Preserve the exact source string when tokens were non-numeric.
    if tls.ja3 != str(ja3).strip():
        tls.cipher_names = None  # marker: canonical string differs
    return tls


def _cipher_ids_from_names(names: List[str]) -> List[int]:
    try:
        from ..gen_fingerprint import CIPHER_IDS
    except Exception:  # pragma: no cover - defensive
        return []
    ids: List[int] = []
    for name in names:
        if name in CIPHER_IDS:
            ids.append(CIPHER_IDS[name])
        elif str(name).startswith("grease_"):
            try:
                ids.append(int(str(name).split("_")[-1]))
            except ValueError:
                continue
    return ids


def fingerprint_from_legacy(profile: Dict[str, Any], name: Optional[str] = None) -> Fingerprint:
    """Build a :class:`Fingerprint` from a gallery/legacy profile dict."""
    name = name or str(profile.get("name", "unnamed"))

    tls: Optional[TLSFingerprint] = None
    ja3_raw = profile.get("ja3")
    extra: Dict[str, Any] = {}
    if isinstance(ja3_raw, str) and len(ja3_raw.split(",")) == _JA3_PARTS:
        tls = _parse_ja3(ja3_raw)
        # Preserve the exact source string when it contained non-numeric
        # tokens that the numeric model cannot round-trip.
        if tls is not None and tls.ja3 != ja3_raw.strip():
            extra["ja3_raw"] = ja3_raw
    if tls is None:
        names = list(profile.get("ciphers") or profile.get("tls12_ciphers") or [])
        exts = list(profile.get("extensions") or [])
        curves = list(profile.get("curves") or [29, 23, 24])
        tls = TLSFingerprint(
            cipher_ids=_cipher_ids_from_names([str(n) for n in names]),
            extension_ids=[int(e) for e in exts],
            curve_ids=[int(c) for c in curves],
            cipher_names=[str(n) for n in names] if names else None,
        )
    else:
        names = profile.get("ciphers") or profile.get("tls12_ciphers")
        if names:
            tls.cipher_names = [str(n) for n in names]
    tls.ja4 = profile.get("ja4")

    settings = profile.get("http2_settings") or {}
    http2 = HTTP2Fingerprint(settings={str(k): int(v) for k, v in settings.items()})

    headers = HeaderFingerprint(
        order=[str(h).lower() for h in (profile.get("header_order") or [])],
        case=str(profile.get("header_case", "lower")),
    )

    # Provenance: generated profiles are synthetic by definition.
    is_generated = str(name).startswith("gen://")
    metadata = Metadata(
        source="synthetic" if is_generated else "documented",
        verified=False,
        browser=_infer_browser(name),
        platform=profile.get("platform"),
        notes=None,
    )

    return Fingerprint(
        name=name,
        tls=tls,
        http2=http2,
        headers=headers,
        metadata=metadata,
        user_agent=profile.get("user_agent"),
        extra=extra,
    )


def fingerprint_to_legacy(fingerprint: Fingerprint) -> Dict[str, Any]:
    """Convert back to a gallery-compatible dict (best effort).

    The numeric ``ja3`` string is always produced from the model; OpenSSL
    cipher names are included when known.
    """
    out: Dict[str, Any] = {
        "name": fingerprint.name,
        "ja3": fingerprint.tls.ja3,
        "ja3_hash": fingerprint.tls.ja3_hash,
        "extensions": list(fingerprint.tls.extension_ids),
    }
    if fingerprint.tls.ja4:
        out["ja4"] = fingerprint.tls.ja4
    if fingerprint.tls.cipher_names:
        out["ciphers"] = list(fingerprint.tls.cipher_names)
    if fingerprint.http2.settings:
        out["http2_settings"] = dict(fingerprint.http2.settings)
    if fingerprint.headers.order:
        out["header_order"] = list(fingerprint.headers.order)
        out["header_case"] = fingerprint.headers.case
    if fingerprint.user_agent:
        out["user_agent"] = fingerprint.user_agent
    return out


def _infer_browser(name: str) -> Optional[str]:
    match = re.match(r"^(chrome|firefox|safari|edge)", str(name).lower())
    return match.group(1) if match else None
