"""Fingerprint validation.

Validation is structural and semantic: it rejects impossible or
self-contradictory configurations (duplicate identifiers, unknown sources,
synthetic data marked as verified, TLS 1.3-only ciphers on a TLS 1.0/1.1
version claim, ...). It does NOT judge whether a fingerprint will fool any
particular detector.
"""

from typing import Any, Dict, List

from .model import Fingerprint, SOURCES

__all__ = ["ValidationIssue", "validate_fingerprint", "validate_profile_dict"]


class ValidationIssue:
    """A single validation finding."""

    def __init__(self, severity: str, code: str, message: str) -> None:
        self.severity = severity  # "error" | "warning"
        self.code = code
        self.message = message

    def to_dict(self) -> Dict[str, str]:
        return {"severity": self.severity, "code": self.code, "message": self.message}

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        return f"<{self.severity} {self.code}: {self.message}>"


def _dupes(values: List[Any]) -> List[Any]:
    seen = set()
    dupes: List[Any] = []
    for value in values:
        if value in seen and value not in dupes:
            dupes.append(value)
        seen.add(value)
    return dupes


# Cipher IDs that only exist in TLS 1.3 (RFC 8446 registry).
_TLS13_CIPHER_IDS = {4865, 4866, 4867}


def _unknown_cipher_names(names: List[str]) -> List[str]:
    try:
        from ..gen_fingerprint import CIPHER_IDS
    except Exception:  # pragma: no cover - defensive
        return []
    unknown = []
    for name in names:
        if str(name).startswith("grease_"):
            continue  # GREASE markers are intentional placeholders
        if name not in CIPHER_IDS:
            unknown.append(name)
    return unknown


def validate_fingerprint(fingerprint: Fingerprint) -> List[ValidationIssue]:
    """Validate a :class:`Fingerprint`; returns a list of issues.

    Empty list means valid. ``error`` issues make a fingerprint invalid;
    ``warning`` issues are advisory.
    """
    issues: List[ValidationIssue] = []
    tls = fingerprint.tls

    if not fingerprint.name:
        issues.append(ValidationIssue("error", "missing_name", "Fingerprint has no name"))

    if not tls.cipher_ids:
        issues.append(ValidationIssue("error", "no_ciphers", "No cipher suites defined"))

    for label, values in (
        ("cipher_ids", tls.cipher_ids),
        ("extension_ids", tls.extension_ids),
        ("curve_ids", tls.curve_ids),
        ("point_format_ids", tls.point_format_ids),
    ):
        duplicates = _dupes(list(values))
        if duplicates:
            issues.append(
                ValidationIssue(
                    "error",
                    f"duplicate_{label}",
                    f"Duplicate values in {label}: {duplicates}",
                )
            )

    # Version consistency: TLS 1.3-only ciphers cannot appear when the record
    # version claims a pre-1.2 negotiation. (771 = TLS 1.2 record version.)
    try:
        version_int = int(tls.version)
    except (TypeError, ValueError):
        issues.append(
            ValidationIssue("error", "bad_version", f"Non-numeric version '{tls.version}'")
        )
    else:
        if version_int < 771:
            tls13 = [c for c in tls.cipher_ids if c in _TLS13_CIPHER_IDS]
            if tls13:
                issues.append(
                    ValidationIssue(
                        "error",
                        "tls13_ciphers_with_old_version",
                        f"TLS 1.3 ciphers {tls13} cannot be offered under "
                        f"record version {version_int}",
                    )
                )

    # Provenance honesty
    if fingerprint.metadata.source not in SOURCES:
        issues.append(
            ValidationIssue(
                "error",
                "unknown_source",
                f"source '{fingerprint.metadata.source}' not in {SOURCES}",
            )
        )
    if fingerprint.metadata.source == "synthetic" and fingerprint.metadata.verified:
        issues.append(
            ValidationIssue(
                "error",
                "synthetic_marked_verified",
                "Synthetic fingerprints must never be marked as verified",
            )
        )
    if fingerprint.metadata.source == "captured" and not fingerprint.metadata.captured_at:
        issues.append(
            ValidationIssue(
                "warning",
                "capture_missing_timestamp",
                "Captured fingerprints should include captured_at metadata",
            )
        )

    # Cipher names, when present, should resolve to known OpenSSL names.
    names = tls.cipher_names or []
    unknown = _unknown_cipher_names(names)
    if unknown:
        issues.append(
            ValidationIssue(
                "warning",
                "unknown_cipher_names",
                f"Cipher names not in mapping table: {unknown}",
            )
        )

    return issues


def validate_profile_dict(profile: Dict[str, Any], name: str = "") -> List[ValidationIssue]:
    """Validate a legacy/gallery profile dict through the model pipeline."""
    from .adapter import fingerprint_from_legacy

    resolved_name = name or str(profile.get("name", "unnamed"))
    fingerprint = fingerprint_from_legacy(profile, name=resolved_name)
    return validate_fingerprint(fingerprint)
