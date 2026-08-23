"""Human- and machine-readable fingerprint diff.

``diff_fingerprints(a, b)`` produces a structured report with SAME/DIFFERENT
verdicts per field and a deterministic text rendering::

    TLS
      Cipher suites       DIFFERENT
      Extensions          SAME
      ALPN                SAME
    HTTP/2
      SETTINGS            DIFFERENT
    Headers
      Ordering            DIFFERENT
    Overall similarity: 87.3%
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .model import Fingerprint
from .similarity import FingerprintSimilarity, SimilarityWeights

__all__ = ["diff_fingerprints", "DiffReport"]


@dataclass
class _FieldVerdict:
    label: str
    same: bool


@dataclass
class DiffReport:
    """Structured diff between two fingerprints."""

    name_a: str
    name_b: str
    sections: Dict[str, List[_FieldVerdict]] = field(default_factory=dict)
    similarity: float = 0.0  # 0..100

    # ------------------------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        """Stable machine-readable representation."""
        return {
            "a": self.name_a,
            "b": self.name_b,
            "sections": {
                section: [
                    {"field": v.label, "same": v.same} for v in verdicts
                ]
                for section, verdicts in self.sections.items()
            },
            "similarity": round(self.similarity, 1),
        }

    def to_text(self) -> str:
        """Deterministic human-readable rendering."""
        lines: List[str] = []
        for section, verdicts in self.sections.items():
            lines.append(section)
            for v in verdicts:
                verdict = "SAME" if v.same else "DIFFERENT"
                pad = max(0, 21 - len(v.label))
                lines.append(f"  {v.label}{' ' * pad}{verdict}")
        lines.append(f"Overall similarity: {round(self.similarity, 1)}%")
        return "\n".join(lines)


def diff_fingerprints(
    a: Fingerprint,
    b: Fingerprint,
    weights: Optional[SimilarityWeights] = None,
) -> DiffReport:
    """Compare two fingerprints field-by-field with an overall score."""
    result = FingerprintSimilarity(weights).compare(a, b)

    ta, tb = a.tls, b.tls
    sections: Dict[str, List[_FieldVerdict]] = {}

    sections["TLS"] = [
        _FieldVerdict("Cipher suites", ta.cipher_ids == tb.cipher_ids),
        _FieldVerdict("Extensions", ta.extension_ids == tb.extension_ids),
        _FieldVerdict("Curves", ta.curve_ids == tb.curve_ids),
        _FieldVerdict("ALPN", ta.alpn == tb.alpn),
        _FieldVerdict("JA3", (a.extra.get("ja3_raw") or ta.ja3)
                      == (b.extra.get("ja3_raw") or tb.ja3)),
    ]
    if ta.ja4 is not None or tb.ja4 is not None:
        sections["TLS"].append(_FieldVerdict("JA4", ta.ja4 == tb.ja4))

    ha, hb = a.http2.settings, b.http2.settings
    keys = sorted(set(ha) | set(hb))
    settings_same = all(ha.get(k) == hb.get(k) for k in keys)
    sections["HTTP/2"] = [
        _FieldVerdict("SETTINGS", settings_same),
        _FieldVerdict(
            "Window size",
            ha.get("INITIAL_WINDOW_SIZE") == hb.get("INITIAL_WINDOW_SIZE"),
        ),
    ]

    sections["Headers"] = [
        _FieldVerdict("Ordering", a.headers.order == b.headers.order),
        _FieldVerdict("Casing", a.headers.case == b.headers.case),
    ]

    return DiffReport(
        name_a=a.name,
        name_b=b.name,
        sections=sections,
        similarity=result.total,
    )
