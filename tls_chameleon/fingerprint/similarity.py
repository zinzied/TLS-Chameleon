"""Explainable fingerprint similarity scoring.

The score measures *structural similarity between two fingerprints*.
It does NOT represent detectability, "stealth", or bypass probability --
see the module docstring of :mod:`tls_chameleon.fingerprint`.
"""

from dataclasses import dataclass, field
from difflib import SequenceMatcher
from typing import Any, Dict, List, Optional

from .model import Fingerprint

__all__ = ["SimilarityWeights", "SimilarityResult", "FingerprintSimilarity"]


@dataclass
class SimilarityWeights:
    """Layer weights (must sum to a positive value; normalized internally)."""

    tls: float = 0.5
    http2: float = 0.3
    headers: float = 0.2


@dataclass
class SimilarityResult:
    """Result of comparing two fingerprints."""

    total: float  # 0..100
    layers: Dict[str, float] = field(default_factory=dict)  # per-layer 0..100
    details: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    changed_fields: List[str] = field(default_factory=list)
    explanation: List[str] = field(default_factory=list)
    confidence: str = "high"  # high | medium | low

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total": round(self.total, 1),
            "layers": {k: round(v, 1) for k, v in self.layers.items()},
            "details": self.details,
            "changed_fields": list(self.changed_fields),
            "explanation": list(self.explanation),
            "confidence": self.confidence,
        }


def _ratio(a: List[Any], b: List[Any]) -> float:
    """Order-sensitive similarity between two sequences (0..1)."""
    if not a and not b:
        return 1.0
    return SequenceMatcher(None, [str(x) for x in a], [str(x) for x in b]).ratio()


def _set_overlap(a: List[Any], b: List[Any]) -> float:
    """Set-based similarity (Jaccard), order-insensitive (0..1)."""
    sa, sb = set(a), set(b)
    if not sa and not sb:
        return 1.0
    union = sa | sb
    return len(sa & sb) / len(union) if union else 1.0


class FingerprintSimilarity:
    """Configurable, explainable comparison engine."""

    def __init__(self, weights: Optional[SimilarityWeights] = None) -> None:
        self.weights = weights or SimilarityWeights()

    # ------------------------------------------------------------------
    # Layer scorers -- each returns (score 0..100, detail dict, notes)
    # ------------------------------------------------------------------

    def _score_tls(self, a: Fingerprint, b: Fingerprint):
        ta, tb = a.tls, b.tls
        details: Dict[str, Any] = {}
        notes: List[str] = []

        cipher_order = _ratio(ta.cipher_ids, tb.cipher_ids)
        cipher_set = _set_overlap(ta.cipher_ids, tb.cipher_ids)
        ext_order = _ratio(ta.extension_ids, tb.extension_ids)
        ext_set = _set_overlap(ta.extension_ids, tb.extension_ids)
        curves_exact = ta.curve_ids == tb.curve_ids
        pf_exact = ta.point_format_ids == tb.point_format_ids
        version_match = int(ta.version or 771) == int(tb.version or 771)

        score = (
            version_match * 10.0
            + cipher_order * 30.0
            + max(cipher_order, cipher_set) * 10.0
            + ext_order * 25.0
            + max(ext_order, ext_set) * 10.0
            + curves_exact * 10.0
            + pf_exact * 5.0
        )

        details["version"] = {"match": version_match}
        details["ciphers"] = {
            "order_ratio": round(cipher_order, 3),
            "overlap": round(cipher_set, 3),
        }
        details["extensions"] = {
            "order_ratio": round(ext_order, 3),
            "overlap": round(ext_set, 3),
        }
        details["curves"] = {"exact": curves_exact}
        details["point_formats"] = {"exact": pf_exact}

        ja4_a, ja4_b = ta.ja4, tb.ja4
        if ja4_a is not None and ja4_b is not None:
            ja4_match = ja4_a == ja4_b
            details["ja4"] = {"match": ja4_match}
            if ja4_match:
                score = min(100.0, score + 5.0)
                notes.append("JA4 strings match exactly")
            else:
                notes.append("JA4 strings differ")

        if not version_match:
            notes.append(f"TLS record version differs ({ta.version} vs {tb.version})")
        if cipher_set < 1.0:
            missing_left = sorted(set(ta.cipher_ids) - set(tb.cipher_ids))
            missing_right = sorted(set(tb.cipher_ids) - set(ta.cipher_ids))
            if missing_left:
                notes.append(f"Ciphers only in '{a.name}': {missing_left}")
            if missing_right:
                notes.append(f"Ciphers only in '{b.name}': {missing_right}")
        if not curves_exact:
            notes.append(
                f"Supported groups differ ({ta.curve_ids} vs {tb.curve_ids})"
            )
        return min(score, 100.0), details, notes

    def _score_http2(self, a: Fingerprint, b: Fingerprint):
        sa, sb = a.http2.settings, b.http2.settings
        details: Dict[str, Any] = {}
        notes: List[str] = []

        keys = sorted(set(sa) | set(sb))
        if not keys:
            # No HTTP/2 data on either side: neutral score, low weight effect.
            return 50.0, {"available": False}, ["No HTTP/2 settings recorded"]

        matching = sum(1 for k in keys if sa.get(k) == sb.get(k))
        score = 100.0 * matching / len(keys)
        differing = [k for k in keys if sa.get(k) != sb.get(k)]
        details["settings"] = {
            k: {"a": sa.get(k), "b": sb.get(k)} for k in differing
        }
        for k in differing:
            notes.append(f"HTTP/2 SETTINGS {k}: {sa.get(k)} vs {sb.get(k)}")
        return score, details, notes

    def _score_headers(self, a: Fingerprint, b: Fingerprint):
        ha, hb = a.headers, b.headers
        details: Dict[str, Any] = {}
        notes: List[str] = []

        order_score = _ratio(ha.order, hb.order) * 100.0
        case_score = 100.0 if ha.case == hb.case else 0.0
        score = order_score * 0.8 + case_score * 0.2

        only_a = [h for h in ha.order if h not in hb.order]
        only_b = [h for h in hb.order if h not in ha.order]
        details["order_ratio"] = round(_ratio(ha.order, hb.order), 3)
        details["case"] = {"a": ha.case, "b": hb.case}
        if ha.case != hb.case:
            notes.append(f"Header casing differs ('{ha.case}' vs '{hb.case}')")
        if only_a:
            notes.append(f"Headers only in '{a.name}': {only_a}")
        if only_b:
            notes.append(f"Headers only in '{b.name}': {only_b}")
        return score, details, notes

    # ------------------------------------------------------------------

    def compare(self, fingerprint_a: Fingerprint, fingerprint_b: Fingerprint) -> SimilarityResult:
        """Compare two fingerprints; returns an explainable result."""
        w = self.weights
        total_weight = (w.tls + w.http2 + w.headers) or 1.0

        layers: Dict[str, float] = {}
        all_details: Dict[str, Dict[str, Any]] = {}
        changed: List[str] = []
        explanation: List[str] = []

        scorers = {
            "tls": (self._score_tls, w.tls),
            "http2": (self._score_http2, w.http2),
            "headers": (self._score_headers, w.headers),
        }
        available_weight = 0.0
        weighted_sum = 0.0
        for layer, (scorer, weight) in scorers.items():
            score, details, notes = scorer(fingerprint_a, fingerprint_b)
            layers[layer] = score
            all_details[layer] = details
            explanation.extend(notes)
            layer_available = details.get("available", True) is not False
            if layer_available:
                weighted_sum += score * weight
                available_weight += weight
            else:
                explanation.append(
                    f"{layer.upper()} layer skipped from weighting (no data)"
                )
                if abs(score - 50.0) < 1e-9:
                    layers[layer] = 50.0

        total = weighted_sum / available_weight if available_weight else 0.0

        # Changed fields: any layer below 100 contributes entries.
        if layers["tls"] < 100.0:
            changed.append("tls")
        if layers["http2"] < 100.0:
            changed.append("http2")
        if layers["headers"] < 100.0:
            changed.append("headers")

        if total >= 99.95:
            confidence = "high"
        elif available_weight < total_weight:
            confidence = "low"
        else:
            confidence = "medium"

        return SimilarityResult(
            total=round(total, 1),
            layers={k: round(v, 1) for k, v in layers.items()},
            details=all_details,
            changed_fields=changed,
            explanation=explanation,
            confidence=confidence,
        )
