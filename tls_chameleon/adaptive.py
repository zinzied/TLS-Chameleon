"""Adaptive engine: explainable per-domain profile memory.

The memory remembers which fingerprint profile last *succeeded* for a
domain so future sessions can start with a known-good choice.

Guarantees:
* bounded storage (LRU eviction beyond ``max_entries``),
* optional TTL expiration (``ttl_seconds``),
* thread-safe (single RLock guards data + metadata),
* stores ONLY ``domain -> profile name`` plus non-sensitive metadata --
  never credentials, headers, cookies, or payloads,
* fully disableable at the client level (``adaptive=False``).
"""

import threading
import time
from collections import OrderedDict
from typing import Any, Dict, Optional

__all__ = ["DomainMemory", "DEFAULT_DOMAIN_MEMORY_MAX"]

DEFAULT_DOMAIN_MEMORY_MAX = 1000


class DomainMemory:
    """Bounded, expiring, thread-safe ``domain -> profile`` memory."""

    def __init__(
        self,
        max_entries: int = DEFAULT_DOMAIN_MEMORY_MAX,
        ttl_seconds: Optional[float] = None,
    ) -> None:
        if max_entries < 1:
            raise ValueError("max_entries must be >= 1")
        self.max_entries = int(max_entries)
        self.ttl_seconds = ttl_seconds
        # Legacy-visible storage: plain OrderedDict mapping domain->profile.
        # Older code (and tests) may manipulate it directly under .lock.
        self._profiles: OrderedDict = OrderedDict()
        self._meta: Dict[str, Dict[str, Any]] = {}
        self.lock = threading.RLock()

    # ------------------------------------------------------------------
    # Legacy compatibility surface
    # ------------------------------------------------------------------

    @property
    def data(self) -> OrderedDict:
        """Direct OrderedDict view kept for backward compatibility."""
        return self._profiles

    # ------------------------------------------------------------------
    # Core API
    # ------------------------------------------------------------------

    def remember(
        self, domain: str, profile_name: str, reason: str = "success"
    ) -> None:
        """Record that ``profile_name`` worked for ``domain``."""
        now = time.time()
        with self.lock:
            previous = self._meta.get(domain)
            self._profiles[domain] = profile_name
            self._profiles.move_to_end(domain)
            self._meta[domain] = {
                "profile": profile_name,
                "reason": reason,
                "first_seen": previous["first_seen"] if previous else now,
                "last_used": now,
                "successes": (previous["successes"] + 1) if previous else 1,
            }
            while len(self._profiles) > self.max_entries:
                evicted_domain, _ = self._profiles.popitem(last=False)
                self._meta.pop(evicted_domain, None)

    def lookup(self, domain: str) -> Optional[str]:
        """Profile name for ``domain``, honoring TTL and LRU recency."""
        now = time.time()
        with self.lock:
            profile = self._profiles.get(domain)
            if profile is None:
                return None
            meta = self._meta.get(domain)
            if (
                self.ttl_seconds is not None
                and meta
                and now - float(meta["last_used"]) > self.ttl_seconds
            ):
                del self._profiles[domain]
                self._meta.pop(domain, None)
                return None
            self._profiles.move_to_end(domain)
            return profile

    def forget(self, domain: str) -> None:
        with self.lock:
            self._profiles.pop(domain, None)
            self._meta.pop(domain, None)

    def clear(self) -> None:
        with self.lock:
            self._profiles.clear()
            self._meta.clear()

    # ------------------------------------------------------------------
    # Explainability
    # ------------------------------------------------------------------

    def explain(self, domain: str) -> Dict[str, Any]:
        """Explain what the memory would choose for ``domain`` and why.

        Returns ``{"profile", "reason", "confidence", "last_used"}``.
        ``confidence`` is a heuristic in [0..1] based on observed successes
        and recency -- it expresses familiarity, not any guarantee.
        """
        now = time.time()
        with self.lock:
            profile = self.lookup(domain)
            if profile is None:
                return {
                    "profile": None,
                    "reason": "no history for this domain",
                    "confidence": 0.0,
                    "last_used": None,
                }
            meta = self._meta.get(domain, {})
            age = max(0.0, now - float(meta.get("last_used", now)))
            successes = int(meta.get("successes", 1))
            confidence = min(1.0, successes / 5.0)
            if self.ttl_seconds:
                confidence *= max(0.0, 1.0 - age / float(self.ttl_seconds))
            return {
                "profile": profile,
                "reason": f"learned after {successes} successful "
                          f"request(s); {age:.0f}s ago",
                "confidence": round(confidence, 2),
                "last_used": meta.get("last_used"),
            }

    def stats(self) -> Dict[str, Any]:
        with self.lock:
            return {
                "entries": len(self._profiles),
                "max_entries": self.max_entries,
                "ttl_seconds": self.ttl_seconds,
                "oldest_age_seconds": (
                    round(time.time() - min(m["first_seen"] for m in self._meta.values()), 3)
                    if self._meta else 0.0
                ),
            }
