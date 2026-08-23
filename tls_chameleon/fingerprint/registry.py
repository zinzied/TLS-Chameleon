"""Fingerprint registry: lookup, search, add/remove, export/import.

Built-in profiles are resolved lazily from the gallery so no data is
duplicated. Custom fingerprints live in memory; use :meth:`export` /
:meth:`import_` to persist them as JSON. No cloud service is required.
"""

import json
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from .adapter import fingerprint_from_legacy
from .model import Fingerprint

__all__ = ["FingerprintRegistry"]


class FingerprintRegistry:
    """Thread-safe in-memory registry with lazy access to built-in profiles."""

    def __init__(self, include_builtin: bool = True) -> None:
        self._lock = threading.Lock()
        self._custom: Dict[str, Fingerprint] = {}
        self._include_builtin = include_builtin
        self._builtin_cache: Dict[str, Fingerprint] = {}

    # ------------------------------------------------------------------
    # Built-in access
    # ------------------------------------------------------------------

    def _builtin_names(self) -> List[str]:
        if not self._include_builtin:
            return []
        try:
            from ..fingerprint_gallery import FINGERPRINT_GALLERY

            return sorted(FINGERPRINT_GALLERY.keys())
        except Exception:  # pragma: no cover - defensive
            return []

    def _get_builtin(self, name: str) -> Optional[Fingerprint]:
        if not self._include_builtin:
            return None
        if name in self._builtin_cache:
            return self._builtin_cache[name]
        try:
            from ..fingerprint_gallery import FINGERPRINT_GALLERY, get_profile
        except Exception:  # pragma: no cover - defensive
            return None
        profile = FINGERPRINT_GALLERY.get(name) or get_profile(name)
        if not profile:
            return None
        fingerprint = fingerprint_from_legacy(profile, name=name)
        self._builtin_cache[name] = fingerprint
        return fingerprint

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def list(self) -> List[str]:
        """All registered fingerprint names (builtin + custom), sorted."""
        names = set(self._builtin_names())
        with self._lock:
            names.update(self._custom.keys())
        return sorted(names)

    def get(self, name: str) -> Fingerprint:
        """Get a fingerprint by name. Raises ``KeyError`` when unknown."""
        with self._lock:
            custom = self._custom.get(name)
        if custom is not None:
            return custom
        builtin = self._get_builtin(name)
        if builtin is not None:
            return builtin
        raise KeyError(f"Unknown fingerprint '{name}'")

    def has(self, name: str) -> bool:
        try:
            self.get(name)
            return True
        except KeyError:
            return False

    def search(
        self,
        browser: Optional[str] = None,
        platform: Optional[str] = None,
        source: Optional[str] = None,
    ) -> List[Fingerprint]:
        """Search by metadata fields (case-insensitive prefix match)."""
        results: List[Fingerprint] = []
        for name in self.list():
            fp = self.get(name)
            meta = fp.metadata
            if browser and not (meta.browser or "").lower().startswith(browser.lower()):
                continue
            if platform and not _platform_matches(fp, platform):
                continue
            if source and meta.source != source:
                continue
            results.append(fp)
        return results

    def add(self, fingerprint: Fingerprint, overwrite: bool = False) -> None:
        """Register a custom fingerprint."""
        if not isinstance(fingerprint, Fingerprint):
            raise TypeError("add() expects a Fingerprint instance")
        with self._lock:
            if fingerprint.name in self._custom and not overwrite:
                raise ValueError(
                    f"Fingerprint '{fingerprint.name}' already exists "
                    f"(use overwrite=True)"
                )
            self._custom[fingerprint.name] = fingerprint

    def remove(self, name: str) -> None:
        """Remove a *custom* fingerprint. Built-ins cannot be removed."""
        with self._lock:
            if name in self._custom:
                del self._custom[name]
                return
        if self.has(name):
            raise ValueError(f"'{name}' is a built-in profile and cannot be removed")
        raise KeyError(f"Unknown fingerprint '{name}'")

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def export(self, path: Optional[Union[str, Path]] = None, custom_only: bool = True) -> Dict[str, Any]:
        """Export fingerprints as JSON data (and optionally write to file)."""
        names = list(self._custom.keys()) if custom_only else self.list()
        payload = {
            "schema": "tls-chameleon.fingerprint-registry/1",
            "fingerprints": [self.get(n).to_dict() for n in sorted(names)],
        }
        if path is not None:
            Path(path).write_text(
                json.dumps(payload, indent=2), encoding="utf-8"
            )
        return payload

    def import_(
        self,
        data: Union[Dict[str, Any], str, Path],
        overwrite: bool = False,
    ) -> int:
        """Import fingerprints from a dict or JSON file. Returns count added."""
        if isinstance(data, (str, Path)):
            text = Path(data).read_text(encoding="utf-8")
            data = json.loads(text)
        entries = data.get("fingerprints") if isinstance(data, dict) else data
        if not isinstance(entries, list):
            raise ValueError("Malformed registry payload: expected 'fingerprints' list")
        count = 0
        for entry in entries:
            fingerprint = (
                entry
                if isinstance(entry, Fingerprint)
                else Fingerprint.from_dict(entry)
            )
            self.add(fingerprint, overwrite=overwrite)
            count += 1
        return count


def _platform_matches(fp: Fingerprint, platform: str) -> bool:
    hay = f"{fp.metadata.platform or ''} {fp.name}".lower()
    return platform.lower() in hay
