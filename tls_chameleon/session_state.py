"""Backend-independent session state.

Separates *what TLS-Chameleon remembers about a session* (profile choice,
headers, cookies, safe adaptive metadata) from backend-internal objects.
Serialized form contains only plain JSON-safe values -- never backend
objects (curl handles, rustls clients, ...).
"""

from dataclasses import asdict, dataclass, field, replace
from typing import Any, Dict, List, Optional

__all__ = ["SessionState", "SCHEMA"]

SCHEMA = "tls-chameleon.session-state/1"


@dataclass
class SessionState:
    """Portable session snapshot (see ``export_session``/``import_session``)."""

    profile_name: Optional[str] = None
    engine: Optional[str] = None
    proxies: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    rotate_index: int = -1
    proxy_index: int = -1
    http3: bool = False
    adaptive: bool = True
    random_seed: Optional[Any] = None
    cookies: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SessionState":
        known = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in data.items() if k in known})

    def evolve(self, **changes: Any) -> "SessionState":
        return replace(self, **changes)
