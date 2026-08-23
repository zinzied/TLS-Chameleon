"""Backend selection for TLS-Chameleon.

Selection order and fallback semantics deliberately match the legacy
``_select_engine`` behavior so existing code keeps working:

* ``None`` / unknown name  -> first available backend by preference order.
* Known but unavailable    -> warn once, fall back to next available.
* Nothing available        -> raise ``BackendUnavailableError``.

Third-party backends can plug in via :func:`register_transport`.
"""

import logging
from typing import Dict, List, Optional

from .base import BackendUnavailableError, Transport
from .curl_backend import CurlTransport
from .httpx_backend import HttpxTransport

try:
    from .primp_backend import PrimpTransport
except Exception:  # pragma: no cover - defensive
    PrimpTransport = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)

__all__ = ["select_transport", "available_backends", "register_transport", "_warned"]

#: Preference order for automatic selection. ``curl`` first preserves the
#: historical default (real TLS fingerprint impersonation when possible).
#: ``native`` (primp/rustls stack) outranks httpx because it adds real TLS
#: fingerprint spoofing; httpx remains the honest last resort.
PREFERENCE_ORDER: List[str] = ["curl", "native", "httpx"]

#: Convenience aliases accepted by select_transport.
_ALIASES: Dict[str, str] = {"primp": "native"}

_REGISTRY: Dict[str, Transport] = {}
_warned = set()


def register_transport(transport_class: type) -> type:
    """Register a custom transport class (decorator form)."""
    instance = transport_class()
    _REGISTRY[instance.name] = instance
    return transport_class


# Built-in registry
_REGISTRY[CurlTransport.name] = CurlTransport()
_REGISTRY[HttpxTransport.name] = HttpxTransport()
if PrimpTransport is not None:
    _REGISTRY[PrimpTransport.name] = PrimpTransport()


def available_backends() -> List[str]:
    """Names of all backends that can currently be used."""
    return [name for name, backend in _REGISTRY.items() if backend.is_available()]


def _warn_once(key: str, message: str) -> None:
    if key not in _warned:
        _warned.add(key)
        logger.warning(message)


def select_transport(preferred: Optional[str] = None) -> Transport:
    """Return a usable transport instance.

    Args:
        preferred: ``"curl"``, ``"native"`` (alias ``"primp"``), ``"httpx"``,
            a registered custom backend name, or ``None`` for automatic
            selection.

    Raises:
        BackendUnavailableError: when the preferred backend is explicitly
            requested but nothing usable is installed at all.
    """
    if preferred in _ALIASES:
        preferred = _ALIASES[preferred]
    available = available_backends()

    if preferred is None or preferred not in _REGISTRY:
        if preferred is not None:
            _warn_once(
                f"unknown:{preferred}",
                f"Unknown engine '{preferred}'; falling back to automatic "
                f"selection {available}.",
            )
        # Preference order wins over registration order for auto-selection.
        for name in PREFERENCE_ORDER:
            if name in available:
                return _REGISTRY[name]
        for name in available:
            return _REGISTRY[name]
        raise BackendUnavailableError(
            "No networking backend available. Install one of: "
            "pip install tls-chameleon[curl]  (or)  pip install httpx"
        )

    backend = _REGISTRY[preferred]
    if backend.is_available():
        return backend

    fallback = available_backends()
    if not fallback:
        raise BackendUnavailableError(
            f"Backend '{preferred}' is not installed and no alternative "
            f"backend is available. Install it with: pip install "
            f"tls-chameleon[curl]  (or)  pip install httpx"
        )
    _warn_once(
        f"fallback:{preferred}",
        f"Backend '{preferred}' is not available; falling back to "
        f"'{fallback[0]}'. Install it with: pip install tls-chameleon[curl]",
    )
    return _REGISTRY[fallback[0]]
