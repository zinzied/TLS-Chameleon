"""Core transport interface for TLS-Chameleon.

A *transport* (backend) knows how to turn a :class:`SessionConfig` into a
live session object and how to dispatch requests on it. Everything above
this layer (fingerprint logic, profile handling, retries, domain memory)
must stay backend-agnostic.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field, replace
from typing import Any, ClassVar, Dict, Optional

__all__ = [
    "BackendUnavailableError",
    "Capabilities",
    "SessionConfig",
    "Transport",
]


class BackendUnavailableError(RuntimeError):
    """Raised when no requested backend is importable/usable."""


@dataclass(frozen=True)
class Capabilities:
    """Honest, per-backend feature report.

    Every flag must reflect what the backend *actually* exercises in this
    library -- never what the underlying dependency could theoretically do.
    """

    backend_name: str
    # Real TLS-level fingerprint impersonation (JA3 controlled by backend).
    tls_fingerprint_spoofing: bool = False
    # Custom cipher-suite ordering can be applied to the TLS handshake.
    custom_cipher_order: bool = False
    http2: bool = False
    http3: bool = False
    async_support: bool = False
    streaming: bool = False
    proxies: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "backend": self.backend_name,
            "tls_fingerprint_spoofing": self.tls_fingerprint_spoofing,
            "custom_cipher_order": self.custom_cipher_order,
            "http2": self.http2,
            "http3": self.http3,
            "async_support": self.async_support,
            "streaming": self.streaming,
            "proxies": self.proxies,
        }


@dataclass
class SessionConfig:
    """Backend-neutral description of a session to create.

    ``cipher_suites`` is an OpenSSL-format cipher list string computed by the
    fingerprint layer; backends decide how (or whether) they can apply it.
    """

    profile: Dict[str, Any] = field(default_factory=dict)
    cipher_suites: Optional[str] = None
    timeout: Optional[float] = 30.0
    verify: bool = True
    proxies: Optional[Dict[str, str]] = None
    headers: Dict[str, str] = field(default_factory=dict)
    http2: Optional[bool] = None
    http3: Optional[bool] = None

    def with_proxies(self, proxies: Optional[Dict[str, str]]) -> "SessionConfig":
        return replace(self, proxies=proxies)


class Transport(ABC):
    """Base class every TLS-Chameleon backend must implement.

    Session objects returned by ``create_session`` / ``create_async_session``
    must duck-type the following surface (both bundled backends already do):

        .request(method, url, **kwargs) -> response
        .headers                        -> mutable mapping
        .cookies                        -> cookie container with .set()
        .close()                        -> sync close
        .aclose()                       -> async close (async sessions only)

    The rest of tls_chameleon must only rely on this duck-typed surface --
    never on backend-specific attributes.
    """

    #: Short backend identifier ("curl", "httpx", ...). Persisted in
    #: export_session() state, so values are part of the public contract.
    name: ClassVar[str] = "abstract"

    #: Static honest capability report for this backend class.
    capabilities: ClassVar[Capabilities]

    @classmethod
    @abstractmethod
    def is_available(cls) -> bool:
        """True if the backing dependency can be imported right now."""

    @abstractmethod
    def create_session(self, config: SessionConfig) -> Any:
        """Create a synchronous session from a config."""

    def create_async_session(self, config: SessionConfig) -> Any:
        raise NotImplementedError(
            f"Backend '{self.name}' does not support async sessions."
        )

    # ------------------------------------------------------------------
    # Request-level hooks (override when a backend needs kwarg translation)
    # ------------------------------------------------------------------

    def adapt_request(
        self, session: Any, kwargs: Dict[str, Any]
    ) -> "tuple[Any, Dict[str, Any]]":
        """Translate generic request kwargs into backend-specific ones.

        Returns ``(session, kwargs)``. Backends may return a *new* session
        object if kwargs force a reconfiguration (e.g. per-request proxies on
        httpx). Default implementation passes everything through untouched.
        """
        return session, kwargs

    async def adapt_request_async(
        self, session: Any, kwargs: Dict[str, Any]
    ) -> "tuple[Any, Dict[str, Any]]":
        """Async variant of :meth:`adapt_request`."""
        return self.adapt_request(session, kwargs)

    def apply_proxies(self, session: Any, proxies: Optional[Dict[str, str]]) -> Any:
        """Make ``session`` use ``proxies`` going forward.

        May mutate or rebuild the session; returns the session to keep using.
        """
        raise NotImplementedError(
            f"Backend '{self.name}' does not support runtime proxy changes."
        )
