"""httpx backend for TLS-Chameleon.

This module is the ONLY place in the entire package allowed to import
``httpx``. It provides an honestly-degraded fallback: standard OpenSSL TLS
(no JA3 impersonation), configurable cipher order, HTTP/1.1 + optional
HTTP/2, and HTTP/3 only when the installed httpx actually supports it.
"""

import inspect
import logging
import ssl
from typing import Any, Dict, Optional, Tuple
from importlib.util import find_spec

try:  # pragma: no cover - exercised implicitly by availability checks
    import httpx
except Exception:  # pragma: no cover
    httpx = None

from .base import BackendUnavailableError, Capabilities, SessionConfig, Transport

logger = logging.getLogger(__name__)

__all__ = ["HttpxTransport"]


def _supports_http3() -> bool:
    """HTTP/3 is only reported when BOTH the kwarg and the h3 stack exist."""
    if httpx is None:
        return False
    try:
        has_kwarg = "http3" in inspect.signature(httpx.Client.__init__).parameters
    except (TypeError, ValueError):  # pragma: no cover
        return False
    return has_kwarg and find_spec("h3") is not None


def _normalize_single_proxy(proxies: Dict[str, str]) -> Optional[str]:
    """Collapse a requests-style proxy dict into one URL when possible."""
    http_p = proxies.get("http") or proxies.get("http://")
    https_p = proxies.get("https") or proxies.get("https://")
    if http_p and https_p:
        return http_p if http_p == https_p else None
    return http_p or https_p


class HttpxTransport(Transport):
    """Backend built on ``httpx.Client`` / ``httpx.AsyncClient``."""

    name = "httpx"
    capabilities = Capabilities(
        backend_name="httpx",
        # httpx uses the system OpenSSL handshake: no browser JA3 spoofing.
        tls_fingerprint_spoofing=False,
        custom_cipher_order=True,
        tls_customization=True,
        http1=True,
        http2=True,
        http3=_supports_http3(),
        async_support=True,
        streaming=True,
        proxies=True,
    )

    @classmethod
    def is_available(cls) -> bool:
        return httpx is not None

    @staticmethod
    def _build_ssl_context(config: SessionConfig) -> ssl.SSLContext:
        context = ssl.create_default_context()
        if not config.verify:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        if config.cipher_suites:
            try:
                context.set_ciphers(config.cipher_suites)
            except Exception as exc:  # pragma: no cover - OpenSSL version dependent
                logger.debug(f"Failed to set ciphers for httpx backend: {exc}")
        return context

    @staticmethod
    def _proxy_kwargs(config: SessionConfig) -> Dict[str, Any]:
        """Translate requests-style proxy dicts into modern httpx kwargs."""
        if not config.proxies:
            return {}
        single = _normalize_single_proxy(config.proxies)
        if single:
            return {"proxy": single}
        mounts: Dict[str, Any] = {}
        for scheme in ("http", "https"):
            url = config.proxies.get(scheme) or config.proxies.get(scheme + "://")
            if url and httpx is not None:
                mounts[scheme + "://"] = httpx.HTTPTransport(proxy=url)
        return {"mounts": mounts} if mounts else {}

    @classmethod
    def _client_kwargs(cls, config: SessionConfig, *, async_: bool) -> Dict[str, Any]:
        kwargs: Dict[str, Any] = {
            "timeout": config.timeout,
            "verify": cls._build_ssl_context(config),
            "follow_redirects": True,
            **cls._proxy_kwargs(config),
        }
        client_cls = httpx.AsyncClient if async_ else httpx.Client  # type: ignore[union-attr]
        params = inspect.signature(client_cls.__init__).parameters

        # http2/http3 kwargs are optional across httpx versions.
        if "http2" in params:
            kwargs["http2"] = bool(config.http2) if config.http2 is not None else False
        if "http3" in params and _supports_http3():
            kwargs["http3"] = bool(config.http3) if config.http3 is not None else False
        return kwargs

    def create_session(self, config: SessionConfig) -> Any:
        self._ensure_available()
        client = httpx.Client(**self._client_kwargs(config, async_=False))
        if config.headers:
            client.headers.update(config.headers)
        # Remember how this client was built so runtime proxy changes can
        # rebuild it faithfully (see adapt_request / apply_proxies).
        setattr(client, "_chameleon_config", config)
        return client

    def create_async_session(self, config: SessionConfig) -> Any:
        self._ensure_available()
        client = httpx.AsyncClient(**self._client_kwargs(config, async_=True))
        if config.headers:
            client.headers.update(config.headers)
        setattr(client, "_chameleon_config", config)
        return client

    # ------------------------------------------------------------------
    # Runtime reconfiguration helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _copy_cookies(source: Any, target: Any) -> None:
        """Best-effort cookie migration when a client must be rebuilt."""
        try:
            jar = getattr(source.cookies, "jar", source.cookies)
            for cookie in jar:
                target.cookies.set(
                    getattr(cookie, "name", ""),
                    getattr(cookie, "value", ""),
                    domain=getattr(cookie, "domain", "") or "",
                    path=getattr(cookie, "path", "/") or "/",
                )
        except Exception as exc:  # pragma: no cover - defensive
            logger.debug(f"Cookie migration between httpx clients failed: {exc}")

    def _rebuild_with_proxies(
        self, session: Any, proxies: Optional[Dict[str, str]], *, async_: bool
    ) -> Any:
        stored = getattr(session, "_chameleon_config", None)
        if stored is None or httpx is None:  # pragma: no cover - defensive
            return session
        new_config = stored.with_proxies(proxies)
        builder = self.create_async_session if async_ else self.create_session
        new_session = builder(new_config)
        self._copy_cookies(session, new_session)
        try:
            session.close()
        except Exception:  # pragma: no cover - best effort
            pass
        return new_session

    def adapt_request(
        self, session: Any, kwargs: Dict[str, Any]
    ) -> Tuple[Any, Dict[str, Any]]:
        # httpx >=0.28 rejects a per-request `proxies=` kwarg; translate it
        # into a rebuilt client instead of crashing mid-retry-loop.
        kwargs = dict(kwargs)
        proxies = kwargs.pop("proxies", None)
        if not proxies:
            return session, kwargs
        desired = {"proxy": _normalize_single_proxy(dict(proxies)) or proxies}
        current = self._proxy_kwargs(getattr(session, "_chameleon_config", SessionConfig()))
        if desired.get("proxy") == current.get("proxy") or desired["proxy"] == proxies:
            return session, kwargs
        return self._rebuild_with_proxies(session, dict(proxies), async_=False), kwargs

    async def adapt_request_async(
        self, session: Any, kwargs: Dict[str, Any]
    ) -> Tuple[Any, Dict[str, Any]]:
        kwargs = dict(kwargs)
        proxies = kwargs.pop("proxies", None)
        if not proxies:
            return session, kwargs
        current = self._proxy_kwargs(getattr(session, "_chameleon_config", SessionConfig()))
        if _normalize_single_proxy(dict(proxies)) == current.get("proxy"):
            return session, kwargs
        return await self._arebuild_with_proxies(session, dict(proxies)), kwargs

    async def _arebuild_with_proxies(self, session: Any, proxies: Dict[str, str]) -> Any:
        stored = getattr(session, "_chameleon_config", None)
        if stored is None or httpx is None:  # pragma: no cover - defensive
            return session
        new_session = self.create_async_session(stored.with_proxies(proxies))
        self._copy_cookies(session, new_session)
        aclose = getattr(session, "aclose", None)
        if aclose is not None:
            try:
                await aclose()
            except Exception:  # pragma: no cover - best effort
                pass
        return new_session

    def apply_proxies(self, session: Any, proxies: Optional[Dict[str, str]]) -> Any:
        return self._rebuild_with_proxies(session, proxies, async_=False)

    @staticmethod
    def _ensure_available() -> None:
        if httpx is None:
            raise BackendUnavailableError(
                "Backend 'httpx' requires httpx. Install it with: pip install httpx"
            )
