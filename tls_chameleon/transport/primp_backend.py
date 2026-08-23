"""primp-based "native" backend for TLS-Chameleon (Phase 8).

Adopted per docs/NATIVE_BACKEND_RESEARCH.md (Stage A). This module is the
ONLY place in the package allowed to import ``primp``.

Design notes:
* primp's ``Client`` *is* the session; we wrap it in a thin adapter so it
  satisfies the package-wide duck-typed contract
  (``.request/.headers/.cookies/.close/.aclose``).
* Profile ``impersonate`` hints (curl-flavored, e.g. "chrome124") are mapped
  to the nearest available primp target. The mapping prefers the largest
  available version <= the hint, else the smallest >= the hint, within the
  same browser family. When no family match exists, NO impersonation is
  applied -- reported honestly rather than guessed.
* Version policy: primp>=1.3,<2 pinned in pyproject `[native]` extra;
  upgrade deliberately, this stack moves fast.
"""

import logging
from typing import Any, Dict, List, Optional

try:  # pragma: no cover - exercised implicitly by availability checks
    import primp
except Exception:  # pragma: no cover
    primp = None

from .base import (
    BackendUnavailableError,
    Capabilities,
    SessionConfig,
    Transport,
)

logger = logging.getLogger(__name__)

_verify_warned = False


def _warn_verify_ignored(target: str) -> None:
    """Warn once per process about the primp verify=False + impersonate bug."""
    global _verify_warned
    if not _verify_warned:
        _verify_warned = True
        logger.warning(
            "primp >=1.3,<2 ignores verify=False while an impersonation "
            "profile ('%s') is active; certificate verification stays "
            "ENABLED for the native backend. See "
            "docs/NATIVE_BACKEND_RESEARCH.md (open questions).",
            target,
        )

__all__ = ["PrimpTransport", "map_impersonate_hint"]

# Verified against primp 1.3.1 (see NATIVE_BACKEND_RESEARCH.md §3.1).
_AVAILABLE_TARGETS = {
    "chrome": (144, 145, 146, 147, 148),
    "firefox": (140, 146, 147, 148),
    "safari": (18, 26),      # safari_18.5 / safari_26(.x)
    "edge": (146, 147, 148),
}


def map_impersonate_hint(hint: Optional[str]) -> Optional[str]:
    """Translate a curl-style impersonate hint ("chrome124") to a primp
    target ("chrome_144"), or None when the family is unknown.

    Pure string mapping -- works whether or not primp is installed.
    """
    if not hint:
        return None
    text = str(hint).strip().lower()
    digits = "".join(ch for ch in text if ch.isdigit())
    target_major = int(digits[:4]) if digits[:4].isdigit() else None

    for family in _AVAILABLE_TARGETS:
        if text.startswith(family):
            versions = sorted(_AVAILABLE_TARGETS[family])
            if target_major is None:
                chosen = versions[-1]
            else:
                lower = [v for v in versions if v <= target_major]
                chosen = lower[-1] if lower else versions[0]
            suffix = ""
            if family == "safari" and chosen == 18:
                suffix = ".5"
            return f"{family}_{chosen}{suffix}"

    # Bare aliases primp itself understands.
    if text in ("chrome", "firefox", "safari", "edge", "opera", "random"):
        return text
    return None


class _CookieShim:
    """requests-flavored cookie surface over primp's URL-scoped API.

    primp requires ``cookie_store=True`` and scopes ``get_cookies(url)``
    to a single URL (raising when empty). We track visited URLs so
    save/export flows can present one merged, requests-style view.
    """

    def __init__(self, client: Any, urls: List[str]) -> None:
        self._client = client
        self._urls = urls          # shared with the session adapter
        self._local: Dict[str, str] = {}  # set() without URL context

    @staticmethod
    def _safe_get(client: Any, url: str) -> Dict[str, Any]:
        try:
            return dict(client.get_cookies(url) or {})
        except Exception:
            return {}

    def all_cookies(self) -> Dict[str, str]:
        merged: Dict[str, str] = {}
        for url in list(self._urls):
            for name, value in self._safe_get(self._client, url).items():
                merged[name] = value if isinstance(value, str) else str(value)
        for name, value in self._local.items():
            merged.setdefault(name, value)
        return merged

    def set(self, name: str, value: str, domain: str = "",
            path: str = "/") -> None:
        url = self._urls[-1] if self._urls else "https://127.0.0.1/"
        existing = self._safe_get(self._client, url)
        existing[name] = value
        try:
            self._client.set_cookies(url, existing)
            self._local.pop(name, None)
        except Exception:
            # Fall back to local-only storage so exports never lose data.
            self._local[name] = value

    def __len__(self) -> int:
        return len(self.all_cookies())

    def __iter__(self):
        store = self.all_cookies()
        for name, value in store.items():
            yield _CookieView(name, value)

    @property
    def jar(self) -> "_CookieShim":
        # client.save_cookies() probes .jar first; serving ourselves keeps
        # one iteration implementation.
        return self


class _CookieView:
    """Attribute-shaped cookie for the generic save/export code paths."""

    def __init__(self, name: str, value: Any) -> None:
        self.name = name
        if isinstance(value, dict):
            self.value = str(value.get("value", ""))
            self.domain = str(value.get("domain", "") or "")
            self.path = str(value.get("path", "/") or "/")
            self.secure = bool(value.get("secure", False))
        else:
            self.value = "" if value is None else str(value)
            self.domain = ""
            self.path = "/"
            self.secure = False
        self.expires = None


class _PrimpSession:
    """Duck-typed session adapter around ``primp.Client``/``AsyncClient``."""

    def __init__(self, client: Any, config: SessionConfig, *, async_: bool) -> None:
        self._client = client
        self._config = config
        self._async = async_
        self._urls_seen: List[str] = []
        self.headers: Dict[str, str] = dict(config.headers)
        self.cookies = _CookieShim(client, self._urls_seen)
        # primp closes via Rust Drop; expose no-op closers for symmetry.
        if async_:
            async def _aclose() -> None:
                return None
            self.aclose = _aclose
        else:
            self.close = lambda: None

    def request(self, method: str, url: str, **kwargs: Any) -> Any:
        kwargs.pop("stream", None)  # streaming flag: accepted, best-effort
        kwargs.pop("allow_redirects", None)
        headers = kwargs.pop("headers", None) or self.headers or None
        timeout = kwargs.pop("timeout", None)
        if timeout is not None:
            kwargs["timeout"] = timeout
        if url not in self._urls_seen:
            self._urls_seen.insert(0, url)
            del self._urls_seen[32:]
        return self._client.request(method.upper(), url,
                                    headers=headers, **kwargs)


class _PrimpAsyncSession(_PrimpSession):
    def __init__(self, client: Any, config: SessionConfig) -> None:
        super().__init__(client, config, async_=True)

    async def request(self, method: str, url: str, **kwargs: Any) -> Any:  # type: ignore[override]
        kwargs.pop("stream", None)
        kwargs.pop("allow_redirects", None)
        headers = kwargs.pop("headers", None) or self.headers or None
        timeout = kwargs.pop("timeout", None)
        if timeout is not None:
            kwargs["timeout"] = timeout
        return await self._client.request(method.upper(), url,
                                          headers=headers, **kwargs)


class PrimpTransport(Transport):
    """Backend built on the primp (rustls-fork) impersonation stack."""

    name = "native"
    capabilities = Capabilities(
        backend_name="native",
        tls_fingerprint_spoofing=True,
        # Cipher order follows the selected impersonation profile rather
        # than an arbitrary OpenSSL cipher string.
        custom_cipher_order=False,
        tls_customization=False,
        http1=True,
        http2=True,
        # Present in the crate stack but NOT verified end-to-end yet;
        # reported honestly until proven (research doc §6.5).
        http3=False,
        async_support=True,
        streaming=True,
        proxies=True,
    )

    @classmethod
    def is_available(cls) -> bool:
        return primp is not None

    @staticmethod
    def _single_proxy(proxies: Optional[Dict[str, str]]) -> Optional[str]:
        if not proxies:
            return None
        http_p = proxies.get("http") or proxies.get("http://")
        https_p = proxies.get("https") or proxies.get("https://")
        if http_p and https_p:
            return http_p if http_p == https_p else None
        return http_p or https_p

    @classmethod
    def _client_kwargs(cls, config: SessionConfig, *, async_: bool) -> Dict[str, Any]:
        kwargs: Dict[str, Any] = {
            "timeout": config.timeout or 30.0,
            "follow_redirects": True,
            "verify": config.verify,
            "cookie_store": True,  # required for get/set_cookies persistence
        }
        proxy_url = cls._single_proxy(config.proxies)
        if proxy_url:
            kwargs["proxy"] = proxy_url
        # Impersonation: profile-driven; unknown families stay unspoofed
        # (honest degradation, never a wrong-family guess).
        target = map_impersonate_hint(config.profile.get("impersonate"))
        if target:
            kwargs["impersonate"] = target
        else:
            logger.debug(
                "No primp impersonation target derived from profile '%s'",
                config.profile.get("name"),
            )
        # Known upstream limitation (verified against primp 1.3.1): when an
        # impersonation profile is active, primp rebuilds its rustls config
        # and IGNORES verify=False. We never weaken TLS silently (project
        # rule): keep verification ON and warn loudly instead.
        if not config.verify and target:
            kwargs["verify"] = True
            _warn_verify_ignored(target)
        return kwargs

    def create_session(self, config: SessionConfig) -> Any:
        self._ensure_available()
        client = primp.Client(**self._client_kwargs(config, async_=False))
        return _PrimpSession(client, config, async_=False)

    def create_async_session(self, config: SessionConfig) -> Any:
        self._ensure_available()
        client = primp.AsyncClient(**self._client_kwargs(config, async_=True))
        return _PrimpAsyncSession(client, config)

    def apply_proxies(self, session: Any, proxies: Optional[Dict[str, str]]) -> Any:
        stored = getattr(session, "_config", None)
        if stored is None or primp is None:
            return session
        new_config = stored.with_proxies(proxies)
        builder = (
            self.create_async_session
            if isinstance(session, _PrimpAsyncSession)
            else self.create_session
        )
        new_session = builder(new_config)
        # Migrate cookies best-effort.
        try:
            existing = session._client.get_cookies() or {}
            if existing:
                new_session._client.set_cookies(existing)
        except Exception as exc:  # pragma: no cover - defensive
            logger.debug(f"cookie migration failed: {exc}")
        return new_session

    @staticmethod
    def _ensure_available() -> None:
        if primp is None:
            raise BackendUnavailableError(
                "Backend 'native' requires primp. Install it with: "
                "pip install tls-chameleon[native]"
            )
