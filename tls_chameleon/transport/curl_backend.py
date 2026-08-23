"""curl_cffi backend for TLS-Chameleon.

This module is the ONLY place in the entire package allowed to import
``curl_cffi``. Everything curl-specific -- impersonation mapping, cipher
options, session quirks -- must stay inside this file.
"""

import logging
from typing import Any, Dict, Optional

try:  # pragma: no cover - exercised implicitly by availability checks
    from curl_cffi import requests as crequests
    from curl_cffi import curl as ccurl
except Exception:  # pragma: no cover
    crequests = None
    ccurl = None

from .base import BackendUnavailableError, Capabilities, SessionConfig, Transport

logger = logging.getLogger(__name__)

__all__ = ["CurlTransport"]


def _ssl_cipher_list_option() -> Optional[int]:
    """Return the numeric curl option id for SSL cipher lists.

    curl_cffi >= 0.7 exposes ``CurlOpt.SSL_CIPHER_LIST``; very old versions
    exposed ``curl.CURLOPT_SSL_CIPHER_LIST`` instead. Returns None when the
    installed version supports neither (the override then no-ops honestly).
    """
    try:
        from curl_cffi import CurlOpt

        option = getattr(CurlOpt, "SSL_CIPHER_LIST", None)
        if option is not None:
            return int(option)
    except Exception:
        pass
    return getattr(ccurl, "CURLOPT_SSL_CIPHER_LIST", None)


class CurlTransport(Transport):
    """Backend built on ``curl_cffi.requests.Session``.

    Provides real TLS-level fingerprint impersonation via the ``impersonate``
    hint stored on profiles.
    """

    name = "curl"
    capabilities = Capabilities(
        backend_name="curl",
        tls_fingerprint_spoofing=True,
        custom_cipher_order=True,  # applied when CurlOpt.SSL_CIPHER_LIST exists
        tls_customization=True,
        http1=True,
        http2=True,
        websocket=True,  # curl_cffi >= 0.13 exposes WebSocket support
        # HTTP/3 exists in recent libcurl builds but is NOT exercised by this
        # backend yet; report it honestly as unsupported.
        http3=False,
        async_support=True,
        streaming=True,
        proxies=True,
    )

    @classmethod
    def is_available(cls) -> bool:
        return crequests is not None

    @staticmethod
    def _build_options(config: SessionConfig) -> Dict[int, str]:
        options: Dict[int, str] = {}
        if config.cipher_suites:
            option_id = _ssl_cipher_list_option()
            if option_id is not None:
                options[option_id] = config.cipher_suites
            else:
                logger.debug(
                    "Installed curl_cffi has no SSL_CIPHER_LIST option; "
                    "custom cipher order will not be applied."
                )
        return options

    @staticmethod
    def _common_kwargs(config: SessionConfig) -> Dict[str, Any]:
        kwargs: Dict[str, Any] = {
            "impersonate": config.profile.get("impersonate"),
            "timeout": config.timeout,
        }
        curl_options = CurlTransport._build_options(config)
        if curl_options:
            kwargs["curl_options"] = curl_options
        if not config.verify:
            kwargs["verify"] = False
        return kwargs

    def create_session(self, config: SessionConfig) -> Any:
        self._ensure_available()
        session = crequests.Session(**self._common_kwargs(config))
        if config.headers:
            session.headers.update(config.headers)
        if config.proxies:
            session.proxies.update(config.proxies)
        session.verify = config.verify
        return session

    def create_async_session(self, config: SessionConfig) -> Any:
        self._ensure_available()
        session = crequests.AsyncSession(**self._common_kwargs(config))
        if config.headers:
            session.headers.update(config.headers)
        if config.proxies:
            session.proxies.update(config.proxies)
        session.verify = config.verify
        return session

    def apply_proxies(self, session: Any, proxies: Optional[Dict[str, str]]) -> Any:
        # curl_cffi sessions keep a mutable .proxies mapping.
        try:
            session.proxies.update(proxies or {})
        except AttributeError:
            pass
        return session

    @staticmethod
    def _ensure_available() -> None:
        if crequests is None:
            raise BackendUnavailableError(
                "Backend 'curl' requires curl_cffi. Install it with: "
                "pip install tls-chameleon[curl]"
            )
