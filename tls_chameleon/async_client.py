from typing import Any, Dict, Optional, List, Callable, Union
import asyncio
import time
import random
import logging
from urllib.parse import urlparse

from .client import (
    _DOMAIN_MEMORY,
    _DOMAIN_MEMORY_LOCK,
    _select_engine,
    _cipher_list,
    ChameleonResponse
)
from .transport import SessionConfig, Transport, select_transport

from .profiles import DEFAULT_PROFILE, get_profile as legacy_get_profile
try:
    from .fingerprint_gallery import (  # noqa: F401  (availability probe)
        FINGERPRINT_GALLERY, get_profile as gallery_get_profile, randomize_profile,
    )
    HAS_GALLERY = True
except ImportError:
    HAS_GALLERY = False

logger = logging.getLogger(__name__)

class AsyncTLSChameleon:
    """
    Asynchronous version of TLSChameleon.

    Sessions are created through the pluggable transport layer
    (:mod:`tls_chameleon.transport`), so no backend-specific code lives here.
    """
    def __init__(
        self,
        fingerprint: Optional[str] = None,
        profile: Optional[str] = None,
        randomize: bool = False,
        http2_priority: Optional[str] = None,
        engine: Optional[str] = None,
        randomize_ciphers: bool = False,
        timeout: Optional[float] = 30.0,
        headers: Optional[Dict[str, str]] = None,
        proxies: Optional[Union[Dict[str, str], str]] = None,
        rotate_profiles: Optional[List[str]] = None,
        on_block: str = "rotate",
        max_retries: int = 2,
        retry_backoff_base: float = 1.0,
        retry_jitter: float = 0.3,
        block_detector: Optional[Callable[[Any], bool]] = None,
        on_retry: Optional[Callable[[int, Any, str], None]] = None,
        rate_limit: Optional[float] = None,
        site: Optional[str] = None,
        proxies_pool: Optional[List[str]] = None,
        header_order: Optional[List[str]] = None,
        http2: Optional[bool] = None,
        http3: Optional[bool] = None,
        verify: bool = True,
        ghost_mode: bool = False,
        adaptive: bool = True,
        random_seed: Optional[Any] = None,
        seed: Optional[Any] = None,
    ) -> None:
        self._explicit_profile = False
        if profile:
            self.profile_name = profile
            self._explicit_profile = True
        elif fingerprint:
            self.profile_name = fingerprint
            self._explicit_profile = True
        else:
            self.profile_name = DEFAULT_PROFILE
            
        self.randomize = randomize
        self.http2_priority = http2_priority
        self.engine = _select_engine(engine)
        self.randomize_ciphers = randomize_ciphers
        self.timeout = timeout
        self.rotate_profiles = rotate_profiles
        self.on_block = on_block
        self.max_retries = max_retries
        self.retry_backoff_base = retry_backoff_base
        self.retry_jitter = retry_jitter
        self.block_detector = block_detector
        self.on_retry = on_retry
        self.rate_limit = rate_limit
        self._rate_limit_last: Dict[str, float] = {}
        self.proxies_pool = proxies_pool
        self.header_order = header_order
        self.http2 = http2
        self.http3 = http3
        self.verify = verify
        self.ghost_mode = ghost_mode
        self.adaptive = adaptive
        # ``seed`` is a documented alias of ``random_seed`` (3.1).
        if random_seed is None and seed is not None:
            random_seed = seed
        self.random_seed = random_seed
        if random_seed is not None:
            from .randomizer import derive_seed_rng

            self._rng = derive_seed_rng(random_seed)
        else:
            self._rng = None
        self.headers = headers or {}

        # Pluggable transport (resolved from the engine preference)
        self._transport: Transport = select_transport(engine)

        if proxies and isinstance(proxies, str):
            self.proxies = {"http": proxies, "https": proxies}
        else:
            self.proxies = proxies or {}
            
        self.session = None

    @property
    def capabilities(self):
        """Honest capability report for the backend currently in use."""
        return self._transport.capabilities

    def _get_profile(self) -> Dict[str, Any]:
        p = gallery_get_profile(self.profile_name) if HAS_GALLERY else None
        if not p:
            p = legacy_get_profile(self.profile_name)
        if not p:
            p = legacy_get_profile(DEFAULT_PROFILE)
        return p or {}

    def _init_session(self) -> None:
        if self.session:
            if hasattr(self.session, "aclose"):
                pass # Need async close, handled by caller or context manager
            elif hasattr(self.session, "close"):
                self.session.close()

        profile = self._get_profile()
        if self.randomize and HAS_GALLERY:
            try:
                profile = randomize_profile(profile, rng=self._rng)
            except Exception:
                pass

        # Re-resolve transport from the current engine preference (mirrors sync)
        self._transport = select_transport(self.engine)
        self.engine = self._transport.name

        config = SessionConfig(
            profile=profile,
            cipher_suites=_cipher_list(profile, self.randomize_ciphers),
            timeout=self.timeout,
            verify=self.verify,
            proxies=self.proxies or None,
            headers=dict(self.headers),
            http2=self.http2,
            http3=self.http3,
        )
        self.session = self._transport.create_async_session(config)

    async def __aenter__(self):
        self._init_session()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            aclose = getattr(self.session, "aclose", None)
            if aclose is not None:
                await aclose()
            else:
                close = getattr(self.session, "close", None)
                if close is not None:
                    result = close()
                    # curl_cffi's AsyncSession.close() returns a coroutine.
                    if asyncio.iscoroutine(result):
                        await result

    async def request(self, method: str, url: str, **kwargs: Any):
        if not self.session:
            self._init_session()

        # trace=True is a TLS-Chameleon extension, not a backend kwarg.
        want_trace = bool(kwargs.pop("trace", False))
        started = time.perf_counter()

        domain = urlparse(url).netloc
        
        if self.rate_limit and self.rate_limit > 0:
            import asyncio
            min_interval = 1.0 / self.rate_limit
            last_time = self._rate_limit_last.get(domain, 0)
            elapsed = time.time() - last_time
            if elapsed < min_interval:
                await asyncio.sleep(min_interval - elapsed)
            self._rate_limit_last[domain] = time.time()

        attempt = 1
        while True:
            try:
                self.session, kwargs = await self._transport.adapt_request_async(
                    self.session, dict(kwargs)
                )
                resp = await self.session.request(method, url, **kwargs)
                    
                wrapped_resp = ChameleonResponse(resp)
                if want_trace:
                    wrapped_resp._trace = self._build_trace(
                        method, url, resp,
                        request_headers=dict(kwargs.get("headers") or {}),
                        total_ms=(time.perf_counter() - started) * 1000.0,
                    )
                if getattr(resp, "status_code", 500) < 400:
                    if self.adaptive:
                        with _DOMAIN_MEMORY_LOCK:
                            _DOMAIN_MEMORY[domain] = self.profile_name
                    return wrapped_resp
                    
                # Very basic block check
                if getattr(resp, "status_code", None) in {403, 429}:
                    pass # treat as blocked
                else:
                    return wrapped_resp
                    
            except Exception as e:
                if attempt >= self.max_retries:
                    raise e
                    
            if attempt >= self.max_retries:
                return wrapped_resp if 'wrapped_resp' in locals() else None

            attempt += 1
            if self.rotate_profiles:
                rand = self._rng if self._rng is not None else random
                idx = rand.randint(0, len(self.rotate_profiles)-1)
                self.profile_name = self.rotate_profiles[idx]
                self._init_session()
                
            import asyncio
            delay = self.retry_backoff_base * (2 ** (attempt - 1))
            await asyncio.sleep(delay + random.uniform(0, self.retry_jitter))

    def _build_trace(self, method: str, url: str, response: Any,
                     request_headers: Dict[str, str],
                     total_ms: float):
        """Build a NetworkTrace for the just-completed request (lazy import)."""
        from .diagnostics.trace import collect_trace

        return collect_trace(
            method,
            url,
            response,
            backend=getattr(self._transport, "name", None),
            profile=self.profile_name,
            request_headers=request_headers or dict(self.headers),
            total_ms=total_ms,
        )

    async def get(self, url: str, **kwargs: Any):
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs: Any):
        return await self.request("POST", url, **kwargs)

    async def put(self, url: str, **kwargs: Any):
        return await self.request("PUT", url, **kwargs)

    async def delete(self, url: str, **kwargs: Any):
        return await self.request("DELETE", url, **kwargs)

    async def head(self, url: str, **kwargs: Any):
        return await self.request("HEAD", url, **kwargs)

    async def patch(self, url: str, **kwargs: Any):
        return await self.request("PATCH", url, **kwargs)

    async def options(self, url: str, **kwargs: Any):
        return await self.request("OPTIONS", url, **kwargs)

AsyncSession = AsyncTLSChameleon


class AsyncChameleon(AsyncTLSChameleon):
    """
    High-level async entry point (v3.1). Drop-in subclass of
    :class:`AsyncTLSChameleon`; accepts ``backend=`` (alias of ``engine``)
    and ``seed=`` (alias of ``random_seed``).
    """

    def __init__(self, profile=None, backend=None, seed=None, **kwargs):
        if backend is not None and "engine" not in kwargs:
            kwargs["engine"] = backend
        if seed is not None and kwargs.get("random_seed") is None:
            kwargs["random_seed"] = seed
        super().__init__(profile=profile, **kwargs)
