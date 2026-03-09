from typing import Any, Dict, Optional, List, Callable, Union
import ssl
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

from .profiles import DEFAULT_PROFILE, get_profile as legacy_get_profile
try:
    from .fingerprint_gallery import FINGERPRINT_GALLERY, get_profile as gallery_get_profile, randomize_profile
    HAS_GALLERY = True
except ImportError:
    HAS_GALLERY = False

try:
    from curl_cffi import requests as crequests
except Exception:
    crequests = None

try:
    import httpx
except Exception:
    httpx = None

logger = logging.getLogger(__name__)

class AsyncTLSChameleon:
    """
    Asynchronous version of TLSChameleon using curl_cffi.requests.AsyncSession 
    or httpx.AsyncClient.
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
        verify: bool = True,
        ghost_mode: bool = False,
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
        self.verify = verify
        self.ghost_mode = ghost_mode
        self.headers = headers or {}
        
        if proxies and isinstance(proxies, str):
            self.proxies = {"http": proxies, "https": proxies}
        else:
            self.proxies = proxies or {}
            
        self.session = None

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
                profile = randomize_profile(profile)
            except Exception:
                pass

        if self.engine == "curl" and crequests is not None:
            impersonate = profile.get("impersonate", "chrome120")
            self.session = crequests.AsyncSession(
                impersonate=impersonate,
                timeout=self.timeout,
                verify=self.verify
            )
            if self.proxies:
                self.session.proxies = self.proxies
        elif self.engine == "httpx" and httpx is not None:
            ssl_context = ssl.create_default_context()
            if not self.verify:
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE
            
            cipher_str = _cipher_list(profile, self.randomize_ciphers)
            if cipher_str:
                try:
                    ssl_context.set_ciphers(cipher_str)
                except Exception:
                    pass
                    
            self.session = httpx.AsyncClient(
                http2=bool(self.http2) if self.http2 is not None else False,
                timeout=self.timeout,
                verify=ssl_context,
                follow_redirects=True
            )
            if self.proxies:
                self.session.proxies = {k: v for k, v in self.proxies.items()}
        else:
            raise RuntimeError(f"Engine {self.engine} not available.")

    async def __aenter__(self):
        self._init_session()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            if hasattr(self.session, "aclose"):
                await self.session.aclose()
            elif hasattr(self.session, "close"):
                self.session.close()

    async def request(self, method: str, url: str, **kwargs: Any):
        if not self.session:
            self._init_session()
            
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
                if self.engine == "httpx" and httpx is not None:
                    resp = await self.session.request(method, url, **kwargs)
                else:
                    resp = await getattr(self.session, method.lower())(url, **kwargs)
                    
                wrapped_resp = ChameleonResponse(resp)
                if getattr(resp, "status_code", 500) < 400:
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
                idx = random.randint(0, len(self.rotate_profiles)-1)
                self.profile_name = self.rotate_profiles[idx]
                self._init_session()
                
            import asyncio
            delay = self.retry_backoff_base * (2 ** (attempt - 1))
            await asyncio.sleep(delay + random.uniform(0, self.retry_jitter))

    async def get(self, url: str, **kwargs: Any):
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs: Any):
        return await self.request("POST", url, **kwargs)

AsyncSession = AsyncTLSChameleon
