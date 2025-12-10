import random
import ssl
import time
from typing import Any, Dict, Optional, List, Callable

from .profiles import PROFILES, DEFAULT_PROFILE

try:
    from curl_cffi import requests as crequests
    from curl_cffi import curl as ccurl
except Exception:
    crequests = None
    ccurl = None

try:
    import httpx
except Exception:
    httpx = None


def _select_engine(preferred: Optional[str]) -> str:
    if preferred in ("curl", "httpx"):
        if preferred == "curl" and crequests is None:
            return "httpx"
        if preferred == "httpx" and httpx is None:
            return "curl" if crequests is not None else "httpx"
        return preferred
    if crequests is not None:
        return "curl"
    return "httpx"


def _get_profile(name: Optional[str]) -> Dict[str, Any]:
    if not name:
        name = DEFAULT_PROFILE
    return PROFILES.get(name, PROFILES[DEFAULT_PROFILE])


def _cipher_list(profile: Dict[str, Any], randomize: bool) -> Optional[str]:
    ciphers = list(profile.get("tls12_ciphers") or [])
    if not ciphers:
        return None
    if randomize:
        random.shuffle(ciphers)
    return ":".join(ciphers)


class TLSChameleon:
    def __init__(
        self,
        fingerprint: Optional[str] = None,
        engine: Optional[str] = None,
        randomize_ciphers: bool = False,
        timeout: Optional[float] = 30.0,
        headers: Optional[Dict[str, str]] = None,
        proxies: Optional[Dict[str, str]] = None,
        rotate_profiles: Optional[List[str]] = None,
        on_block: str = "rotate",
        max_retries: int = 2,
        retry_backoff_base: float = 1.0,
        retry_jitter: float = 0.3,
        block_detector: Optional[Callable[[Any], bool]] = None,
        site: Optional[str] = None,
        proxies_pool: Optional[List[str]] = None,
        header_order: Optional[List[str]] = None,
        http2: Optional[bool] = None,
    ) -> None:
        self._profile_name = fingerprint if fingerprint in PROFILES else DEFAULT_PROFILE
        self.profile = _get_profile(self._profile_name)
        self.engine = _select_engine(engine)
        self.randomize_ciphers = randomize_ciphers
        self.timeout = timeout
        self.proxies = proxies or {}
        base_headers = {"User-Agent": self.profile.get("user_agent") or ""}
        if headers:
            base_headers.update(headers)
        self.headers = base_headers
        self.rotate_profiles = rotate_profiles
        self.on_block = on_block
        self.max_retries = max_retries
        self.retry_backoff_base = retry_backoff_base
        self.retry_jitter = retry_jitter
        self._block_detector = block_detector
        self._rotate_index = -1
        self._proxy_index = -1
        self.proxies_pool = proxies_pool
        self.header_order = header_order
        self.http2 = http2
        if site:
            self._apply_site_preset(site)
        if self.engine == "httpx" and httpx is not None:
            try:
                self._httpx_client = httpx.Client(http2=bool(self.http2)) if self.http2 is not None else httpx.Client()
            except Exception:
                self._httpx_client = httpx.Client()
        else:
            self._httpx_client = None

    def request(self, method: str, url: str, **kwargs: Any):
        headers = kwargs.pop("headers", None) or {}
        if headers:
            merged = dict(self.headers)
            merged.update(headers)
            headers = merged
        else:
            headers = self.headers
        attempt = 0
        while True:
            if self.engine == "curl" and crequests is not None:
                curl_kwargs: Dict[str, Any] = {}
                impersonate = self.profile.get("impersonate")
                if impersonate:
                    curl_kwargs["impersonate"] = impersonate
                cipher_str = _cipher_list(self.profile, self.randomize_ciphers)
                curl_options: Dict[str, Any] = {}
                if cipher_str and ccurl is not None and hasattr(ccurl, "CURLOPT_SSL_CIPHER_LIST"):
                    curl_options[ccurl.CURLOPT_SSL_CIPHER_LIST] = cipher_str
                hdrs = self._apply_header_order(headers)
                proxy = self._current_proxy()
                resp = crequests.request(
                    method,
                    url,
                    headers=hdrs,
                    timeout=self.timeout,
                    proxies=proxy,
                    curl_options=curl_options or None,
                    **curl_kwargs,
                    **kwargs,
                )
            else:
                if httpx is None:
                    raise RuntimeError("httpx is required when curl_cffi is unavailable")
                ctx = ssl.create_default_context()
                cipher_str = _cipher_list(self.profile, self.randomize_ciphers)
                if cipher_str:
                    try:
                        ctx.set_ciphers(cipher_str)
                    except Exception:
                        pass
                transport = httpx.HTTPTransport(retries=0)
                hdrs = self._apply_header_order(headers)
                proxy = self._current_proxy()
                httpx_proxies = self._normalize_proxy_for_httpx(proxy)
                if httpx_proxies is not None:
                    resp = httpx.request(
                        method,
                        url,
                        headers=hdrs,
                        timeout=self.timeout,
                        proxies=httpx_proxies,
                        **kwargs,
                    )
                else:
                    with httpx.Client(transport=transport, http2=bool(self.http2)) as client:
                        resp = client.request(
                            method,
                            url,
                            headers=hdrs,
                            timeout=self.timeout,
                            **kwargs,
                        )
            blocked = self._is_block(resp)
            if not blocked or self.on_block == "none" or attempt >= self.max_retries:
                return resp
            attempt += 1
            if self.on_block in {"rotate", "both"}:
                self._rotate_profile()
            if self.on_block in {"proxy", "both"}:
                self._rotate_proxy()
            delay = self.retry_backoff_base * (2 ** (attempt - 1))
            jitter = random.uniform(0, self.retry_jitter)
            time.sleep(delay + jitter)

    def _is_block(self, resp: Any) -> bool:
        if self._block_detector:
            try:
                return bool(self._block_detector(resp))
            except Exception:
                pass
        code = getattr(resp, "status_code", None)
        if code in {403, 429, 1020}:
            return True
        text = ""
        try:
            text = getattr(resp, "text", "") or ""
        except Exception:
            text = ""
        t = text.lower()
        if any(x in t for x in ["access denied", "error 1020", "attention required", "bot detected"]):
            return True
        return False

    def _rotate_profile(self) -> None:
        if self.rotate_profiles:
            if not self.rotate_profiles:
                return
            self._rotate_index = (self._rotate_index + 1) % len(self.rotate_profiles)
            name = self.rotate_profiles[self._rotate_index]
        else:
            names = [n for n in PROFILES.keys() if n != self._profile_name]
            if not names:
                return
            name = random.choice(names)
        self._profile_name = name
        self.profile = _get_profile(name)
        ua = self.profile.get("user_agent") or ""
        if ua:
            self.headers["User-Agent"] = ua

    def _rotate_proxy(self) -> None:
        if not self.proxies_pool:
            return
        if not self.proxies_pool:
            return
        self._proxy_index = (self._proxy_index + 1) % len(self.proxies_pool)

    def _current_proxy(self):
        if self.proxies_pool and len(self.proxies_pool) > 0:
            if self._proxy_index < 0:
                self._proxy_index = 0
            return self.proxies_pool[self._proxy_index]
        return self.proxies or None

    def _normalize_proxy_for_httpx(self, proxy):
        if proxy is None:
            return None
        if isinstance(proxy, str):
            return {"http": proxy, "https": proxy}
        if isinstance(proxy, dict):
            return proxy
        return None

    def _apply_header_order(self, headers: Dict[str, str]) -> Dict[str, str]:
        if not self.header_order:
            return headers
        ordered: Dict[str, str] = {}
        for k in self.header_order:
            if k in headers:
                ordered[k] = headers[k]
        for k, v in headers.items():
            if k not in ordered:
                ordered[k] = v
        return ordered

    def _apply_site_preset(self, site: str) -> None:
        s = site.lower()
        if s == "cloudflare":
            if not self.rotate_profiles:
                self.rotate_profiles = ["chrome_124", "chrome_120", "mobile_safari_17"]
            self.max_retries = max(self.max_retries, 3)
            self.retry_backoff_base = min(self.retry_backoff_base, 0.8)
            self.retry_jitter = max(self.retry_jitter, 0.4)
            if self.http2 is None:
                self.http2 = True
            if not self.header_order:
                self.header_order = ["User-Agent", "Accept", "Accept-Language", "Accept-Encoding", "Connection"]
        elif s == "akamai":
            if not self.rotate_profiles:
                self.rotate_profiles = ["chrome_124", "firefox_120", "mobile_safari_17"]
            self.max_retries = max(self.max_retries, 3)
            self.retry_backoff_base = min(self.retry_backoff_base, 1.0)
            self.retry_jitter = max(self.retry_jitter, 0.5)
            if self.http2 is None:
                self.http2 = True

    def get(self, url: str, **kwargs: Any):
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any):
        return self.request("POST", url, **kwargs)

    def put(self, url: str, **kwargs: Any):
        return self.request("PUT", url, **kwargs)

    def delete(self, url: str, **kwargs: Any):
        return self.request("DELETE", url, **kwargs)

    def head(self, url: str, **kwargs: Any):
        return self.request("HEAD", url, **kwargs)

    def patch(self, url: str, **kwargs: Any):
        return self.request("PATCH", url, **kwargs)


def request(method: str, url: str, fingerprint: Optional[str] = None, **kwargs: Any):
    client = TLSChameleon(fingerprint=fingerprint)
    return client.request(method, url, **kwargs)


def get(url: str, fingerprint: Optional[str] = None, **kwargs: Any):
    client = TLSChameleon(fingerprint=fingerprint)
    return client.get(url, **kwargs)


def post(url: str, fingerprint: Optional[str] = None, **kwargs: Any):
    client = TLSChameleon(fingerprint=fingerprint)
    return client.post(url, **kwargs)


def put(url: str, fingerprint: Optional[str] = None, **kwargs: Any):
    client = TLSChameleon(fingerprint=fingerprint)
    return client.put(url, **kwargs)


def delete(url: str, fingerprint: Optional[str] = None, **kwargs: Any):
    client = TLSChameleon(fingerprint=fingerprint)
    return client.delete(url, **kwargs)


def head(url: str, fingerprint: Optional[str] = None, **kwargs: Any):
    client = TLSChameleon(fingerprint=fingerprint)
    return client.head(url, **kwargs)


def patch(url: str, fingerprint: Optional[str] = None, **kwargs: Any):
    client = TLSChameleon(fingerprint=fingerprint)
    return client.patch(url, **kwargs)
