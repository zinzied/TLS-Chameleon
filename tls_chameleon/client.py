import random
import re
import json
import time
from typing import Any, Dict, Optional, List, Callable, Union
from urllib.parse import urljoin, urlparse
import http.cookiejar
import os
import copy
import logging
import concurrent.futures

# Global bounded pool for background asset prefetching
_ASSET_EXECUTOR = concurrent.futures.ThreadPoolExecutor(max_workers=5)

logger = logging.getLogger(__name__)

# Adaptive per-domain profile memory (Phase 4): bounded, expiring,
# thread-safe, explainable. The legacy module-level names below are kept
# as aliases so existing code (and tests) keep working unchanged.
from .adaptive import DomainMemory, DEFAULT_DOMAIN_MEMORY_MAX

_memory = DomainMemory(max_entries=DEFAULT_DOMAIN_MEMORY_MAX)
_DOMAIN_MEMORY = _memory.data            # legacy OrderedDict view
_DOMAIN_MEMORY_LOCK = _memory.lock       # legacy lock alias
_DOMAIN_MEMORY_MAX = DEFAULT_DOMAIN_MEMORY_MAX

from .profiles import PROFILES, DEFAULT_PROFILE
from .magnet import Magnet

# Import new v2.0 modules
try:
    from .fingerprint_gallery import (  # noqa: F401  (probe + re-export)
        FINGERPRINT_GALLERY,
        get_random_profile,
        get_profile as gallery_get_profile,
        randomize_profile,
    )
    HAS_GALLERY = True
except ImportError:
    FINGERPRINT_GALLERY = {}
    HAS_GALLERY = False

try:
    from .http2_simulator import HTTP2Profile, get_http2_profile  # noqa: F401  (probe)
    HAS_HTTP2_SIM = True
except ImportError:
    HAS_HTTP2_SIM = False

from .transport import (
    ProxyConfig,
    SessionConfig,
    Transport,
    select_transport,
)


def _select_engine(preferred: Optional[str]) -> str:
    """Deprecated: resolve an engine preference to an available backend name.

    Kept as a compatibility shim; all selection logic now lives in
    :mod:`tls_chameleon.transport.factory`.
    """
    return select_transport(preferred).name


def _get_profile(name: Optional[str], use_gallery: bool = True) -> Dict[str, Any]:
    """Get a profile by name, checking gallery first if available."""
    if not name:
        name = DEFAULT_PROFILE
    
    # Generative engine: resolve gen:// scheme into a synthesized fingerprint
    if isinstance(name, str) and name.startswith("gen://"):
        try:
            from .gen_fingerprint import resolve_gen_profile
            return resolve_gen_profile(name)
        except Exception as e:
            logger.warning(f"Generative profile failed ({e}); using default.")
            name = DEFAULT_PROFILE
    
    # Try new gallery first
    if use_gallery and HAS_GALLERY:
        profile = gallery_get_profile(name)
        if profile:
            # Convert to legacy format if needed
            if "ciphers" in profile and "tls12_ciphers" not in profile:
                profile = dict(profile)
                profile["tls12_ciphers"] = profile["ciphers"]
            return profile
    
    # Fall back to legacy profiles
    return PROFILES.get(name, PROFILES.get(DEFAULT_PROFILE, {}))


def _cipher_list(
    profile: Dict[str, Any], randomize: bool, rng: Optional[random.Random] = None
) -> Optional[str]:
    ciphers = list(profile.get("tls12_ciphers") or [])
    # Drop any GREASE markers (e.g. "grease_2570") -- not valid OpenSSL names
    ciphers = [c for c in ciphers if not str(c).startswith("grease_")]
    if not ciphers:
        return None
    if randomize:
        rand = rng if rng is not None else random
        rand.shuffle(ciphers)
    return ":".join(ciphers)


class ChameleonResponse:
    """TLS-Chameleon-owned HTTP response.

    This is the ONLY response type users interact with. Backend response
    objects never escape the transport layer: attributes are an explicit,
    documented surface; anything else raises ``AttributeError`` naming the
    supported fields instead of silently leaking backend internals.
    """

    _SUPPORTED = (
        "status_code", "text", "content", "headers", "cookies", "url",
        "encoding", "history", "ok", "json()", "raise_for_status()",
        "magnet", "trace",
    )

    def __init__(self, original_response: Any):
        self._resp = original_response
        self._magnet = None
        self._trace = None  # Optional NetworkTrace (set when trace=True)

    # -- explicit, owned surface --------------------------------------
    @property
    def status_code(self) -> int:
        return getattr(self._resp, "status_code")

    @property
    def text(self) -> str:
        return getattr(self._resp, "text") or ""

    @property
    def content(self) -> bytes:
        return getattr(self._resp, "content")

    @property
    def url(self) -> str:
        return str(getattr(self._resp, "url", ""))

    @property
    def encoding(self):
        return getattr(self._resp, "encoding", None)

    @property
    def headers(self) -> Dict[str, str]:
        """Received response headers as a plain dict (owned copy)."""
        return dict(getattr(self._resp, "headers", {}) or {})

    @property
    def cookies(self) -> Dict[str, Any]:
        """Cookies from this response as a plain dict (owned copy)."""
        return dict(getattr(self._resp, "cookies", {}) or {})

    @property
    def history(self) -> list:
        return list(getattr(self._resp, "history", []) or [])

    @property
    def ok(self) -> bool:
        status = self.status_code
        return status < 400

    def json(self, **kwargs: Any) -> Any:
        return getattr(self._resp, "json")(**kwargs)

    def raise_for_status(self) -> "ChameleonResponse":
        raiser = getattr(self._resp, "raise_for_status", None)
        if callable(raiser):
            raiser()
        elif self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code} for {self.url}")
        return self

    # -- TLS-Chameleon extensions -------------------------------------
    @property
    def trace(self):
        """Structured :class:`~tls_chameleon.diagnostics.NetworkTrace`.

        Populated only when the request was made with ``trace=True``;
        ``None`` otherwise. Headers are always redacted.
        """
        return self._trace

    @property
    def magnet(self):
        if self._magnet is None:
            self._magnet = Magnet(self.text)
        return self._magnet

    # -- ownership guard ----------------------------------------------
    def __getattr__(self, name: str):
        if name.startswith("_"):
            raise AttributeError(name)
        raise AttributeError(
            f"'ChameleonResponse' object has no attribute '{name}'. "
            f"Supported: {', '.join(ChameleonResponse._SUPPORTED)}"
        )

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        try:
            return f"<ChameleonResponse [{self.status_code}]>"
        except Exception:
            return "<ChameleonResponse>"
        
    def json_fuzzy(self):
        """Attempts to parse JSON from broken/JSONP responses."""
        # Simple implementation
        t = getattr(self._resp, "text", "")
        # Strip padding like callback(...)
        t = re.sub(r'^\w+\((.*)\);?$', r'\1', t.strip())
        try:
            return json.loads(t) 
        except Exception:
             # Try simple trailing comma fix
             t = re.sub(r',\s*([}\]])', r'\1', t)
             return json.loads(t)


class TLSChameleon:
    """
    A drop-in replacement for requests.Session that handles TLS fingerprinting
    and rotates profiles/proxies on blocks.
    
    v2.0 Features:
    - New `profile` parameter for selecting from 30+ browser profiles
    - `randomize` parameter for fingerprint variation
    - `http2_priority` for browser-specific HTTP/2 simulation
    """
    def __init__(
        self,
        fingerprint: Optional[str] = None,
        profile: Optional[str] = None,  # New v2.0: explicit profile selection
        randomize: bool = False,  # New v2.0: enable fingerprint randomization
        http2_priority: Optional[str] = None,  # New v2.0: 'chrome', 'firefox', 'safari'
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
        on_retry: Optional[Callable[[int, Any, str], None]] = None,  # v2.1: retry hook(attempt, resp, next_profile)
        rate_limit: Optional[float] = None,  # v2.1: max requests/second per domain
        site: Optional[str] = None,
        proxies_pool: Optional[List[str]] = None,
        header_order: Optional[List[str]] = None,
        http2: Optional[bool] = None,
        http3: Optional[bool] = None,
        verify: bool = True,
        ghost_mode: bool = False,
        adaptive: bool = True,
        adaptive_ttl: Optional[float] = None,
        random_seed: Optional[Any] = None,
        seed: Optional[Any] = None,
    ) -> None:
        # New v2.0: Handle profile parameter (takes precedence over fingerprint)
        self._explicit_profile = False
        if profile:
            self.profile_name = profile
            self._explicit_profile = True
        elif fingerprint:
            self.profile_name = fingerprint
            self._explicit_profile = True
        else:
            self.profile_name = DEFAULT_PROFILE
        
        # Validate profile exists (check both legacy and gallery)
        if not self._profile_exists(self.profile_name):
            logger.warning(f"Profile '{self.profile_name}' not found. Falling back to default.")
            self.profile_name = DEFAULT_PROFILE
        
        # New v2.0: Store randomization and HTTP/2 priority settings
        self.randomize = randomize
        self.http2_priority = http2_priority
        self._current_profile_data = None  # Cached profile data
        
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
        self._rate_limit_last: Dict[str, float] = {}  # domain -> last request timestamp
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
        # Deterministic RNG: same seed + config => identical fingerprint
        # choices. Derivation is stable across processes (SHA-256 of repr).
        if random_seed is not None:
            from .randomizer import derive_seed_rng

            self._rng = derive_seed_rng(random_seed)
        else:
            self._rng = None
        
        # Internal state
        self._rotate_index = -1
        self._proxy_index = -1
        self.session = None
        self._transport: Transport = select_transport(engine)

        # Normalize initial proxies
        # Accept str | requests-style dict | ProxyConfig; normalize once.
        _pcfg = ProxyConfig.coerce(proxies)
        self.proxies = _pcfg.to_requests_dict() if _pcfg else {}

        # Initial Headers
        self.headers = headers or {}
        
        # Apply Site Preset logic before creating session
        if site:
            self._apply_site_preset(site)
            
        # Initialize the underlying session
        self._init_session()



    def _init_session(self):
        """Initializes or Re-initializes the underlying session (curl or httpx)"""
        # Close existing if any
        if self.session:
            try:
                self.session.close()
            except Exception:
                pass

        # Get profile, applying randomization if enabled
        profile = _get_profile(self.profile_name)
        
        # Apply randomization if enabled (v2.0 feature); seeded RNG keeps
        # the variant reproducible when random_seed is provided.
        if self.randomize and HAS_GALLERY:
            try:
                profile = randomize_profile(profile, rng=self._rng)
            except Exception as e:
                logger.debug(f"Randomization failed: {e}")
        
        # Cache the profile data for get_fingerprint_info()
        self._current_profile_data = copy.deepcopy(profile)
        
        user_agent = profile.get("user_agent")
        
        # Always update User-Agent to match the current profile (AI-Urllib4 Adaptive Fix)
        if user_agent:
             self.headers["User-Agent"] = user_agent
        
        # Add/Update Sec-CH-UA headers if present in profile
        if "sec_ch_ua" in profile:
            self.headers["Sec-CH-UA"] = profile["sec_ch_ua"]
        if "sec_ch_ua_platform" in profile:
            self.headers["Sec-CH-UA-Platform"] = profile["sec_ch_ua_platform"]
        if profile.get("sec_ch_ua_mobile"):
            self.headers["Sec-CH-UA-Mobile"] = profile.get("sec_ch_ua_mobile", "?0")

        # Resolve the transport from the (possibly user-mutated) engine name,
        # then build the session through the backend-agnostic interface.
        self._transport = select_transport(self.engine)
        self.engine = self._transport.name

        cipher_str = _cipher_list(profile, self.randomize_ciphers, rng=self._rng)

        config = SessionConfig(
            profile=profile,
            cipher_suites=cipher_str,
            timeout=self.timeout,
            verify=self.verify,
            proxies=self.proxies or None,
            headers=dict(self.headers),
            http2=self.http2,
            http3=self.http3,
        )
        self.session = self._transport.create_session(config)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    def close(self):
        if self.session:
            self.session.close()
    
    def _profile_exists(self, name: str) -> bool:
        """Check if a profile exists in either legacy or gallery profiles."""
        if isinstance(name, str) and name.startswith("gen://"):
            return True
        if name in PROFILES:
            return True
        if HAS_GALLERY and name in FINGERPRINT_GALLERY:
            return True
        return False
    
    @property
    def capabilities(self):
        """Honest capability report for the backend currently in use.

        Example:
            client.capabilities.http3        # True only if really supported
            client.capabilities.tls_fingerprint_spoofing
        """
        return self._transport.capabilities

    def get_fingerprint_info(self) -> Dict[str, Any]:
        """
        Return current fingerprint details for debugging.
        
        Returns:
            Dict with user_agent, ja3, ja3_hash, profile_name, etc.
        """
        profile = self._current_profile_data or _get_profile(self.profile_name)
        
        info = {
            "profile_name": self.profile_name,
            "user_agent": profile.get("user_agent"),
            "ja3": profile.get("ja3"),
            "ja3_hash": profile.get("ja3_hash"),
            "impersonate": profile.get("impersonate"),
            "header_case": profile.get("header_case"),
            "randomized": self.randomize,
            "random_seed": self.random_seed,
            "adaptive": self.adaptive,
            "http2_priority": self.http2_priority,
            "engine": self.engine,
            "http3": bool(self.http3) if hasattr(self, 'http3') else False,
        }
        
        # Honest per-backend capabilities (what the session can actually do)
        if getattr(self, "_transport", None) is not None:
            info["capabilities"] = self._transport.capabilities.to_dict()
        
        # Add Sec-CH-UA if present
        if "sec_ch_ua" in profile:
            info["sec_ch_ua"] = profile["sec_ch_ua"]
        if "sec_ch_ua_platform" in profile:
            info["sec_ch_ua_platform"] = profile["sec_ch_ua_platform"]
        
        return info
    
    def sync_fingerprint(
        self, 
        ja3: Optional[str] = None, 
        user_agent: Optional[str] = None
    ) -> None:
        """
        Manually set fingerprint to match network layer.
        
        This is useful for ensuring the TLS fingerprint (JA3) matches
        the User-Agent being sent.
        
        Args:
            ja3: JA3 fingerprint string to use
            user_agent: User-Agent string to use
        """
        if user_agent:
            self.headers["User-Agent"] = user_agent
        
        # Note: JA3 is determined by curl_cffi's impersonate setting
        # We can't directly set JA3, but we can store it for reference
        if ja3 and self._current_profile_data:
            self._current_profile_data["ja3"] = ja3
        
        # Reinitialize session to apply changes
        self._init_session()

    def profile_for(self, domain: str) -> Dict[str, Any]:
        """Explain which profile the adaptive engine would use for a domain.

        Returns:
            ``{"profile", "reason", "confidence", "last_used"}``. ``profile``
            is ``None`` when nothing was learned yet.
        """
        explanation = _memory.explain(domain)
        if not self.adaptive:
            explanation["reason"] = "adaptive engine disabled"
            if explanation["profile"] is not None:
                explanation["confidence"] = 0.0
        elif self._explicit_profile:
            explanation["reason"] = (
                "explicit profile set; learned value would be ignored"
            )
        return explanation

    def request(self, method: str, url: str, **kwargs: Any):
        # Domain Memory Check (Adaptive Profile Selection)
        domain = urlparse(url).netloc
        memory_profile = _memory.lookup(domain) if self.adaptive else None
        if not self._explicit_profile and self.adaptive and memory_profile:
            if memory_profile != self.profile_name and self._profile_exists(memory_profile):
                logger.info(f"Domain Memory: Switching to known good profile '{memory_profile}' for {domain}")
                self.profile_name = memory_profile
                self._init_session()

        # Handle custom logic that needs to happen per-request
        # 1. Randomize Ciphers (if curl) -> Handled in _init_session
        # 2. Header Ordering
        
        # Prepare kwargs for the delegated call
        request_kwargs = kwargs.copy()

        # trace=True is a TLS-Chameleon extension, not a backend kwarg.
        want_trace = bool(request_kwargs.pop("trace", False))
        started = time.perf_counter()
        
        # Rate limiting per domain
        if self.rate_limit and self.rate_limit > 0:
            min_interval = 1.0 / self.rate_limit
            last_time = self._rate_limit_last.get(domain, 0)
            elapsed = time.time() - last_time
            if elapsed < min_interval:
                time.sleep(min_interval - elapsed)
            self._rate_limit_last[domain] = time.time()
        
        # Merge headers
        req_headers = request_kwargs.pop("headers", {}) or {}
        
        # 1. Header Morphing (Ordering & Casing)
        profile = _get_profile(self.profile_name)
        req_headers = self._morph_headers(req_headers, profile)

        # 2. Ghost Mode (Traffic Shaping)
        if self.ghost_mode:
            self._apply_ghost_mode(method, url, request_kwargs)

        attempt = 0
        while True:
            # Proxy Rotation logic for this specific request attempt?
            # If we Rotate Proxy, we usually update the Session's proxy or pass it in kwargs.
            current_proxy = self._current_proxy()
            if current_proxy and current_proxy != self.proxies:
                 # Override session proxy for this request (backend-agnostic;
                 # the transport translates/removes the kwarg as needed)
                 request_kwargs["proxies"] = current_proxy

            try:
                # Remove curl_options from kwargs if present (since Session.request doesn't take it)
                if "curl_options" in request_kwargs:
                    request_kwargs.pop("curl_options")
                
                # Check for mimic_assets
                mimic_assets = request_kwargs.pop("mimic_assets", False)

                self.session, request_kwargs = self._transport.adapt_request(
                    self.session, request_kwargs
                )
                resp = self.session.request(method, url, headers=req_headers, **request_kwargs)
                
                # Wrap response
                wrapped_resp = ChameleonResponse(resp)
                
                # WAF Detection & Adaptation
                self._check_waf_and_adapt(wrapped_resp)

                # Trigger mimic_assets if success
                if mimic_assets and resp and 200 <= getattr(resp, "status_code", 500) < 300:
                    self._mimic_assets(getattr(resp, "text", ""), url)

                # Return wrapped response so checking blocking status works on wrapper too (since it proxies)
                if want_trace:
                    wrapped_resp._trace = self._build_trace(
                        method, url, resp,
                        request_headers=req_headers,
                        total_ms=(time.perf_counter() - started) * 1000.0,
                    )
                resp = wrapped_resp
                
            except Exception as e:
                # Network error, potentially retry or rotate
                if attempt >= self.max_retries:
                    raise e
                # Fallthrough to rotation/retry logic
                resp = None 

            blocked = self._is_block(resp) if resp else True
            
            if not blocked:
                # Success! Learn this profile works for this domain
                if self.adaptive:
                    _memory.remember(domain, self.profile_name)
                return resp

            if attempt >= self.max_retries:
                 return resp

            # Blocking Logic
            attempt += 1
            if self.on_block in {"rotate", "both"}:
                self._rotate_profile()
                # Re-init session to apply new profile (User-Agent, JA3/Impersonate)
                self._init_session()
                
            if self.on_block in {"proxy", "both"}:
                self._rotate_proxy()
                # Proxy is applied in next loop iteration via _current_proxy() override 
                # OR we should update self.proxies and re-init. 
                # Let's update self.proxies to be sticky
                self.proxies = self._current_proxy()
                # Transport decides whether mutating (curl) or rebuilding
                # (httpx) the session is the right way to swap proxies.
                if self.session is not None:
                    self.session = self._transport.apply_proxies(self.session, self.proxies)
                else:
                    self._init_session()

            delay = self.retry_backoff_base * (2 ** (attempt - 1))
            jitter = self._rand().uniform(0, self.retry_jitter)
            
            # Call on_retry hook if set
            if self.on_retry:
                try:
                    self.on_retry(attempt, resp, self.profile_name)
                except Exception as e:
                    logger.debug(f"on_retry hook error: {e}")
            
            time.sleep(delay + jitter)

    def _build_trace(self, method: str, url: str, response: Any,
                     request_headers: Dict[str, str],
                     total_ms: float):
        """Build a NetworkTrace for the just-completed request (lazy import)."""
        from .diagnostics.trace import collect_trace

        return collect_trace(
            method,
            url,
            getattr(response, "_resp", response),
            backend=getattr(self._transport, "name", None),
            profile=self.profile_name,
            request_headers=request_headers or dict(self.headers),
            total_ms=total_ms,
        )

    def _is_block(self, resp: Any) -> bool:
        if not resp:
            return True # Network error treated as block for retry purposes
            
        if self.block_detector:
            try:
                return bool(self.block_detector(resp))
            except Exception:
                pass
        
        # Standard checks
        code = getattr(resp, "status_code", None)
        if code in {403, 429, 1020}:
            return True
        
        # Only check body keywords on non-2xx responses to avoid false-positives
        if code is not None and 200 <= code < 300:
            return False
            
        text = ""
        try:
            text = getattr(resp, "text", "") or ""
        except Exception:
            text = ""
        t = text.lower()
        if any(x in t for x in ["access denied", "error 1020", "attention required", "bot detected"]):
            return True
        return False

    def _rand(self):
        """Seeded RNG when random_seed was given, else the global module."""
        return self._rng if self._rng is not None else random

    def _rotate_profile(self) -> None:
        rand = self._rand()
        if self.rotate_profiles:
            self._rotate_index = (self._rotate_index + 1) % len(self.rotate_profiles)
            name = self.rotate_profiles[self._rotate_index]
        else:
            # Draw from both legacy and gallery profiles
            all_profiles = set(PROFILES.keys())
            if HAS_GALLERY:
                all_profiles.update(FINGERPRINT_GALLERY.keys())
            names = [n for n in all_profiles if n != self.profile_name]
            if not names:
                return
            name = rand.choice(names)
        
        self.profile_name = name
        # User-Agent update happens in _init_session calling _get_profile

    def _rotate_proxy(self) -> None:
        if not self.proxies_pool:
            return
        self._proxy_index = (self._proxy_index + 1) % len(self.proxies_pool)

    def _current_proxy(self) -> Optional[Dict[str, str]]:
        if self.proxies_pool and len(self.proxies_pool) > 0:
            if self._proxy_index < 0:
                self._proxy_index = 0
            p = self.proxies_pool[self._proxy_index]
            if isinstance(p, str):
                return {"http": p, "https": p}
            return p
        return self.proxies or None

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

    def _morph_headers(self, headers: Dict[str, str], profile: Dict[str, Any]) -> Dict[str, str]:
        """Applies casing and ordering to headers based on profile settings."""
        if not profile:
            return headers
        
        # Merge session headers with request headers
        merged = self.headers.copy()
        merged.update(headers)
        
        case_mode = profile.get("header_case", "title")
        order_rule = self.header_order or profile.get("header_order")
        
        morphed = {}
        
        def case_key(k: str) -> str:
            if case_mode == "lower":
                return k.lower()
            if case_mode == "title":
                return "-".join(word.capitalize() for word in k.split("-"))
            return k

        # Apply order if specified
        if order_rule:
            # Normalize order rule to lowercase for matching
            norm_order = [o.lower() for o in order_rule]
            # Add known ordered headers first
            for key in norm_order:
                # Find matching key in merged (case insensitive)
                found_key = next((k for k in merged if k.lower() == key), None)
                if found_key:
                    morphed[case_key(found_key)] = merged.pop(found_key)
        
        # Add remaining headers
        for k, v in merged.items():
            morphed[case_key(k)] = v
            
        return morphed

    def _apply_ghost_mode(self, method: str, url: str, kwargs: Any) -> None:
        """Simulates human behavior and masks traffic patterns."""
        rand = self._rand()
        # 1. Timing Jitter (Poisson distribution representation)
        # Random delay between 0.1 and 1.5 seconds for every request if ghost_mode is on
        delay = rand.expovariate(1.0 / 0.5) # Average 0.5s delay
        delay = min(max(delay, 0.1), 3.0) # Clamp
        time.sleep(delay)
        
        # 2. Payload Padding for POST/PUT
        if method.upper() in ("POST", "PUT"):
            data = kwargs.get("data")
            json_data = kwargs.get("json")
            
            padding_key = f"_{rand.getrandbits(16):x}"
            padding_val = "".join(rand.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=rand.randint(8, 32)))
            
            if isinstance(data, dict):
                data[padding_key] = padding_val
            elif isinstance(json_data, dict):
                json_data[padding_key] = padding_val

    def _check_waf_and_adapt(self, resp: Any) -> None:
        """Detects WAF and automatically adapts session settings."""
        headers = {k.lower(): v for k, v in getattr(resp, "headers", {}).items()}
        server = headers.get("server", "").lower()
        
        waf_detected = None
        if "cloudflare" in server or "cf-ray" in headers:
            waf_detected = "cloudflare"
        elif "akamai" in server or "x-akamai-transformed" in headers:
            waf_detected = "akamai"
        elif "datadome" in headers:
            waf_detected = "datadome"
        elif "x-amz-cf-id" in headers:
            waf_detected = "cloudfront"
            
        if waf_detected:
            # Adapt logic
            if waf_detected == "cloudflare":
                # Ensure HTTP/2 and modern chrome
                self.http2 = True
                if "chrome" not in self.profile_name:
                    self._rotate_to_modern_chrome()
            
            # We could log this if we had a logger
            pass

    def _rotate_to_modern_chrome(self) -> None:
        chromes = [n for n in PROFILES.keys() if "chrome" in n]
        if chromes:
            self.profile_name = random.choice(chromes)
            self._init_session()

    def export_session(self) -> Dict[str, Any]:
        """Returns the full state of the session for persistence."""
        cookies_list = []
        if self.session and hasattr(self.session, "cookies"):
            iterator = getattr(self.session.cookies, "jar", self.session.cookies)
            for c in iterator:
                cookies_list.append({
                    "name": getattr(c, "name", ""),
                    "value": getattr(c, "value", ""),
                    "domain": getattr(c, "domain", ""),
                    "path": getattr(c, "path", "/"),
                    "secure": getattr(c, "secure", False),
                    "expires": getattr(c, "expires", None)
                })

        # Backend-independent state object (3.1); serialized keys unchanged.
        from .session_state import SessionState

        state = SessionState(
            profile_name=self.profile_name,
            engine=self.engine,
            proxies=self.proxies,
            headers=self.headers,
            rotate_index=self._rotate_index,
            proxy_index=self._proxy_index,
            http3=bool(self.http3) if hasattr(self, 'http3') else False,
            adaptive=self.adaptive,
            random_seed=self.random_seed,
            cookies=cookies_list,
        )
        return state.to_dict()

    def import_session(self, state: Dict[str, Any]) -> None:
        """Restores session state."""
        self.profile_name = state.get("profile_name", self.profile_name)
        self.engine = state.get("engine", self.engine)
        self.proxies = state.get("proxies", self.proxies)
        self.headers = state.get("headers", self.headers)
        self._rotate_index = state.get("rotate_index", -1)
        self._proxy_index = state.get("proxy_index", -1)
        if "adaptive" in state:
            self.adaptive = bool(state["adaptive"])
        if "random_seed" in state and state["random_seed"] != self.random_seed:
            from .randomizer import derive_seed_rng

            self.random_seed = state["random_seed"]
            self._rng = (
                derive_seed_rng(self.random_seed)
                if self.random_seed is not None
                else None
            )
        self._init_session()

        for c in state.get("cookies", []):
            if self.session and hasattr(self.session, "cookies"):
                self.session.cookies.set(
                    c["name"],
                    c["value"],
                    domain=c.get("domain"),
                    path=c.get("path", "/")
                )

    def save_cookies(self, filename: str, cookie_format: str = "netscape") -> None:
        """
        Saves the current session cookies to a file.

        Args:
            filename: Path to the cookie file.
            cookie_format: "netscape" (default) or "json".
        """
        if not self.session:
            return

        if cookie_format == "netscape":
            cj = http.cookiejar.MozillaCookieJar(filename)

            # Identify the iterator that yields actual Cookie objects
            # httpx.Cookies iterates keys (strings), but has .jar (CookieJar)
            # requests/curl_cffi RequestCookieJar iterates cookies
            if hasattr(self.session.cookies, "jar"):
                cookie_iterator = self.session.cookies.jar
            else:
                cookie_iterator = self.session.cookies

            for cookie in cookie_iterator:
                # Check if it's already a http.cookiejar.Cookie (requests/curl_cffi usually)
                if isinstance(cookie, http.cookiejar.Cookie):
                    cj.set_cookie(cookie)
                else:
                    # Convert generic object (like httpx.Cookie) to http.cookiejar.Cookie
                    c = http.cookiejar.Cookie(
                        version=0,
                        name=getattr(cookie, "name", ""),
                        value=getattr(cookie, "value", ""),
                        port=None,
                        port_specified=False,
                        domain=getattr(cookie, "domain", ""),
                        domain_specified=bool(getattr(cookie, "domain", "")),
                        domain_initial_dot=False,
                        path=getattr(cookie, "path", "/"),
                        path_specified=bool(getattr(cookie, "path", "/")),
                        secure=getattr(cookie, "secure", False),
                        expires=getattr(cookie, "expires", None),
                        discard=False,
                        comment=None,
                        comment_url=None,
                        rest={"HttpOnly": getattr(cookie, "http_only", False)},
                        rfc2109=False,
                    )
                    cj.set_cookie(c)

            cj.save(ignore_discard=True, ignore_expires=True)

        elif cookie_format == "json":
            cookies_list = []

            if hasattr(self.session.cookies, "jar"):
                cookie_iterator = self.session.cookies.jar
            else:
                cookie_iterator = self.session.cookies

            for cookie in cookie_iterator:
                cookies_list.append({
                    "name": getattr(cookie, "name", ""),
                    "value": getattr(cookie, "value", ""),
                    "domain": getattr(cookie, "domain", ""),
                    "path": getattr(cookie, "path", "/"),
                    "secure": getattr(cookie, "secure", False),
                    "expires": getattr(cookie, "expires", None)
                })
            with open(filename, "w") as f:
                json.dump(cookies_list, f, indent=2)
        else:
            raise ValueError(f"Unknown cookie format: {cookie_format}")

    def load_cookies(self, filename: str, cookie_format: str = "netscape") -> None:
        """
        Loads cookies from a file into the session.

        Args:
            filename: Path to the cookie file.
            cookie_format: "netscape" (default) or "json".
        """
        if not os.path.exists(filename):
            return

        if not self.session:
            self._init_session()

        if cookie_format == "netscape":
            cj = http.cookiejar.MozillaCookieJar(filename)
            cj.load(ignore_discard=True, ignore_expires=True)
            for cookie in cj:
                self.session.cookies.set(
                    cookie.name,
                    cookie.value,
                    domain=cookie.domain,
                    path=cookie.path
                )

        elif cookie_format == "json":
            with open(filename, "r") as f:
                cookies_list = json.load(f)
                for c in cookies_list:
                    self.session.cookies.set(
                        c["name"],
                        c["value"],
                        domain=c.get("domain"),
                        path=c.get("path", "/")
                    )
        else:
            raise ValueError(f"Unknown cookie format: {cookie_format}")

    def submit_form(self, url: str, data: Dict[str, str], form_selector: int = 0, **kwargs):
        """
        Automatically finds forms on the page, fills them with 'data', and submits.
        """
        # 1. GET page
        resp = self.get(url, **kwargs)
        if not resp:
             return None
        forms = resp.magnet.get_forms()
        if not forms:
            raise ValueError(f"No forms found at {url}")
        
        if form_selector >= len(forms):
             raise ValueError(f"Form selector {form_selector} out of range (found {len(forms)} forms)")

        target_form = forms[form_selector]
        
        # Merge data
        payload = target_form["inputs"].copy()
        payload.update(data)
        
        # Action URL
        action = target_form["action"]
        if not action:
            post_url = url
        else:
            post_url = urljoin(url, action)
        
        method = target_form["method"].upper()
        
        if method == "POST":
            return self.post(post_url, data=payload, **kwargs)
        else:
            return self.get(post_url, params=payload, **kwargs)

    def human_delay(self, reading_speed: str = "normal") -> None:
        """
        Sleeps for a duration to simulate human reading/typing.
        """
        base = 1.0
        if reading_speed == "fast":
            base = 0.5
        elif reading_speed == "slow":
            base = 2.5
        
        delay = random.uniform(base, base * 2.0)
        time.sleep(delay)

    def _mimic_assets(self, html: str, base_url: str) -> None:
        """
        Fetches static resources (CSS, JS, Images) in background threads without waiting.
        """
        # Simple extraction
        assets = set()
        assets.update(re.findall(r'<link.*?href=["\'](.*?)["\']', html))
        assets.update(re.findall(r'<script.*?src=["\'](.*?)["\']', html))
        assets.update(re.findall(r'<img.*?src=["\'](.*?)["\']', html))
        
        def fetch(u):
            try:
                full_url = urljoin(base_url, u)
                # Head request to look like prefetch, or GET
                # Use a lightweight request to mimic asset prefetch
                self.session.head(full_url, timeout=5)
            except Exception:
                pass

        # Submit to bounded thread pool
        for asset in list(assets)[:10]:
            _ASSET_EXECUTOR.submit(fetch, asset)

    # Method aliases for compatibility
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
    
    def options(self, url: str, **kwargs: Any):
        return self.request("OPTIONS", url, **kwargs)


# Module-level convenience functions (non-persistent session unless cached?)
# Standard requests behavior is: requests.get() creates a NEW session/request every time.
# We will match that.

# Session-level kwargs are separated from request-level kwargs
_SESSION_KWARGS = {
    'fingerprint', 'profile', 'randomize', 'http2_priority', 'engine',
    'randomize_ciphers', 'timeout', 'proxies', 'rotate_profiles', 'on_block',
    'max_retries', 'retry_backoff_base', 'retry_jitter', 'block_detector',
    'on_retry', 'rate_limit',
    'site', 'proxies_pool', 'header_order', 'http2', 'http3', 'verify',
    'ghost_mode', 'adaptive', 'adaptive_ttl', 'random_seed', 'seed',
}

def _split_kwargs(kwargs: Dict[str, Any]):
    """Split kwargs into session-level and request-level."""
    session_kw = {}
    request_kw = {}
    for k, v in kwargs.items():
        if k in _SESSION_KWARGS:
            session_kw[k] = v
        else:
            request_kw[k] = v
    return session_kw, request_kw

def request(method: str, url: str, fingerprint: Optional[str] = None, **kwargs: Any):
    session_kw, request_kw = _split_kwargs(kwargs)
    with TLSChameleon(fingerprint=fingerprint, **session_kw) as client:
        return client.request(method, url, **request_kw)

def get(url: str, fingerprint: Optional[str] = None, **kwargs: Any):
    session_kw, request_kw = _split_kwargs(kwargs)
    with TLSChameleon(fingerprint=fingerprint, **session_kw) as client:
        return client.get(url, **request_kw)

def post(url: str, fingerprint: Optional[str] = None, **kwargs: Any):
    session_kw, request_kw = _split_kwargs(kwargs)
    with TLSChameleon(fingerprint=fingerprint, **session_kw) as client:
        return client.post(url, **request_kw)

def put(url: str, fingerprint: Optional[str] = None, **kwargs: Any):
    session_kw, request_kw = _split_kwargs(kwargs)
    with TLSChameleon(fingerprint=fingerprint, **session_kw) as client:
        return client.put(url, **request_kw)

def delete(url: str, fingerprint: Optional[str] = None, **kwargs: Any):
    session_kw, request_kw = _split_kwargs(kwargs)
    with TLSChameleon(fingerprint=fingerprint, **session_kw) as client:
        return client.delete(url, **request_kw)

def head(url: str, fingerprint: Optional[str] = None, **kwargs: Any):
    session_kw, request_kw = _split_kwargs(kwargs)
    with TLSChameleon(fingerprint=fingerprint, **session_kw) as client:
        return client.head(url, **request_kw)

def patch(url: str, fingerprint: Optional[str] = None, **kwargs: Any):
    session_kw, request_kw = _split_kwargs(kwargs)
    with TLSChameleon(fingerprint=fingerprint, **session_kw) as client:
        return client.patch(url, **request_kw)

def options(url: str, fingerprint: Optional[str] = None, **kwargs: Any):
    session_kw, request_kw = _split_kwargs(kwargs)
    with TLSChameleon(fingerprint=fingerprint, **session_kw) as client:
        return client.options(url, **request_kw)

Session = TLSChameleon

# New v2.0 alias - recommended for new code
TLSSession = TLSChameleon


def list_available_profiles() -> List[str]:
    """
    List all available fingerprint profiles.
    
    Returns:
        List of profile names that can be used with TLSSession(profile=...)
    """
    profiles = list(PROFILES.keys())
    if HAS_GALLERY:
        profiles.extend(FINGERPRINT_GALLERY.keys())
    return sorted(set(profiles))


class Chameleon(TLSChameleon):
    """
    High-level entry point (v3.1): WHAT vs HOW separation.

    ``profile=`` describes the fingerprint you want (backend-independent);
    ``backend=/engine=`` describes how requests are executed. ``Chameleon``
    is a drop-in subclass of :class:`TLSChameleon` -- everything documented
    there works identically.

    Example:
        from tls_chameleon import Chameleon

        client = Chameleon(profile="chrome_124_linux")
        response = client.get("https://example.com")

    Args (in addition to all TLSChameleon parameters):
        backend: alias for ``engine`` ("curl", "native", "httpx").
        seed: alias for ``random_seed``.
    """

    def __init__(self, profile=None, backend=None, seed=None, **kwargs):
        if backend is not None and "engine" not in kwargs:
            kwargs["engine"] = backend
        if seed is not None and kwargs.get("random_seed") is None:
            kwargs["random_seed"] = seed
        super().__init__(profile=profile, **kwargs)
