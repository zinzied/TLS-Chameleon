import random
import re
import json
import ssl
import time
from typing import Any, Dict, Optional, List, Callable, Union
import threading
from urllib.parse import urljoin
import http.cookiejar
import os
import copy

from .profiles import PROFILES, DEFAULT_PROFILE, get_profile as profiles_get_profile
from .magnet import Magnet

# Import new v2.0 modules
try:
    from .fingerprint_gallery import (
        FINGERPRINT_GALLERY,
        get_profile as gallery_get_profile,
        randomize_profile,
        get_random_profile,
    )
    HAS_GALLERY = True
except ImportError:
    FINGERPRINT_GALLERY = {}
    HAS_GALLERY = False

try:
    from .http2_simulator import HTTP2Profile, get_http2_profile
    HAS_HTTP2_SIM = True
except ImportError:
    HAS_HTTP2_SIM = False

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


def _get_profile(name: Optional[str], use_gallery: bool = True) -> Dict[str, Any]:
    """Get a profile by name, checking gallery first if available."""
    if not name:
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


def _cipher_list(profile: Dict[str, Any], randomize: bool) -> Optional[str]:
    ciphers = list(profile.get("tls12_ciphers") or [])
    if not ciphers:
        return None
    if randomize:
        random.shuffle(ciphers)
    return ":".join(ciphers)


class ChameleonResponse:
    """Wrapper around Response to add Magnet features."""
    def __init__(self, original_response: Any):
        self._resp = original_response

    @property
    def magnet(self):
        return Magnet(getattr(self._resp, "text", "") or "")
        
    def json_fuzzy(self):
        """Attempts to parse JSON from broken/JSONP responses."""
        # Simple implementation
        t = getattr(self._resp, "text", "")
        # Strip padding like callback(...)
        t = re.sub(r'^\w+\((.*)\);?$', r'\1', t.strip())
        import json # Local import to be safe or assuming top level
        try:
            return json.loads(t) 
        except:
             # Try simple trailing comma fix
             t = re.sub(r',\s*([}\]])', r'\1', t)
             return json.loads(t)

    def __getattr__(self, name):
        return getattr(self._resp, name)

    def __repr__(self):
        return repr(self._resp)


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
        site: Optional[str] = None,
        proxies_pool: Optional[List[str]] = None,
        header_order: Optional[List[str]] = None,
        http2: Optional[bool] = None,
        verify: bool = True,
        ghost_mode: bool = False,
    ) -> None:
        # New v2.0: Handle profile parameter (takes precedence over fingerprint)
        if profile:
            self.profile_name = profile
        elif fingerprint:
            self.profile_name = fingerprint
        else:
            self.profile_name = DEFAULT_PROFILE
        
        # Validate profile exists (check both legacy and gallery)
        if not self._profile_exists(self.profile_name):
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
        self.proxies_pool = proxies_pool
        self.header_order = header_order
        self.http2 = http2
        self.verify = verify
        self.ghost_mode = ghost_mode
        
        # Internal state
        self._rotate_index = -1
        self._proxy_index = -1
        self.session = None

        # Normalize initial proxies
        if proxies and isinstance(proxies, str):
            self.proxies = {"http": proxies, "https": proxies}
        else:
            self.proxies = proxies or {}

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
        
        # Apply randomization if enabled (v2.0 feature)
        if self.randomize and HAS_GALLERY:
            try:
                profile = randomize_profile(profile)
            except Exception:
                pass
        
        # Cache the profile data for get_fingerprint_info()
        self._current_profile_data = copy.deepcopy(profile)
        
        user_agent = profile.get("user_agent")
        
        # Merge User-Agent into headers if not already present
        if user_agent and "User-Agent" not in self.headers:
             self.headers["User-Agent"] = user_agent
        
        # Add Sec-CH-UA headers if present in profile (v2.0 feature)
        if "sec_ch_ua" in profile and "Sec-CH-UA" not in self.headers:
            self.headers["Sec-CH-UA"] = profile["sec_ch_ua"]
        if "sec_ch_ua_platform" in profile and "Sec-CH-UA-Platform" not in self.headers:
            self.headers["Sec-CH-UA-Platform"] = profile["sec_ch_ua_platform"]
        if profile.get("sec_ch_ua_mobile") and "Sec-CH-UA-Mobile" not in self.headers:
            self.headers["Sec-CH-UA-Mobile"] = profile.get("sec_ch_ua_mobile", "?0")

        if self.engine == "curl" and crequests is not None:
            impersonate = profile.get("impersonate")
            
            # Helper to build options
            curl_opts = {}
            cipher_str = _cipher_list(profile, self.randomize_ciphers)
            if cipher_str and ccurl and hasattr(ccurl, "CURLOPT_SSL_CIPHER_LIST"):
                curl_opts[ccurl.CURLOPT_SSL_CIPHER_LIST] = cipher_str

            self.session = crequests.Session(
                impersonate=impersonate,
                timeout=self.timeout,
                curl_options=curl_opts
            )
            # Apply headers
            self.session.headers.update(self.headers)
            # Apply proxies 
            if self.proxies:
                self.session.proxies.update(self.proxies)
            # Apply verification
            self.session.verify = self.verify
            
            # Note: curls_cffi Session handles cookies automatically

        elif self.engine == "httpx" and httpx is not None:
            # Setup HTTPX Client
            self.session = httpx.Client(
                http2=bool(self.http2) if self.http2 is not None else False,
                timeout=self.timeout,
                verify=self.verify,
                follow_redirects=True
            )
            self.session.headers.update(self.headers)
            if self.proxies:
                self.session.proxies = self._normalize_proxy_for_httpx(self.proxies)
                
            # Manually handle cipher suite setting for HTTPX if possible
            # (Limitation: httpx python level config is limited, usually relies on ssl context)
            cipher_str = _cipher_list(profile, self.randomize_ciphers)
            if cipher_str:
                context = ssl.create_default_context()
                if not self.verify:
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                try:
                    context.set_ciphers(cipher_str)
                    # We have to mount the adapter/transport with this context
                    # This is complex in httpx.Client after init, effectively we just set it on a new transport
                    # For simplicty in this 'drop-in' we might accept default or rebuild transport
                    pass 
                except Exception:
                    pass
        else:
            raise RuntimeError(f"Engine {self.engine} not available.")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    def close(self):
        if self.session:
            self.session.close()
    
    def _profile_exists(self, name: str) -> bool:
        """Check if a profile exists in either legacy or gallery profiles."""
        if name in PROFILES:
            return True
        if HAS_GALLERY and name in FINGERPRINT_GALLERY:
            return True
        return False
    
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
            "http2_priority": self.http2_priority,
            "engine": self.engine,
        }
        
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

    def request(self, method: str, url: str, **kwargs: Any):
        # Handle custom logic that needs to happen per-request
        # 1. Randomize Ciphers (if curl) -> Handled in _init_session
        # 2. Header Ordering
        
        # Prepare kwargs for the delegated call
        request_kwargs = kwargs.copy()
        
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
                 # Override session proxy for this request
                 if self.engine == "curl":
                     request_kwargs["proxies"] = current_proxy
                 else:
                     request_kwargs["proxies"] = self._normalize_proxy_for_httpx(current_proxy)

            try:
                # Remove curl_options from kwargs if present (since Session.request doesn't take it)
                if "curl_options" in request_kwargs:
                    request_kwargs.pop("curl_options")
                
                # Check for mimic_assets
                mimic_assets = request_kwargs.pop("mimic_assets", False)

                resp = self.session.request(method, url, headers=req_headers, **request_kwargs)
                
                # Wrap response
                wrapped_resp = ChameleonResponse(resp)
                
                # WAF Detection & Adaptation
                self._check_waf_and_adapt(wrapped_resp)

                # Trigger mimic_assets if success
                if mimic_assets and resp and 200 <= getattr(resp, "status_code", 500) < 300:
                    self._mimic_assets(getattr(resp, "text", ""), url)

                # Return wrapped response so checking blocking status works on wrapper too (since it proxies)
                resp = wrapped_resp
                
            except Exception as e:
                # Network error, potentially retry or rotate
                if attempt >= self.max_retries:
                    raise e
                # Fallthrough to rotation/retry logic
                resp = None 

            blocked = self._is_block(resp) if resp else True
            
            if not blocked or self.on_block == "none" or attempt >= self.max_retries:
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
                if self.engine == "curl":
                    self.session.proxies.update(self.proxies or {})
                # For httpx we'd need to set .proxies, but it's immutable-ish. Re-init is safer.
                if self.engine == "httpx":
                     self._init_session()

            delay = self.retry_backoff_base * (2 ** (attempt - 1))
            jitter = random.uniform(0, self.retry_jitter)
            time.sleep(delay + jitter)

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
            
        text = ""
        try:
            text = getattr(resp, "text", "") or ""
        except Exception:
            text = ""
        t = text.lower()
        if any(x in t for x in ["access denied", "error 1020", "attention required", "bot detected", "cloudflare"]):
            # Simple keyword check - can be prone to false positives if page content talks about these things
            # but standard for scraper block detection.
            return True
        return False

    def _rotate_profile(self) -> None:
        if self.rotate_profiles:
            self._rotate_index = (self._rotate_index + 1) % len(self.rotate_profiles)
            name = self.rotate_profiles[self._rotate_index]
        else:
            names = [n for n in PROFILES.keys() if n != self.profile_name]
            if not names:
                return
            name = random.choice(names)
        
        self.profile_name = name
        # User-Agent update happens in _init_session calling _get_profile

    def _rotate_proxy(self) -> None:
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
            return {"http://": proxy, "https://": proxy} # HTMX usually prefers protocol
        if isinstance(proxy, dict):
            # mapping requests style to httpx style can be tricky (http -> http://)
            # but httpx handles dicts reasonably well now.
            return proxy
        return None

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
        # 1. Timing Jitter (Poisson distribution representation)
        # Random delay between 0.1 and 1.5 seconds for every request if ghost_mode is on
        delay = random.expovariate(1.0 / 0.5) # Average 0.5s delay
        delay = min(max(delay, 0.1), 3.0) # Clamp
        time.sleep(delay)
        
        # 2. Payload Padding for POST/PUT
        if method.upper() in ("POST", "PUT"):
            data = kwargs.get("data")
            json_data = kwargs.get("json")
            
            padding_key = f"_{random.getrandbits(16):x}"
            padding_val = "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=random.randint(8, 32)))
            
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
        return {
            "profile_name": self.profile_name,
            "engine": self.engine,
            "proxies": self.proxies,
            "headers": self.headers,
            "rotate_index": self._rotate_index,
            "proxy_index": self._proxy_index,
            # We don't export cookies here as load/save_cookies handle files, 
            # but we could return them as a list.
        }

    def import_session(self, state: Dict[str, Any]) -> None:
        """Restores session state."""
        self.profile_name = state.get("profile_name", self.profile_name)
        self.engine = state.get("engine", self.engine)
        self.proxies = state.get("proxies", self.proxies)
        self.headers = state.get("headers", self.headers)
        self._rotate_index = state.get("rotate_index", -1)
        self._proxy_index = state.get("proxy_index", -1)
        self._init_session()

    def save_cookies(self, filename: str, format: str = "netscape") -> None:
        """
        Saves the current session cookies to a file.
        
        Args:
            filename: Path to the cookie file.
            format: "netscape" (default) or "json".
        """
        if not self.session:
            return

        if format == "netscape":
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
            
        elif format == "json":
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
            raise ValueError(f"Unknown cookie format: {format}")

    def load_cookies(self, filename: str, format: str = "netscape") -> None:
        """
        Loads cookies from a file into the session.
        
        Args:
            filename: Path to the cookie file.
            format: "netscape" (default) or "json".
        """
        if not os.path.exists(filename):
            return
            
        if not self.session:
            self._init_session()

        if format == "netscape":
            cj = http.cookiejar.MozillaCookieJar(filename)
            cj.load(ignore_discard=True, ignore_expires=True)
            for cookie in cj:
                self.session.cookies.set(
                    cookie.name, 
                    cookie.value, 
                    domain=cookie.domain, 
                    path=cookie.path
                )
                
        elif format == "json":
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
            raise ValueError(f"Unknown cookie format: {format}")

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
                # We use specific headers to look like asset request?
                # For now just simple GET/HEAD with current session logic (re-using cookies)
                # Use a lightweight request
                self.session.head(full_url, timeout=5)
            except:
                pass

        # Limit to first N assets to avoid flooding?
        # Browser fetches many in parallel.
        # We spawn threads
        for asset in list(assets)[:20]: # Cap at 20 assets
            t = threading.Thread(target=fetch, args=(asset,))
            t.daemon = True
            t.start()

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

def request(method: str, url: str, fingerprint: Optional[str] = None, **kwargs: Any):
    with TLSChameleon(fingerprint=fingerprint, **kwargs) as client:
        return client.request(method, url)

def get(url: str, fingerprint: Optional[str] = None, **kwargs: Any):
    with TLSChameleon(fingerprint=fingerprint, **kwargs) as client:
        return client.get(url)

def post(url: str, fingerprint: Optional[str] = None, **kwargs: Any):
    with TLSChameleon(fingerprint=fingerprint, **kwargs) as client:
        return client.post(url)

def put(url: str, fingerprint: Optional[str] = None, **kwargs: Any):
    with TLSChameleon(fingerprint=fingerprint, **kwargs) as client:
        return client.put(url)

def delete(url: str, fingerprint: Optional[str] = None, **kwargs: Any):
    with TLSChameleon(fingerprint=fingerprint, **kwargs) as client:
        return client.delete(url)

def head(url: str, fingerprint: Optional[str] = None, **kwargs: Any):
    with TLSChameleon(fingerprint=fingerprint, **kwargs) as client:
        return client.head(url)

def patch(url: str, fingerprint: Optional[str] = None, **kwargs: Any):
    with TLSChameleon(fingerprint=fingerprint, **kwargs) as client:
        return client.patch(url)

def options(url: str, fingerprint: Optional[str] = None, **kwargs: Any):
    with TLSChameleon(fingerprint=fingerprint, **kwargs) as client:
        return client.options(url)

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

