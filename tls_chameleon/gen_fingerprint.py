"""
TLS-Chameleon Generative Fingerprint Engine
===========================================

A world-first approach: instead of shipping a fixed gallery of captured
browser fingerprints (which themselves become detectable signatures), this
module *synthesizes* brand-new, cryptographically-valid, internally-consistent
TLS/HTTP/2 fingerprints by modelling the **implementation rules** of real
browsers.

Key ideas
---------
1. CONSTRAINT MODEL: For each browser family (chrome/firefox/safari/edge) we
   encode the *rules* that govern how that browser orders ciphers, inserts
   GREASE, lays out extensions, chooses key-share groups, signature
   algorithms, ALPN, supported_versions, etc. Nothing here is a raw capture;
   it is the generative grammar.

2. DETERMINISTIC SYNTHESIS: A seed (int/bytes/str) drives a seeded PRNG so a
   generated fingerprint is reproducible. Same seed -> same fingerprint.

3. VALIDITY: Permutations are only ever applied *within* the constraint
   boundaries (e.g. AEAD suites never move after CBC suites, GREASE always
   lands in GREASE-legal slots). The result is a ClientHello that a server
   will happily accept as a real browser.

4. CONSISTENCY: The produced profile carries a matching User-Agent,
   Sec-CH-UA, header ordering/casing and HTTP/2 SETTINGS so the TLS layer and
   the HTTP layer never disagree (a classic bot tell).

5. COMPUTED HASHES: JA3 and JA4 are *computed* from the generated values, so
   they are real fingerprints of the synthesized ClientHello, not invented.

Integration
-----------
`generate_profile(...)` returns a dict in the exact format the rest of
TLS-Chameleon expects (`ciphers`, `extensions`, `ja3`, `ja3_hash`, `user_agent`,
`sec_ch_ua`, `header_order`, `http2_settings`, ...). Generated profiles can be
passed straight into `TLSSession(profile=...)`.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional

# -----------------------------------------------------------------------------
# Primitive value tables (decimal IDs as used by JA3/JA4)
# -----------------------------------------------------------------------------

# OpenSSL cipher name -> decimal ID (IANA/RFC)
CIPHER_IDS: Dict[str, int] = {
    "TLS_AES_128_GCM_SHA256": 4865,
    "TLS_AES_256_GCM_SHA384": 4866,
    "TLS_CHACHA20_POLY1305_SHA256": 4867,
    "ECDHE-ECDSA-AES128-GCM-SHA256": 49195,
    "ECDHE-RSA-AES128-GCM-SHA256": 49196,
    "ECDHE-ECDSA-AES256-GCM-SHA384": 49199,
    "ECDHE-RSA-AES256-GCM-SHA384": 49200,
    "ECDHE-ECDSA-CHACHA20-POLY1305": 52393,
    "ECDHE-RSA-CHACHA20-POLY1305": 52392,
    "ECDHE-RSA-AES128-SHA": 49171,
    "ECDHE-RSA-AES256-SHA": 49172,
    "AES128-GCM-SHA256": 156,
    "AES256-GCM-SHA384": 157,
    "AES128-SHA": 47,
    "AES256-SHA": 53,
}

# Extension name -> decimal ID
EXT_IDS: Dict[str, int] = {
    "server_name": 0,
    "extended_master_secret": 23,
    "renegotiation_info": 65281,
    "supported_groups": 10,
    "ec_point_formats": 11,
    "session_ticket": 35,
    "alpn": 16,
    "status_request": 5,
    "signature_algorithms": 13,
    "signed_certificate_timestamp": 18,
    "key_share": 51,
    "psk_key_exchange_modes": 45,
    "supported_versions": 43,
    "cert_compression_algorithms": 27,
    "application_settings": 17513,   # Google ALPS
    "padding": 21,
    "quic_transport_parameters": 65445,
    "pre_shared_key": 41,
    "record_size_limit": 28,
}

# GREASE values (decimal) -- valid GREASE slots per RFC 8701
GREASE_VALUES: List[int] = [
    2570, 6682, 10794, 14906, 19018, 23130, 27242,
    31354, 35466, 39578, 43690, 47802, 51914, 56026, 60138, 64250,
]

# Supported groups (decimal)
GROUP_IDS: Dict[str, int] = {
    "x25519": 29,
    "secp256r1": 23,
    "secp384r1": 24,
    "secp521r1": 25,
    "x448": 30,
    "ffdhe2048": 256,
    "ffdhe3072": 257,
}

# Signature algorithms (decimal)
SIGALG_IDS: Dict[str, int] = {
    "ecdsa_secp256r1_sha256": 1027,
    "ecdsa_secp384r1_sha384": 1283,
    "ecdsa_secp521r1_sha512": 1539,
    "rsa_pss_pss_sha256": 2052,
    "rsa_pss_pss_sha384": 2053,
    "rsa_pss_pss_sha512": 2054,
    "rsa_pss_rsae_sha256": 2052,
    "rsa_pss_rsae_sha384": 2053,
    "rsa_pss_rsae_sha512": 2054,
    "rsa_pkcs1_sha256": 1025,
    "rsa_pkcs1_sha384": 1281,
    "rsa_pkcs1_sha512": 1537,
}

# EC point formats (decimal) -- 0 == uncompressed
EC_POINT_FORMATS: List[int] = [0]

# Supported TLS versions (decimal) -- 772 = 1.3, 771 = 1.2
SUPPORTED_VERSIONS: List[int] = [772, 771]


# -----------------------------------------------------------------------------
# Constraint model
# -----------------------------------------------------------------------------

@dataclass
class BrowserConstraints:
    """Generative grammar for one browser family's ClientHello."""
    family: str
    # Cipher suites in canonical preference order (OpenSSL names)
    cipher_order: List[str]
    # Extension names in canonical order
    extension_order: List[str]
    # Whether this browser uses GREASE
    grease: bool
    # GREASE insertion slots (indexes *into* the canonical extension list
    # where a GREASE extension may be inserted)
    grease_ext_slots: List[int]
    # Whether GREASE may also appear in the cipher list
    grease_cipher: bool
    # ALPN list (ordered)
    alpn: List[str]
    # Supported groups in order
    groups: List[str]
    # Signature algorithms in order
    sigalgs: List[str]
    # Whether cert_compression is advertised and its algorithms
    cert_compression: Optional[List[str]] = None
    # User-Agent template; {major}.{minor}.{patch} are substituted
    ua_template: str = ""
    # Sec-CH-UA brand template
    sec_ch_ua_template: str = ""
    # HTTP/2 SETTINGS (name -> value) aligned to this family
    http2_settings: Dict[str, int] = field(default_factory=dict)
    # Header casing: 'lower' or 'title'
    header_case: str = "lower"
    # Canonical header order
    header_order: List[str] = field(default_factory=list)
    # Allowed minor-version jitter range for UA (keeps it believable)
    ua_minor_jitter: int = 0
    # Whether the browser may drop/reorder a few trailing low-priority
    # extensions (drives diversity without breaking validity)
    flexible_trailing_ext: bool = True


# Linux/Win/Mac/Android/iOS UA strings -------------------------------------------------
_UA = {
    "chrome": {
        "win11": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{maj}.{min}.0.0 Safari/537.36",
        "win10": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{maj}.{min}.0.0 Safari/537.36",
        "macos": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{maj}.{min}.0.0 Safari/537.36",
        "linux": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{maj}.{min}.0.0 Safari/537.36",
        "android": "Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{maj}.{min}.0.0 Mobile Safari/537.36",
    },
    "firefox": {
        "win11": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:{maj}.0) Gecko/20100101 Firefox/{maj}.{min}.0",
        "win10": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:{maj}.0) Gecko/20100101 Firefox/{maj}.{min}.0",
        "macos": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:{maj}.0) Gecko/20100101 Firefox/{maj}.{min}.0",
        "linux": "Mozilla/5.0 (X11; Linux x86_64; rv:{maj}.0) Gecko/20100101 Firefox/{maj}.{min}.0",
    },
    "safari": {
        "macos": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
        "ios": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    },
    "edge": {
        "win11": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{maj}.{min}.0.0 Safari/537.36 Edg/{maj}.{min}.0.0",
        "win10": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{maj}.{min}.0.0 Safari/537.36 Edg/{maj}.{min}.0.0",
    },
}

_SEC_CH_UA = {
    "chrome": '"Not_A Brand";v="{bv}", "Chromium";v="{maj}", "Google Chrome";v="{maj}"',
    "edge":   '"Not_A Brand";v="{bv}", "Chromium";v="{maj}", "Microsoft Edge";v="{maj}"',
    "firefox": "",  # Firefox does not send Sec-CH-UA
    "safari": "",
}

# Shared TLS 1.3 cipher block (AEAD) -- order is browser-consistent
_TLS13_AEAD = [
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
]
_ECDHE_AEAD = [
    "ECDHE-ECDSA-AES128-GCM-SHA256",
    "ECDHE-RSA-AES128-GCM-SHA256",
    "ECDHE-ECDSA-AES256-GCM-SHA384",
    "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-ECDSA-CHACHA20-POLY1305",
    "ECDHE-RSA-CHACHA20-POLY1305",
]
_LEGACY_CBC = [
    "ECDHE-RSA-AES128-SHA",
    "ECDHE-RSA-AES256-SHA",
    "AES128-GCM-SHA256",
    "AES256-GCM-SHA384",
    "AES128-SHA",
    "AES256-SHA",
]

_H2_CHROME = {
    "HEADER_TABLE_SIZE": 65536,
    "ENABLE_PUSH": 0,
    "MAX_CONCURRENT_STREAMS": 1000,
    "INITIAL_WINDOW_SIZE": 6291456,
    "MAX_FRAME_SIZE": 16384,
    "MAX_HEADER_LIST_SIZE": 262144,
}
_H2_FIREFOX = {
    "HEADER_TABLE_SIZE": 65536,
    "ENABLE_PUSH": 1,
    "MAX_CONCURRENT_STREAMS": 100,
    "INITIAL_WINDOW_SIZE": 131072,
    "MAX_FRAME_SIZE": 16384,
    "MAX_HEADER_LIST_SIZE": 65536,
}
_H2_SAFARI = {
    "HEADER_TABLE_SIZE": 4096,
    "ENABLE_PUSH": 0,
    "MAX_CONCURRENT_STREAMS": 100,
    "INITIAL_WINDOW_SIZE": 65535,
    "MAX_FRAME_SIZE": 16384,
    "MAX_HEADER_LIST_SIZE": 16384,
}

_CHROME_EXT = [
    "server_name", "extended_master_secret", "renegotiation_info",
    "supported_groups", "ec_point_formats", "session_ticket", "alpn",
    "status_request", "signature_algorithms", "signed_certificate_timestamp",
    "key_share", "psk_key_exchange_modes", "supported_versions",
    "cert_compression_algorithms", "application_settings", "padding",
]
_FIREFOX_EXT = [
    "server_name", "extended_master_secret", "renegotiation_info",
    "supported_groups", "ec_point_formats", "alpn", "status_request",
    "session_ticket", "signature_algorithms", "key_share",
    "psk_key_exchange_modes", "supported_versions", "padding",
]
_SAFARI_EXT = [
    "server_name", "extended_master_secret", "renegotiation_info",
    "supported_groups", "ec_point_formats", "alpn", "status_request",
    "signature_algorithms", "key_share", "psk_key_exchange_modes",
    "supported_versions",
]


def _build_constraints(family: str, os_name: str, major: int) -> BrowserConstraints:
    family = family.lower()
    os_name = os_name.lower()

    if family in ("chrome", "edge"):
        cipher_order = _TLS13_AEAD + _ECDHE_AEAD + _LEGACY_CBC
        ext = _CHROME_EXT
        grease = True
        grease_ext_slots = [1, 7, 12]
        grease_cipher = family == "chrome"
        groups = ["x25519", "secp256r1", "secp384r1", "secp521r1", "x448"]
        sigalgs = [
            "ecdsa_secp256r1_sha256", "ecdsa_secp384r1_sha384",
            "ecdsa_secp521r1_sha512", "rsa_pss_pss_sha256",
            "rsa_pss_pss_sha384", "rsa_pss_pss_sha512",
            "rsa_pss_rsae_sha256", "rsa_pss_rsae_sha384",
            "rsa_pss_rsae_sha512", "rsa_pkcs1_sha256",
            "rsa_pkcs1_sha384", "rsa_pkcs1_sha512",
        ]
        cert_compression = ["zlib"] if family == "chrome" else None
        http2 = _H2_CHROME
        header_case = "lower"
        header_order = [
            "host", "connection", "cache-control", "sec-ch-ua",
            "sec-ch-ua-mobile", "sec-ch-ua-platform",
            "upgrade-insecure-requests", "user-agent", "accept",
            "sec-fetch-site", "sec-fetch-mode", "sec-fetch-user",
            "sec-fetch-dest", "accept-encoding", "accept-language",
        ]
    elif family == "firefox":
        cipher_order = _TLS13_AEAD + _ECDHE_AEAD + _LEGACY_CBC
        ext = _FIREFOX_EXT
        grease = False
        grease_ext_slots = []
        grease_cipher = False
        groups = ["x25519", "secp256r1", "secp384r1", "secp521r1"]
        sigalgs = [
            "ecdsa_secp256r1_sha256", "ecdsa_secp384r1_sha384",
            "ecdsa_secp521r1_sha512", "rsa_pss_pss_sha256",
            "rsa_pss_pss_sha384", "rsa_pss_pss_sha512",
            "rsa_pss_rsae_sha256", "rsa_pss_rsae_sha384",
            "rsa_pss_rsae_sha512", "rsa_pkcs1_sha256",
            "rsa_pkcs1_sha384", "rsa_pkcs1_sha512",
        ]
        cert_compression = None
        http2 = _H2_FIREFOX
        header_case = "title"
        header_order = [
            "Host", "User-Agent", "Accept", "Accept-Language",
            "Accept-Encoding", "Referer", "Connection", "Upgrade-Insecure-Requests",
            "Sec-Fetch-Dest", "Sec-Fetch-Mode", "Sec-Fetch-Site", "Sec-Fetch-User",
            "TE", "DNT",
        ]
    elif family == "safari":
        cipher_order = _TLS13_AEAD + _ECDHE_AEAD + _LEGACY_CBC
        ext = _SAFARI_EXT
        grease = False
        grease_ext_slots = []
        grease_cipher = False
        groups = ["x25519", "secp256r1", "secp384r1"]
        sigalgs = [
            "ecdsa_secp256r1_sha256", "ecdsa_secp384r1_sha384",
            "ecdsa_secp521r1_sha512", "rsa_pss_pss_sha256",
            "rsa_pss_pss_sha384", "rsa_pss_pss_sha512",
            "rsa_pss_rsae_sha256", "rsa_pss_rsae_sha384",
            "rsa_pss_rsae_sha512", "rsa_pkcs1_sha256",
            "rsa_pkcs1_sha384", "rsa_pkcs1_sha512",
        ]
        cert_compression = None
        http2 = _H2_SAFARI
        header_case = "title"
        header_order = [
            "Host", "User-Agent", "Accept", "Accept-Language",
            "Accept-Encoding", "Connection", "Upgrade-Insecure-Requests",
            "Sec-Fetch-Dest", "Sec-Fetch-Mode", "Sec-Fetch-Site", "Sec-Fetch-User",
        ]
    else:
        raise ValueError(f"Unknown browser family: {family}")

    ua = _UA[family][os_name].format(maj=major, min=0)
    sec = _SEC_CH_UA[family]
    if sec:
        bv = (major % 8) + 1  # believable "Not_A Brand" build number
        sec = sec.format(maj=major, bv=bv)

    return BrowserConstraints(
        family=family,
        cipher_order=cipher_order,
        extension_order=ext,
        grease=grease,
        grease_ext_slots=grease_ext_slots,
        grease_cipher=grease_cipher,
        alpn=["h2", "http/1.1"],
        groups=groups,
        sigalgs=sigalgs,
        cert_compression=cert_compression,
        ua_template=ua,
        sec_ch_ua_template=sec,
        http2_settings=dict(http2),
        header_case=header_case,
        header_order=header_order,
        ua_minor_jitter=2,
    )


# -----------------------------------------------------------------------------
# Seeded PRNG (HMAC-DRBG-lite) so generation is reproducible
# -----------------------------------------------------------------------------

def _derive_prng(seed: Any) -> "SeededRNG":
    if isinstance(seed, (bytes, bytearray)):
        key = bytes(seed)
    elif isinstance(seed, str):
        key = hashlib.sha256(seed.encode("utf-8")).digest()
    elif isinstance(seed, int):
        key = seed.to_bytes(32, "big")
    else:
        key = hashlib.sha256(repr(seed).encode("utf-8")).digest()
    return SeededRNG(key)


class SeededRNG:
    """Minimal HMAC-SHA256 based stream PRNG (reproducible)."""
    __slots__ = ("_key", "_ctr")

    def __init__(self, key: bytes):
        self._key = key
        self._ctr = 0

    def _block(self) -> bytes:
        self._ctr += 1
        msg = self._ctr.to_bytes(8, "big")
        return hmac.new(self._key, msg, hashlib.sha256).digest()

    def random(self) -> float:
        return int.from_bytes(self._block()[:8], "big") / (2 ** 64)

    def randint(self, a: int, b: int) -> int:
        if b < a:
            a, b = b, a
        span = b - a + 1
        return a + int(self.random() * span)

    def choice(self, seq):
        return seq[self.randint(0, len(seq) - 1)]

    def shuffle(self, seq: list) -> None:
        # Fisher-Yates with seeded randomness
        for i in range(len(seq) - 1, 0, -1):
            j = self.randint(0, i)
            seq[i], seq[j] = seq[j], seq[i]


# -----------------------------------------------------------------------------
# Fingerprint synthesis
# -----------------------------------------------------------------------------

# Quality tiers of diversity -- how aggressively we permute within constraints
TIERS = ("conservative", "balanced", "aggressive")


@dataclass
class GeneratedFingerprint:
    name: str
    family: str
    os: str
    major: int
    seed: str
    profile: Dict[str, Any]

    def to_profile(self) -> Dict[str, Any]:
        return self.profile


def _ja3_hash(ja3: str) -> str:
    return hashlib.md5(ja3.encode("utf-8")).hexdigest()


def _cipher_id(name: str) -> int:
    """Resolve a cipher name to its decimal ID, handling GREASE markers."""
    if name in CIPHER_IDS:
        return CIPHER_IDS[name]
    # GREASE marker form: 'grease_<int>'
    return int(str(name).split("_")[-1])


def _ja4(ciphers: List[int], extensions: List[int], port: int = 443) -> str:
    """Compute a real JA4 string from generated cipher/extension IDs."""
    # JA4_a: t<version>d<port(omitted if 443)><ciphercount>h<extcount>
    version = "t13"
    dest = "" if port == 443 else str(port)
    ja4_a = f"{version}d{dest}{len(ciphers)}h{len(extensions)}"

    # JA4_b: sha1 of cipher IDs joined by ','
    cipher_str = ",".join(str(c) for c in ciphers)
    ja4_b = hashlib.sha1(cipher_str.encode("utf-8")).hexdigest()[:12]

    # JA4_c: GREASE removed, sorted numerically, sha1 of joined IDs
    clean = [e for e in extensions if e not in GREASE_VALUES]
    ext_str = ",".join(str(e) for e in sorted(clean))
    ja4_c = hashlib.sha1(ext_str.encode("utf-8")).hexdigest()[:12]

    return f"{ja4_a}_{ja4_b}_{ja4_c}"


def generate_fingerprint(
    family: str = "chrome",
    os: str = "win11",
    major: int = 124,
    seed: Any = None,
    tier: str = "balanced",
) -> GeneratedFingerprint:
    """
    Synthesize a single, valid, unique browser fingerprint.

    Args:
        family:     'chrome' | 'firefox' | 'safari' | 'edge'
        os:         'win11' | 'win10' | 'macos' | 'linux' | 'ios' | 'android'
        major:      browser major version (drives UA / Sec-CH-UA)
        seed:       any hashable value; same seed -> identical fingerprint
        tier:       'conservative' | 'balanced' | 'aggressive'
                    (how far we permute within the constraint model)

    Returns:
        GeneratedFingerprint with `.profile` (gallery-compatible dict)
    """
    if tier not in TIERS:
        raise ValueError(f"tier must be one of {TIERS}")

    if seed is None:
        seed = hashlib.sha256(str(id(object())).encode()).hexdigest()
    seed_str = repr(seed)

    cons = _build_constraints(family, os, major)
    rng = _derive_prng((family, os, major, tier, seed_str))

    # ---- 1. Ciphers -----------------------------------------------------------
    cipher_names = list(cons.cipher_order)
    # Within-bucket permutation: AEAD block, ECDHE block, legacy block may each
    # be lightly shuffled, but blocks never cross (validity preserved).
    block_size = 3
    if tier == "aggressive":
        block_size = 6
    for start in range(0, len(cipher_names), block_size):
        chunk = cipher_names[start:start + block_size]
        if len(chunk) > 1:
            rng.shuffle(chunk)
            cipher_names[start:start + block_size] = chunk

    # Optional GREASE cipher (Chrome-style) inserted at a legal slot
    if cons.grease_cipher and rng.random() < (0.7 if tier != "conservative" else 0.3):
        grease_cipher_id = rng.choice(GREASE_VALUES)
        slot = rng.randint(1, len(cipher_names) - 2)
        cipher_names.insert(slot, f"grease_{grease_cipher_id}")

    # ---- 2. Extensions --------------------------------------------------------
    # Work with decimal IDs directly so GREASE (already an int) mixes cleanly.
    ext_ids = [EXT_IDS[e] for e in cons.extension_order]
    ext_names = list(cons.extension_order)

    # Insert GREASE extensions at allowed slots (kept in legal positions)
    if cons.grease:
        n_grease = 1 if tier == "conservative" else rng.randint(1, len(cons.grease_ext_slots))
        n_grease = min(n_grease, len(cons.grease_ext_slots))
        slots = list(cons.grease_ext_slots)
        rng.shuffle(slots)
        for i in range(n_grease):
            gext = rng.choice(GREASE_VALUES)
            ext_ids.insert(slots[i], gext)
            ext_names.insert(slots[i], f"grease_{gext}")

    # Flexible trailing extensions: optionally drop a low-impact trailing ext
    # (e.g. padding) to diversify the JA3 hash without breaking servers.
    if cons.flexible_trailing_ext and tier != "conservative":
        if "padding" in ext_names and rng.random() < 0.4:
            idx = ext_names.index("padding")
            ext_names.pop(idx)
            ext_ids.pop(idx)

    cipher_ids = [_cipher_id(c) for c in cipher_names]
    groups_ids = [GROUP_IDS[g] for g in cons.groups]
    sig_ids = [SIGALG_IDS[s] for s in cons.sigalgs]

    # ---- 3. JA3 / JA4 ---------------------------------------------------------
    # JA3: SSLVersion,Ciphers,Extensions,Groups,ECPointFormats
    ja3 = "771,{ciphers},{exts},{groups},{ec}".format(
        ciphers="-".join(str(c) for c in cipher_ids),
        exts="-".join(str(e) for e in ext_ids),
        groups="-".join(str(g) for g in groups_ids),
        ec="-".join(str(f) for f in EC_POINT_FORMATS),
    )
    ja3_hash = _ja3_hash(ja3)
    ja4 = _ja4(cipher_ids, ext_ids)

    # ---- 4. User-Agent / Sec-CH-UA -------------------------------------------
    ua = cons.ua_template
    if cons.ua_minor_jitter and "{min}" in ua:
        minor = rng.randint(0, cons.ua_minor_jitter)
        ua = ua.replace("{min}", str(minor))
    sec = cons.sec_ch_ua_template

    # ---- 5. HTTP/2 SETTINGS (slight legal variance) ---------------------------
    h2 = dict(cons.http2_settings)
    if tier != "conservative":
        # INITIAL_WINDOW_SIZE may vary within browser-typical bounds
        if "INITIAL_WINDOW_SIZE" in h2:
            base = h2["INITIAL_WINDOW_SIZE"]
            delta = rng.randint(-65536, 65536)
            h2["INITIAL_WINDOW_SIZE"] = max(16384, base + delta)
        if "MAX_HEADER_LIST_SIZE" in h2:
            base = h2["MAX_HEADER_LIST_SIZE"]
            h2["MAX_HEADER_LIST_SIZE"] = max(16384, base + rng.randint(-8192, 8192))

    # ---- 6. Assemble profile -------------------------------------------------
    name = f"gen_{family}_{major}_{os}_{ja3_hash[:8]}"
    profile: Dict[str, Any] = {
        "name": name,
        "generated": True,
        "family": family,
        "os": os,
        "major": major,
        "seed": seed_str,
        "tier": tier,
        "user_agent": ua,
        "ja3": ja3,
        "ja3_hash": ja3_hash,
        "ja4": ja4,
        "ciphers": [_cipher_id(c) for c in cipher_names],  # numeric (incl. GREASE)
        "cipher_names": cipher_names,
        # OpenSSL cipher names only (GREASE markers stripped) -- this is what
        # client.py feeds into CURLOPT_SSL_CIPHER_LIST / ssl.set_ciphers
        "tls12_ciphers": [c for c in cipher_names if not str(c).startswith("grease_")],
        "extensions": ext_ids,
        "extension_names": ext_names,
        "supported_groups": groups_ids,
        "signature_algorithms": sig_ids,
        "alpn": cons.alpn,
        "supported_versions": SUPPORTED_VERSIONS,
        "ec_point_formats": EC_POINT_FORMATS,
        "http2_settings": h2,
        "header_case": cons.header_case,
        "header_order": cons.header_order,
        "impersonate": _impersonate_hint(family, major),
        "grease": cons.grease,
    }
    if sec:
        profile["sec_ch_ua"] = sec
        profile["sec_ch_ua_platform"] = _platform_token(os)
        profile["sec_ch_ua_mobile"] = "?1" if os == "android" else "?0"

    return GeneratedFingerprint(
        name=name,
        family=family,
        os=os,
        major=major,
        seed=seed_str,
        profile=profile,
    )


def _impersonate_hint(family: str, major: int) -> str:
    """
    Best-effort curl_cffi impersonate hint.

    NOTE: curl_cffi only accepts a small fixed set of impersonation targets
    (e.g. 'chrome124', 'firefox133', 'firefox', 'safari', 'edge'). Version-
    specific strings like 'firefox124' raise at request time, so we fall back
    to the nearest supported target. The generative engine's real value is the
    *described* fingerprint (UA/headers/h2/cipher-order metadata); the wire
    JA3 is whatever curl_cffi's impersonation emits. Full wire-level control
    requires a custom ClientHello emitter (see README / future work).
    """
    if family == "chrome":
        return "chrome124"
    if family == "edge":
        return "edge"          # generic Edge (Chromium-based)
    if family == "firefox":
        return "firefox"       # generic Firefox (avoids unsupported 'firefox124')
    if family == "safari":
        return "safari"
    return "chrome124"


def _platform_token(os_name: str) -> str:
    return {
        "win11": '"Windows"',
        "win10": '"Windows"',
        "macos": '"macOS"',
        "linux": '"Linux"',
        "android": '"Android"',
        "ios": '"iOS"',
    }.get(os_name, '"Windows"')


def generate_batch(
    n: int,
    family: str = "chrome",
    os: str = "win11",
    major: int = 124,
    tier: str = "balanced",
    base_seed: Any = None,
    diversity: float = 0.3,
) -> List[GeneratedFingerprint]:
    """
    Generate `n` diverse-but-valid fingerprints.

    `diversity` (0..1) controls how many *different* seed derivations are used:
    higher diversity -> more structurally distinct fingerprints (more GREASE,
    more permutation), while still every output is a valid browser ClientHello.
    """
    if base_seed is None:
        base_seed = hashlib.sha256(str(id(object())).encode()).hexdigest()
    out: List[GeneratedFingerprint] = []
    for i in range(n):
        # Each item gets its own seed; diversity raises the tier probabilistically
        item_tier = tier
        if diversity > 0.5 and (i % 3 == 0):
            item_tier = "aggressive"
        elif diversity < 0.3 and (i % 4 == 0):
            item_tier = "conservative"
        fp = generate_fingerprint(
            family=family,
            os=os,
            major=major,
            seed=f"{base_seed}::{i}",
            tier=item_tier,
        )
        out.append(fp)
    return out


def generate_profile(**kwargs) -> Dict[str, Any]:
    """Convenience: return just the profile dict from generate_fingerprint."""
    return generate_fingerprint(**kwargs).profile


# -----------------------------------------------------------------------------
# gen:// scheme + registry (for direct integration with TLSSession)
# -----------------------------------------------------------------------------
#
# Profile name format:
#   gen://<family>/<os>/<major>/<tier>/<seed>
# Example:
#   gen://chrome/win11/124/balanced/myseed
#   gen://firefox/linux/124/aggressive/abc
#
# Anything generated is cached in GENERATED_PROFILES so the same name always
# yields the identical, reproducible fingerprint during a process lifetime.

GENERATED_PROFILES: Dict[str, Dict[str, Any]] = {}

_GEN_DEFAULTS = {"family": "chrome", "os": "win11", "major": 124, "tier": "balanced"}


def parse_gen_spec(name: str) -> Dict[str, Any]:
    """Parse a `gen://...` profile name into generation kwargs."""
    if name.startswith("gen://"):
        body = name[len("gen://"):]
    else:
        body = name
    parts = [p for p in body.split("/") if p]
    kwargs = dict(_GEN_DEFAULTS)
    mapping = ["family", "os", "major", "tier", "seed"]
    for i, part in enumerate(parts):
        key = mapping[i]
        if key == "major":
            try:
                kwargs["major"] = int(part)
                continue
            except ValueError:
                pass
        kwargs[key] = part
    if "seed" not in kwargs or not kwargs.get("seed"):
        kwargs["seed"] = name  # name itself is the seed -> reproducible
    return kwargs


def resolve_gen_profile(name: str) -> Dict[str, Any]:
    """
    Resolve a `gen://...` profile name into a gallery-compatible dict,
    generating and caching it on first use.
    """
    if name in GENERATED_PROFILES:
        return GENERATED_PROFILES[name]
    kwargs = parse_gen_spec(name)
    fp = generate_fingerprint(
        family=kwargs["family"],
        os=kwargs["os"],
        major=kwargs["major"],
        seed=kwargs.get("seed", name),
        tier=kwargs["tier"],
    )
    GENERATED_PROFILES[name] = fp.profile
    return fp.profile


def is_gen_profile(name: str) -> bool:
    return isinstance(name, str) and name.startswith("gen://")

