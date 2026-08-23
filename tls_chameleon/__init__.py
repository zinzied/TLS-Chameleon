"""
TLS-Chameleon v2.0
==================

Anti-Fingerprinting HTTP client that spoofs real browser TLS fingerprints
with a simple, requests-like API.

v2.0 Features:
- 30+ browser fingerprint profiles (Chrome, Firefox, Safari, Edge)
- Multi-OS support (Windows 10, Windows 11, macOS, Linux, iOS, Android)
- Fingerprint randomization to avoid pattern detection
- HTTP/2 priority simulation
- Auto-update system for fingerprints
"""

from .client import (
    TLSChameleon,
    Session,
    TLSSession,  # New v2.0: recommended alias
    request,
    get,
    post,
    put,
    delete,
    head,
    patch,
    options,
    list_available_profiles,  # New v2.0
    ChameleonResponse,
)
from .magnet import Magnet

from .async_client import AsyncTLSChameleon, AsyncSession

# New v2.0 modules
try:
    from .fingerprint_gallery import (
        FINGERPRINT_GALLERY,
        get_profile,
        get_all_profiles,
        get_profiles_by_browser,
        get_profiles_by_os,
        get_random_profile,
        randomize_profile,
    )
except ImportError:
    FINGERPRINT_GALLERY = {}
    get_profile = None

# Generative Fingerprint Engine (private enhancement)
try:
    from .gen_fingerprint import (
        generate_fingerprint,
        generate_batch,
        generate_profile,
        resolve_gen_profile,
        parse_gen_spec,
        is_gen_profile,
        GeneratedFingerprint,
    )
except ImportError:
    generate_fingerprint = None

try:
    from .http2_simulator import HTTP2Profile, get_http2_profile
except ImportError:
    HTTP2Profile = None

try:
    from .randomizer import FingerprintRandomizer, create_variant_profile
except ImportError:
    FingerprintRandomizer = None

try:
    from .fingerprint_updater import FingerprintUpdater, update_fingerprints
except ImportError:
    FingerprintUpdater = None

# Phase 2: structured fingerprint system
try:
    from .fingerprint import (
        Fingerprint,
        FingerprintRegistry,
        FingerprintSimilarity,
        SimilarityResult,
        SimilarityWeights,
        TLSFingerprint,
        HTTP2Fingerprint,
        HeaderFingerprint,
        Metadata,
        ValidationIssue,
        validate_fingerprint,
        validate_profile_dict,
        diff_fingerprints,
        DiffReport,
        capture,
        CaptureResult,
        HeaderProfile,
        ConsistencyIssue,
        check_header_consistency,
    )
except ImportError:  # pragma: no cover - defensive
    pass

# Phase 3: diagnostics + redaction
from .diagnostics import (
    NetworkTrace,
    collect_trace,
    InspectResult,
    inspect_url,
    CheckResult,
    DoctorReport,
    doctor,
)
from .security.redaction import (
    REDACTED,
    is_sensitive_header,
    redact_headers,
    redact_mapping,
    redact_url,
)
from .session_state import SessionState
from .transport import ProxyConfig, SessionConfig

# Phase 4: adaptive engine + deterministic randomization
from .adaptive import DomainMemory, DEFAULT_DOMAIN_MEMORY_MAX
from .randomizer import derive_seed_rng

# v3.1: high-level WHAT-vs-HOW API
from .client import Chameleon
from .async_client import AsyncChameleon

__version__ = "3.1.0"

__all__ = [
    # Core classes
    "TLSChameleon",
    "Session",
    "TLSSession",
    "ChameleonResponse",
    "Magnet",

    # Async core classes
    "AsyncTLSChameleon",
    "AsyncSession",

    # Request functions
    "request",
    "get",
    "post",
    "put",
    "delete",
    "head",
    "patch",
    "options",

    # Profile utilities
    "list_available_profiles",
    "FINGERPRINT_GALLERY",
    "get_profile",
    "get_all_profiles",
    "get_profiles_by_browser",
    "get_profiles_by_os",
    "get_random_profile",
    "randomize_profile",
    
    # HTTP/2 simulation
    "HTTP2Profile",
    "get_http2_profile",
    
    # Randomization
    "FingerprintRandomizer",
    "create_variant_profile",
    
    # Generative Fingerprint Engine
    "generate_fingerprint",
    "generate_batch",
    "generate_profile",
    "resolve_gen_profile",
    "parse_gen_spec",
    "is_gen_profile",
    "GeneratedFingerprint",
    
    # Auto-update
    "FingerprintUpdater",
    "update_fingerprints",

    # Diagnostics (Phase 3)
    "NetworkTrace",
    "collect_trace",
    "InspectResult",
    "inspect_url",
    "CheckResult",
    "DoctorReport",
    "doctor",

    # Redaction (Phase 3)
    "REDACTED",
    "is_sensitive_header",
    "redact_headers",
    "redact_mapping",
    "redact_url",

    # Adaptive engine (Phase 4)
    "DomainMemory",
    "DEFAULT_DOMAIN_MEMORY_MAX",
    "derive_seed_rng",
    "HeaderProfile",
    "ConsistencyIssue",
    "check_header_consistency",

    # High-level API (3.1)
    "Chameleon",
    "AsyncChameleon",
    "ProxyConfig",
    "SessionConfig",
    "SessionState",
]
