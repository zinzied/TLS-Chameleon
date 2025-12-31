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
)

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

__version__ = "2.0.0"

__all__ = [
    # Core classes
    "TLSChameleon",
    "Session",
    "TLSSession",
    
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
    
    # Auto-update
    "FingerprintUpdater",
    "update_fingerprints",
]
