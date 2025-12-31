"""
TLS-Chameleon Browser Profiles
==============================

Legacy profiles module - maintained for backward compatibility.
New code should use fingerprint_gallery module directly.

This module provides a unified interface to both old simple profiles
and the new comprehensive fingerprint gallery.
"""

from typing import Dict, Any, Optional, List

# Import new fingerprint gallery
from .fingerprint_gallery import (
    FINGERPRINT_GALLERY,
    get_profile as gallery_get_profile,
    get_all_profiles,
    get_profiles_by_browser,
    get_profiles_by_os,
    get_random_profile,
    randomize_profile,
)


# =============================================================================
# LEGACY PROFILES (Backward Compatibility)
# =============================================================================

# These map old simple names to new gallery profiles
PROFILES = {
    "chrome_120": {
        "impersonate": "chrome120",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "tls12_ciphers": [
            "ECDHE-ECDSA-AES128-GCM-SHA256",
            "ECDHE-RSA-AES128-GCM-SHA256",
            "ECDHE-ECDSA-AES256-GCM-SHA384",
            "ECDHE-RSA-AES256-GCM-SHA384",
            "ECDHE-ECDSA-CHACHA20-POLY1305",
            "ECDHE-RSA-CHACHA20-POLY1305",
        ],
        "header_case": "lower",
        "header_order": ["host", "user-agent", "accept", "accept-language", "accept-encoding", "connection", "upgrade-insecure-requests"],
    },
    "chrome_124": {
        "impersonate": "chrome124",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "tls12_ciphers": [
            "ECDHE-ECDSA-AES128-GCM-SHA256",
            "ECDHE-RSA-AES128-GCM-SHA256",
            "ECDHE-ECDSA-AES256-GCM-SHA384",
            "ECDHE-RSA-AES256-GCM-SHA384",
            "ECDHE-ECDSA-CHACHA20-POLY1305",
            "ECDHE-RSA-CHACHA20-POLY1305",
        ],
        "header_case": "lower",
        "header_order": ["host", "user-agent", "accept", "accept-language", "accept-encoding", "connection", "priority"],
    },
    "firefox_120": {
        "impersonate": "firefox120",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
        "tls12_ciphers": [
            "ECDHE-ECDSA-AES128-GCM-SHA256",
            "ECDHE-RSA-AES128-GCM-SHA256",
            "ECDHE-ECDSA-AES256-GCM-SHA384",
            "ECDHE-RSA-AES256-GCM-SHA384",
            "ECDHE-ECDSA-CHACHA20-POLY1305",
            "ECDHE-RSA-CHACHA20-POLY1305",
        ],
        "header_case": "title",
        "header_order": ["Host", "User-Agent", "Accept", "Accept-Language", "Accept-Encoding", "Connection", "Upgrade-Insecure-Requests"],
    },
    "mobile_safari_17": {
        "impersonate": "safari17_0",
        "user_agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
        "tls12_ciphers": [
            "ECDHE-ECDSA-AES128-GCM-SHA256",
            "ECDHE-RSA-AES128-GCM-SHA256",
            "ECDHE-ECDSA-AES256-GCM-SHA384",
            "ECDHE-RSA-AES256-GCM-SHA384",
            "ECDHE-ECDSA-CHACHA20-POLY1305",
            "ECDHE-RSA-CHACHA20-POLY1305",
        ],
        "header_case": "title",
        "header_order": ["Host", "Accept", "Accept-Language", "User-Agent", "Accept-Encoding", "Connection"],
    },
    "ios_safari_17": {
        "impersonate": "ios17_0",
        "user_agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
        "tls12_ciphers": [
            "ECDHE-ECDSA-AES128-GCM-SHA256",
            "ECDHE-RSA-AES128-GCM-SHA256",
            "ECDHE-ECDSA-AES256-GCM-SHA384",
            "ECDHE-RSA-AES256-GCM-SHA384",
            "ECDHE-ECDSA-CHACHA20-POLY1305",
            "ECDHE-RSA-CHACHA20-POLY1305",
        ],
        "header_case": "title",
        "header_order": ["Host", "Accept", "Accept-Language", "User-Agent", "Accept-Encoding", "Connection"],
    },
}

DEFAULT_PROFILE = "chrome_120"


# =============================================================================
# UNIFIED API - Works with both legacy and new profiles
# =============================================================================

def get_profile(name: str, use_gallery: bool = True) -> Optional[Dict[str, Any]]:
    """
    Get a browser profile by name.
    
    This function checks both the legacy PROFILES dict and the new
    FINGERPRINT_GALLERY for maximum compatibility.
    
    Args:
        name: Profile name (e.g., "chrome_120" or "chrome_120_win11")
        use_gallery: Whether to check the new gallery first (default True)
        
    Returns:
        Profile dict or None if not found
    """
    if use_gallery:
        # Check new gallery first
        gallery_profile = gallery_get_profile(name)
        if gallery_profile:
            # Convert to legacy format if needed (for client.py compatibility)
            return _convert_to_legacy_format(gallery_profile)
    
    # Fall back to legacy profiles
    return PROFILES.get(name)


def _convert_to_legacy_format(gallery_profile: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convert a gallery profile to legacy format for client.py compatibility.
    
    The legacy format uses `tls12_ciphers` while the new format uses `ciphers`.
    """
    result = dict(gallery_profile)
    
    # Convert ciphers key
    if "ciphers" in result and "tls12_ciphers" not in result:
        result["tls12_ciphers"] = result["ciphers"]
    
    return result


def list_profiles(browser: Optional[str] = None, os_name: Optional[str] = None) -> List[str]:
    """
    List available profile names.
    
    Args:
        browser: Filter by browser (chrome, firefox, safari, edge)
        os_name: Filter by OS (win11, win10, macos, linux, ios, android)
        
    Returns:
        List of profile names
    """
    all_names = list(PROFILES.keys()) + list(FINGERPRINT_GALLERY.keys())
    unique_names = sorted(set(all_names))
    
    if browser:
        browser = browser.lower()
        unique_names = [n for n in unique_names if n.startswith(browser)]
    
    if os_name:
        os_name = os_name.lower()
        unique_names = [n for n in unique_names if os_name in n]
    
    return unique_names


# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
    "PROFILES",
    "FINGERPRINT_GALLERY",
    "DEFAULT_PROFILE",
    "get_profile",
    "list_profiles",
    "get_all_profiles",
    "get_profiles_by_browser",
    "get_profiles_by_os",
    "get_random_profile",
    "randomize_profile",
]
