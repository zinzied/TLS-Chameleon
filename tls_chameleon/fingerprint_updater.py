"""
TLS-Chameleon Fingerprint Updater
=================================

Auto-update fingerprints from live sources.

Features:
- Fetch latest browser fingerprint data from public sources
- Cache fingerprints locally with TTL
- Background update capability
- Fallback to bundled fingerprints

Note: This is an optional feature. The bundled fingerprint gallery
will always work without network access.
"""

import json
import os
import time
from typing import Dict, Any, Optional, List
from pathlib import Path


# Cache configuration
DEFAULT_CACHE_DIR = Path.home() / ".tls_chameleon" / "cache"
CACHE_TTL_SECONDS = 86400 * 7  # 1 week


# Public fingerprint data sources
FINGERPRINT_SOURCES = {
    "ja3er": "https://ja3er.com/getAllHashesJson",
    "ja4db": "https://ja4db.com/api/read/",
    # GitHub mirror of fingerprint data
    "github_ja3": "https://raw.githubusercontent.com/salesforce/ja3/master/lists/osx-nix-ja3.json",
}


class FingerprintUpdater:
    """
    Updates fingerprint profiles from online sources.
    
    This is an optional enhancement - the library works perfectly
    with bundled fingerprints.
    """
    
    def __init__(self, cache_dir: Optional[Path] = None):
        """
        Initialize the updater.
        
        Args:
            cache_dir: Directory for caching downloaded fingerprints
        """
        self.cache_dir = cache_dir or DEFAULT_CACHE_DIR
        self._ensure_cache_dir()
        self._http_client = None
    
    def _ensure_cache_dir(self):
        """Create cache directory if it doesn't exist."""
        try:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
        except OSError:
            pass
    
    def _get_http_client(self):
        """Get or create HTTP client for fetching data."""
        if self._http_client is None:
            try:
                import httpx
                self._http_client = httpx.Client(timeout=30.0)
            except ImportError:
                # Try requests as fallback
                try:
                    import requests
                    self._http_client = requests
                except ImportError:
                    return None
        return self._http_client
    
    def _get_cache_path(self, source_name: str) -> Path:
        """Get the cache file path for a source."""
        return self.cache_dir / f"{source_name}.json"
    
    def _is_cache_valid(self, source_name: str) -> bool:
        """Check if cached data is still valid (not expired)."""
        cache_path = self._get_cache_path(source_name)
        if not cache_path.exists():
            return False
        
        # Check age
        mtime = cache_path.stat().st_mtime
        age = time.time() - mtime
        return age < CACHE_TTL_SECONDS
    
    def _read_cache(self, source_name: str) -> Optional[Dict[str, Any]]:
        """Read cached fingerprint data."""
        cache_path = self._get_cache_path(source_name)
        if not cache_path.exists():
            return None
        
        try:
            with open(cache_path, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            return None
    
    def _write_cache(self, source_name: str, data: Dict[str, Any]):
        """Write fingerprint data to cache."""
        cache_path = self._get_cache_path(source_name)
        try:
            with open(cache_path, "w") as f:
                json.dump(data, f, indent=2)
        except OSError:
            pass
    
    def fetch_fingerprints(
        self, 
        source: str = "ja3er",
        force_refresh: bool = False
    ) -> Optional[Dict[str, Any]]:
        """
        Fetch fingerprint data from an online source.
        
        Args:
            source: Source name (ja3er, ja4db, github_ja3)
            force_refresh: Ignore cache and fetch fresh data
            
        Returns:
            Dict of fingerprint data or None if unavailable
        """
        # Check cache first
        if not force_refresh and self._is_cache_valid(source):
            cached = self._read_cache(source)
            if cached:
                return cached
        
        # Get HTTP client
        client = self._get_http_client()
        if not client:
            # No HTTP client available, try cache even if expired
            return self._read_cache(source)
        
        # Get source URL
        url = FINGERPRINT_SOURCES.get(source)
        if not url:
            return None
        
        try:
            # Fetch data
            if hasattr(client, "get"):
                response = client.get(url)
                if hasattr(response, "json"):
                    data = response.json()
                else:
                    data = response.json()
            else:
                # httpx client
                response = client.get(url)
                data = response.json()
            
            # Cache the result
            self._write_cache(source, {"data": data, "timestamp": time.time()})
            
            return {"data": data, "timestamp": time.time()}
            
        except Exception:
            # Fetch failed, return cached data even if expired
            return self._read_cache(source)
    
    def get_latest_ja3(self, browser: str = "chrome") -> Optional[str]:
        """
        Get the latest JA3 hash for a browser.
        
        Args:
            browser: Browser name (chrome, firefox, safari)
            
        Returns:
            JA3 hash string or None
        """
        data = self.fetch_fingerprints("ja3er")
        if not data or "data" not in data:
            return None
        
        # Search for matching browser in fingerprint data
        browser_lower = browser.lower()
        fingerprints = data.get("data", [])
        
        if isinstance(fingerprints, list):
            for fp in fingerprints:
                user_agent = fp.get("User-Agent", "").lower()
                if browser_lower in user_agent:
                    return fp.get("JA3 Hash") or fp.get("ja3_hash")
        
        return None
    
    def update_profile(
        self, 
        profile_name: str, 
        profile: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Update a profile with the latest fingerprint data.
        
        Args:
            profile_name: Name of the profile
            profile: Current profile dict
            
        Returns:
            Updated profile dict
        """
        import copy
        updated = copy.deepcopy(profile)
        
        # Try to get latest JA3 for this browser type
        browser = profile_name.split("_")[0]  # e.g., "chrome" from "chrome_120_win11"
        latest_ja3 = self.get_latest_ja3(browser)
        
        if latest_ja3:
            updated["ja3_hash"] = latest_ja3
        
        return updated
    
    def update_gallery(self) -> int:
        """
        Update all profiles in the fingerprint gallery.
        
        Returns:
            Number of profiles updated
        """
        from .fingerprint_gallery import FINGERPRINT_GALLERY
        
        updated_count = 0
        for name, profile in FINGERPRINT_GALLERY.items():
            try:
                new_profile = self.update_profile(name, profile)
                if new_profile.get("ja3_hash") != profile.get("ja3_hash"):
                    # Update in-place
                    profile["ja3_hash"] = new_profile["ja3_hash"]
                    updated_count += 1
            except Exception:
                continue
        
        return updated_count
    
    def get_cache_info(self) -> Dict[str, Any]:
        """
        Get information about cached fingerprint data.
        
        Returns:
            Dict with cache status info
        """
        info = {
            "cache_dir": str(self.cache_dir),
            "sources": {}
        }
        
        for source_name in FINGERPRINT_SOURCES:
            cache_path = self._get_cache_path(source_name)
            if cache_path.exists():
                mtime = cache_path.stat().st_mtime
                age = time.time() - mtime
                info["sources"][source_name] = {
                    "cached": True,
                    "age_seconds": int(age),
                    "valid": age < CACHE_TTL_SECONDS,
                }
            else:
                info["sources"][source_name] = {
                    "cached": False,
                    "age_seconds": None,
                    "valid": False,
                }
        
        return info
    
    def clear_cache(self):
        """Clear all cached fingerprint data."""
        for source_name in FINGERPRINT_SOURCES:
            cache_path = self._get_cache_path(source_name)
            try:
                if cache_path.exists():
                    cache_path.unlink()
            except OSError:
                pass


# Convenience function
def update_fingerprints(force: bool = False) -> int:
    """
    Update fingerprint gallery from online sources.
    
    Args:
        force: Force refresh even if cache is valid
        
    Returns:
        Number of profiles updated
    """
    updater = FingerprintUpdater()
    if force:
        updater.clear_cache()
    return updater.update_gallery()
