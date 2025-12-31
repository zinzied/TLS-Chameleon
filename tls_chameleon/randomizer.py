"""
TLS-Chameleon Fingerprint Randomizer
====================================

Generates realistic fingerprint variations within a browser family.

This helps avoid pattern detection by creating slight variations
that still look like the same browser but differ enough to appear
as different users.

Variations include:
- Minor User-Agent version changes
- TLS extension order shuffles (where browsers allow)
- Screen resolution hints
- Timezone suggestions
"""

import random
import copy
import re
from typing import Dict, Any, Optional, List, Tuple


class FingerprintRandomizer:
    """
    Creates randomized variants of browser fingerprint profiles.
    
    The variants are realistic - they stay within the bounds of what
    the original browser would actually produce.
    """
    
    def __init__(self, profile: Dict[str, Any]):
        """
        Initialize the randomizer with a base profile.
        
        Args:
            profile: A fingerprint profile dict from fingerprint_gallery
        """
        self.base_profile = profile
        self.randomization_config = profile.get("randomization", {})
    
    def generate_variant(self) -> Dict[str, Any]:
        """
        Generate a randomized variant of the base profile.
        
        Returns:
            A new profile dict with slight variations
        """
        variant = copy.deepcopy(self.base_profile)
        
        # Apply User-Agent variance
        if self.randomization_config.get("ua_minor_variance", False):
            variant["user_agent"] = self._randomize_user_agent(variant.get("user_agent", ""))
            variant["sec_ch_ua"] = self._randomize_sec_ch_ua(variant.get("sec_ch_ua", ""))
        
        # Apply TLS extension order variance
        ext_variance = self.randomization_config.get("extension_variance", 0)
        if ext_variance > 0 and "extensions" in variant:
            variant["extensions"] = self._randomize_extensions(
                variant["extensions"], ext_variance
            )
        
        # Apply cipher order variance (if allowed by browser)
        if self.randomization_config.get("cipher_shuffle", False) and "ciphers" in variant:
            variant["ciphers"] = self._randomize_ciphers(variant["ciphers"])
        
        return variant
    
    def _randomize_user_agent(self, ua: str) -> str:
        """
        Create a slight variation in the User-Agent string.
        
        Changes the minor/patch version numbers by small amounts.
        """
        if not ua:
            return ua
        
        # Pattern for Chrome version: Chrome/120.0.6099.130
        def bump_chrome_version(match):
            major = match.group(1)
            minor = match.group(2)
            build = int(match.group(3))
            patch = int(match.group(4))
            
            # Vary build by -50 to +100
            new_build = max(0, build + random.randint(-50, 100))
            # Vary patch by -20 to +50
            new_patch = max(0, patch + random.randint(-20, 50))
            
            return f"Chrome/{major}.{minor}.{new_build}.{new_patch}"
        
        ua = re.sub(
            r'Chrome/(\d+)\.(\d+)\.(\d+)\.(\d+)',
            bump_chrome_version,
            ua
        )
        
        # Pattern for Firefox version: Firefox/120.0
        def bump_firefox_version(match):
            major = match.group(1)
            minor = int(match.group(2))
            # Only vary minor occasionally
            if random.random() < 0.3:
                minor = max(0, minor + random.randint(0, 1))
            return f"Firefox/{major}.{minor}"
        
        ua = re.sub(
            r'Firefox/(\d+)\.(\d+)',
            bump_firefox_version,
            ua
        )
        
        return ua
    
    def _randomize_sec_ch_ua(self, sec_ch_ua: str) -> str:
        """
        Randomize the Sec-CH-UA header slightly.
        """
        if not sec_ch_ua:
            return sec_ch_ua
        
        # The version number in sec_ch_ua should match the UA
        # This is informational - real randomization happens in User-Agent
        return sec_ch_ua
    
    def _randomize_extensions(self, extensions: List[int], variance: int) -> List[int]:
        """
        Apply slight reordering to TLS extensions.
        
        Firefox allows some extension order variance; Chrome does not.
        """
        if not extensions or variance <= 0:
            return extensions
        
        exts = list(extensions)
        
        # Perform swap operations
        swaps = min(variance, len(exts) - 1)
        for _ in range(swaps):
            i = random.randint(0, len(exts) - 2)
            exts[i], exts[i + 1] = exts[i + 1], exts[i]
        
        return exts
    
    def _randomize_ciphers(self, ciphers: List[str]) -> List[str]:
        """
        Shuffle cipher suite order (only for browsers that allow it).
        
        Most modern browsers have fixed cipher order.
        """
        if not ciphers:
            return ciphers
        
        # Create a shuffled copy
        shuffled = list(ciphers)
        random.shuffle(shuffled)
        return shuffled
    
    @staticmethod
    def get_random_screen_resolution() -> Tuple[int, int]:
        """
        Get a random but realistic screen resolution.
        
        Returns:
            Tuple of (width, height)
        """
        common_resolutions = [
            (1920, 1080),  # Full HD - most common
            (1920, 1080),  # Weight it higher
            (1920, 1080),
            (2560, 1440),  # 2K
            (1366, 768),   # HD laptop
            (1536, 864),   # HD+
            (1440, 900),   # WXGA+
            (1680, 1050),  # WSXGA+
            (2560, 1600),  # WQXGA
            (3840, 2160),  # 4K
            (1280, 720),   # HD
            (1600, 900),   # HD+
        ]
        return random.choice(common_resolutions)
    
    @staticmethod
    def get_random_timezone() -> Tuple[str, int]:
        """
        Get a random but common timezone.
        
        Returns:
            Tuple of (timezone_name, offset_minutes)
        """
        common_timezones = [
            ("America/New_York", -300),
            ("America/Chicago", -360),
            ("America/Los_Angeles", -480),
            ("Europe/London", 0),
            ("Europe/Paris", 60),
            ("Europe/Berlin", 60),
            ("Asia/Tokyo", 540),
            ("Asia/Shanghai", 480),
            ("Australia/Sydney", 660),
            ("America/Sao_Paulo", -180),
        ]
        return random.choice(common_timezones)
    
    @staticmethod
    def get_random_language_preference() -> str:
        """
        Get a random but common Accept-Language header.
        
        Returns:
            Accept-Language header value
        """
        common_languages = [
            "en-US,en;q=0.9",
            "en-GB,en;q=0.9",
            "en-US,en;q=0.9,es;q=0.8",
            "en-US,en;q=0.9,fr;q=0.8",
            "de-DE,de;q=0.9,en;q=0.8",
            "fr-FR,fr;q=0.9,en;q=0.8",
            "es-ES,es;q=0.9,en;q=0.8",
            "ja-JP,ja;q=0.9,en;q=0.8",
            "zh-CN,zh;q=0.9,en;q=0.8",
            "pt-BR,pt;q=0.9,en;q=0.8",
        ]
        return random.choice(common_languages)


def create_variant_profile(profile_name: str, randomize: bool = True) -> Dict[str, Any]:
    """
    Create a fingerprint profile variant from a gallery profile.
    
    Args:
        profile_name: Name of the profile in FINGERPRINT_GALLERY
        randomize: Whether to apply randomization
        
    Returns:
        Profile dict (randomized if requested)
    """
    from .fingerprint_gallery import FINGERPRINT_GALLERY, get_profile
    
    profile = get_profile(profile_name)
    if not profile:
        # Fall back to chrome_120_win11
        profile = FINGERPRINT_GALLERY.get("chrome_120_win11", {})
    
    if randomize:
        randomizer = FingerprintRandomizer(profile)
        return randomizer.generate_variant()
    
    return copy.deepcopy(profile)


def batch_generate_variants(
    profile_name: str, 
    count: int = 10
) -> List[Dict[str, Any]]:
    """
    Generate multiple unique variants of a profile.
    
    Useful for rotating through different "identities" while
    maintaining the same browser fingerprint family.
    
    Args:
        profile_name: Base profile name
        count: Number of variants to generate
        
    Returns:
        List of variant profile dicts
    """
    variants = []
    for _ in range(count):
        variant = create_variant_profile(profile_name, randomize=True)
        variants.append(variant)
    return variants
