"""Header-profile consistency checking.

Headers are part of the overall fingerprint. This engine detects internal
contradictions -- e.g. a Chrome User-Agent combined with Firefox-specific
client hints, or a mobile platform claim on a desktop UA -- and reports
them as ``Profile inconsistency detected`` findings.

Correctness comes first: this module never randomizes anything.
"""

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

__all__ = ["ConsistencyIssue", "HeaderProfile", "check_header_consistency"]


@dataclass
class ConsistencyIssue:
    """One consistency finding."""

    severity: str  # "error" | "warning"
    code: str
    message: str

    def to_dict(self) -> Dict[str, str]:
        return {"severity": self.severity, "code": self.code,
                "message": self.message}


@dataclass
class HeaderProfile:
    """Normalized view of a profile's header-relevant fields."""

    user_agent: Optional[str] = None
    ua_family: Optional[str] = None          # chrome | firefox | safari | edge | bot
    ua_version: Optional[str] = None         # major version string
    header_case: str = "lower"
    header_order: List[str] = None
    sec_ch_ua: Optional[str] = None
    sec_ch_ua_platform: Optional[str] = None
    sec_ch_ua_mobile: Optional[str] = None

    def __post_init__(self) -> None:
        if self.header_order is None:
            self.header_order = []

    @classmethod
    def from_profile_dict(cls, profile: Dict[str, Any]) -> "HeaderProfile":
        return cls(
            user_agent=profile.get("user_agent"),
            **_family_and_version(profile.get("user_agent")),
            header_case=str(profile.get("header_case", "lower")),
            header_order=[str(h).lower() for h in (profile.get("header_order") or [])],
            sec_ch_ua=profile.get("sec_ch_ua"),
            sec_ch_ua_platform=profile.get("sec_ch_ua_platform"),
            sec_ch_ua_mobile=(
                str(profile["sec_ch_ua_mobile"])
                if profile.get("sec_ch_ua_mobile") is not None
                else None
            ),
        )


def _family_and_version(user_agent: Optional[str]) -> Dict[str, Optional[str]]:
    if not user_agent:
        return {"ua_family": None, "ua_version": None}
    patterns = [
        ("edge", r"(?:Edge|Edg)/(\d+)"),
        ("chrome", r"Chrome/(\d+)"),
        ("firefox", r"Firefox/(\d+)"),
        ("safari", r"Version/(\d+).*Safari"),
    ]
    lowered = user_agent.lower()
    for family, pattern in patterns:
        match = re.search(pattern, user_agent, re.IGNORECASE)
        if match:
            # Edge UAs also contain 'Chrome/' -- check Edge first (above).
            return {"ua_family": family, "ua_version": match.group(1)}
    if "bot" in lowered or "spider" in lowered or "crawler" in lowered:
        return {"ua_family": "bot", "ua_version": None}
    return {"ua_family": None, "ua_version": None}


def _brands_in_sec_ch_ua(sec_ch_ua: Optional[str]) -> List[str]:
    if not sec_ch_ua:
        return []
    brands = []
    for name_match in re.finditer(r'"?([A-Za-z _]+)"?;v="\d+"', sec_ch_ua):
        brand = name_match.group(1).strip().lower()
        if brand not in ("not a brand", "not_a_brand", "not"):
            brands.append(brand)
    return brands


def check_header_consistency(profile: Dict[str, Any]) -> List[ConsistencyIssue]:
    """Check a profile dict for header-level contradictions.

    Errors mark impossible/self-contradictory combinations; warnings mark
    suspicious-but-possible ones.
    """
    hp = HeaderProfile.from_profile_dict(profile)
    issues: List[ConsistencyIssue] = []

    def error(code: str, message: str) -> None:
        issues.append(
            ConsistencyIssue("error", code, f"Profile inconsistency detected: {message}")
        )

    def warn(code: str, message: str) -> None:
        issues.append(ConsistencyIssue("warning", code, message))

    # --- UA vs Sec-CH-UA brand -----------------------------------------
    brands = _brands_in_sec_ch_ua(hp.sec_ch_ua)
    if hp.ua_family == "chrome" and hp.sec_ch_ua and brands:
        chromium_based = any(b in ("chromium", "chrome", "edge",
                                   "google chrome", "microsoft edge")
                             for b in brands)
        firefox_like = any(b in ("firefox", "gecko") for b in brands)
        safari_like = any(b in ("safari", "webkit") for b in brands)
        if firefox_like and not chromium_based:
            error("chrome_ua_with_firefox_brands",
                  "Chrome User-Agent combined with Firefox Sec-CH-UA brands "
                  f"{brands}")
        elif safari_like and not chromium_based:
            error("chrome_ua_with_safari_brands",
                  "Chrome User-Agent combined with Safari Sec-CH-UA brands "
                  f"{brands}")

    if hp.ua_family == "firefox" and hp.sec_ch_ua:
        # Firefox does NOT send Sec-CH-UA at all.
        error("firefox_with_client_hints",
              "Firefox never sends Sec-CH-UA headers but the profile defines them")

    if hp.ua_family == "safari" and hp.sec_ch_ua:
        # Safari sends Sec-CH-UA only as opt-in draft; treat as warning.
        warn("safari_with_client_hints",
             "Safari rarely sends Sec-CH-UA headers; verify this is intended")

    # --- UA version vs Sec-CH-UA versions -------------------------------
    if hp.ua_family in ("chrome", "edge") and hp.sec_ch_ua and hp.ua_version:
        versions = [int(v) for v in re.findall(r'v="(\d+)"', hp.sec_ch_ua)]
        if versions:
            try:
                ua_major = int(hp.ua_version)
            except ValueError:
                ua_major = None
            if ua_major and max(versions) - ua_major > 1:
                warn("version_mismatch",
                     f"Sec-CH-UA version(s) {sorted(set(versions))} far from "
                     f"UA major {ua_major}")

    # --- Mobile claim vs platform ---------------------------------------
    mobile_claim = hp.sec_ch_ua_mobile not in (None, "", "?0")
    if mobile_claim and hp.sec_ch_ua_platform:
        platform = hp.sec_ch_ua_platform.strip().strip('"').lower()
        if platform in ("windows", "macos", "linux"):
            error("mobile_claim_on_desktop_platform",
                  f"Sec-CH-UA-Mobile claims mobile on desktop platform '{platform}'")

    # --- UA OS token vs Sec-CH-UA platform ------------------------------
    if hp.user_agent and hp.sec_ch_ua_platform:
        platform = hp.sec_ch_ua_platform.strip().strip('"').lower()
        ua_lower = hp.user_agent.lower()
        os_tokens = {
            "windows": ("windows nt",),
            "macos": ("mac os x", "macintosh"),
            "linux": ("linux", "x11"),
            "android": ("android",),
            "ios": ("iphone", "ipad"),
        }
        matched = [os_name for os_name, tokens in os_tokens.items()
                   if any(t in ua_lower for t in tokens)]
        if matched and platform not in matched:
            # Android/Linux overlap: Linux token appears in Android UAs.
            if not (platform == "linux" and "android" in matched):
                error("platform_mismatch",
                      f"User-Agent implies {matched} but Sec-CH-UA-Platform "
                      f"says '{platform}'")

    # --- Chrome without client hints ------------------------------------
    if (
        hp.ua_family == "chrome"
        and hp.ua_version
        and hp.sec_ch_ua is None
        and int(hp.ua_version or 0) >= 90
    ):
        warn("chrome_missing_client_hints",
             f"Chrome {hp.ua_version} normally sends Sec-CH-UA headers")

    return issues
