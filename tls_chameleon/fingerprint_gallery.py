"""
TLS-Chameleon Fingerprint Gallery v2.0
======================================

Comprehensive browser fingerprint database with profiles for:
- Chrome (Windows 10, Windows 11, macOS, Linux)
- Firefox (Windows 10, Windows 11, macOS, Linux)
- Safari (iOS, macOS)
- Edge (Windows 10, Windows 11)

Each profile includes:
- User-Agent string
- JA3 fingerprint (TLS 1.2)
- JA3N fingerprint (normalized)
- Cipher suites with exact ordering
- TLS extensions list
- Header ordering and casing
- HTTP/2 SETTINGS values
- Randomization parameters
"""

from typing import Dict, Any, List, Optional
import random
import copy


# =============================================================================
# CHROME PROFILES
# =============================================================================

CHROME_BASE = {
    "header_case": "lower",
    "http2_settings": {
        "HEADER_TABLE_SIZE": 65536,
        "ENABLE_PUSH": 0,
        "MAX_CONCURRENT_STREAMS": 1000,
        "INITIAL_WINDOW_SIZE": 6291456,
        "MAX_FRAME_SIZE": 16384,
        "MAX_HEADER_LIST_SIZE": 262144,
    },
    "randomization": {
        "cipher_shuffle": False,  # Chrome keeps strict cipher order
        "extension_variance": 0,
        "ua_minor_variance": True,  # Can vary minor version
    }
}

# Chrome 120 - Windows 11
CHROME_120_WIN11 = {
    **CHROME_BASE,
    "name": "chrome_120_win11",
    "impersonate": "chrome120",
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "sec_ch_ua": '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
    "sec_ch_ua_platform": '"Windows"',
    "ja3": "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0",
    "ja3_hash": "cd08e31494f9531f560d64c695473da9",
    "ciphers": [
        "TLS_AES_128_GCM_SHA256",
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
        "ECDHE-ECDSA-AES128-GCM-SHA256",
        "ECDHE-RSA-AES128-GCM-SHA256",
        "ECDHE-ECDSA-AES256-GCM-SHA384",
        "ECDHE-RSA-AES256-GCM-SHA384",
        "ECDHE-ECDSA-CHACHA20-POLY1305",
        "ECDHE-RSA-CHACHA20-POLY1305",
        "ECDHE-RSA-AES128-SHA",
        "ECDHE-RSA-AES256-SHA",
        "AES128-GCM-SHA256",
        "AES256-GCM-SHA384",
        "AES128-SHA",
        "AES256-SHA",
    ],
    "extensions": [0, 23, 65281, 10, 11, 35, 16, 5, 13, 18, 51, 45, 43, 27, 17513, 21],
    "header_order": [
        "host", "connection", "cache-control", "sec-ch-ua", "sec-ch-ua-mobile",
        "sec-ch-ua-platform", "upgrade-insecure-requests", "user-agent", "accept",
        "sec-fetch-site", "sec-fetch-mode", "sec-fetch-user", "sec-fetch-dest",
        "accept-encoding", "accept-language"
    ],
}

# Chrome 120 - Windows 10
CHROME_120_WIN10 = {
    **CHROME_BASE,
    "name": "chrome_120_win10",
    "impersonate": "chrome120",
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "sec_ch_ua": '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
    "sec_ch_ua_platform": '"Windows"',
    "ja3": "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0",
    "ja3_hash": "cd08e31494f9531f560d64c695473da9",
    "ciphers": [
        "TLS_AES_128_GCM_SHA256",
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
        "ECDHE-ECDSA-AES128-GCM-SHA256",
        "ECDHE-RSA-AES128-GCM-SHA256",
        "ECDHE-ECDSA-AES256-GCM-SHA384",
        "ECDHE-RSA-AES256-GCM-SHA384",
        "ECDHE-ECDSA-CHACHA20-POLY1305",
        "ECDHE-RSA-CHACHA20-POLY1305",
        "ECDHE-RSA-AES128-SHA",
        "ECDHE-RSA-AES256-SHA",
        "AES128-GCM-SHA256",
        "AES256-GCM-SHA384",
        "AES128-SHA",
        "AES256-SHA",
    ],
    "extensions": [0, 23, 65281, 10, 11, 35, 16, 5, 13, 18, 51, 45, 43, 27, 17513, 21],
    "header_order": [
        "host", "connection", "cache-control", "sec-ch-ua", "sec-ch-ua-mobile",
        "sec-ch-ua-platform", "upgrade-insecure-requests", "user-agent", "accept",
        "sec-fetch-site", "sec-fetch-mode", "sec-fetch-user", "sec-fetch-dest",
        "accept-encoding", "accept-language"
    ],
}

# Chrome 120 - macOS
CHROME_120_MACOS = {
    **CHROME_BASE,
    "name": "chrome_120_macos",
    "impersonate": "chrome120",
    "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "sec_ch_ua": '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
    "sec_ch_ua_platform": '"macOS"',
    "ja3": "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0",
    "ja3_hash": "cd08e31494f9531f560d64c695473da9",
    "ciphers": [
        "TLS_AES_128_GCM_SHA256",
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
        "ECDHE-ECDSA-AES128-GCM-SHA256",
        "ECDHE-RSA-AES128-GCM-SHA256",
        "ECDHE-ECDSA-AES256-GCM-SHA384",
        "ECDHE-RSA-AES256-GCM-SHA384",
        "ECDHE-ECDSA-CHACHA20-POLY1305",
        "ECDHE-RSA-CHACHA20-POLY1305",
        "ECDHE-RSA-AES128-SHA",
        "ECDHE-RSA-AES256-SHA",
        "AES128-GCM-SHA256",
        "AES256-GCM-SHA384",
        "AES128-SHA",
        "AES256-SHA",
    ],
    "extensions": [0, 23, 65281, 10, 11, 35, 16, 5, 13, 18, 51, 45, 43, 27, 17513, 21],
    "header_order": [
        "host", "connection", "cache-control", "sec-ch-ua", "sec-ch-ua-mobile",
        "sec-ch-ua-platform", "upgrade-insecure-requests", "user-agent", "accept",
        "sec-fetch-site", "sec-fetch-mode", "sec-fetch-user", "sec-fetch-dest",
        "accept-encoding", "accept-language"
    ],
}

# Chrome 120 - Linux
CHROME_120_LINUX = {
    **CHROME_BASE,
    "name": "chrome_120_linux",
    "impersonate": "chrome120",
    "user_agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "sec_ch_ua": '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
    "sec_ch_ua_platform": '"Linux"',
    "ja3": "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0",
    "ja3_hash": "cd08e31494f9531f560d64c695473da9",
    "ciphers": [
        "TLS_AES_128_GCM_SHA256",
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
        "ECDHE-ECDSA-AES128-GCM-SHA256",
        "ECDHE-RSA-AES128-GCM-SHA256",
        "ECDHE-ECDSA-AES256-GCM-SHA384",
        "ECDHE-RSA-AES256-GCM-SHA384",
        "ECDHE-ECDSA-CHACHA20-POLY1305",
        "ECDHE-RSA-CHACHA20-POLY1305",
        "ECDHE-RSA-AES128-SHA",
        "ECDHE-RSA-AES256-SHA",
        "AES128-GCM-SHA256",
        "AES256-GCM-SHA384",
        "AES128-SHA",
        "AES256-SHA",
    ],
    "extensions": [0, 23, 65281, 10, 11, 35, 16, 5, 13, 18, 51, 45, 43, 27, 17513, 21],
    "header_order": [
        "host", "connection", "cache-control", "sec-ch-ua", "sec-ch-ua-mobile",
        "sec-ch-ua-platform", "upgrade-insecure-requests", "user-agent", "accept",
        "sec-fetch-site", "sec-fetch-mode", "sec-fetch-user", "sec-fetch-dest",
        "accept-encoding", "accept-language"
    ],
}

# Chrome 124 - Windows 11
CHROME_124_WIN11 = {
    **CHROME_BASE,
    "name": "chrome_124_win11",
    "impersonate": "chrome124",
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "sec_ch_ua": '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
    "sec_ch_ua_platform": '"Windows"',
    "ja3": "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0",
    "ja3_hash": "cd08e31494f9531f560d64c695473da9",
    "ciphers": [
        "TLS_AES_128_GCM_SHA256",
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
        "ECDHE-ECDSA-AES128-GCM-SHA256",
        "ECDHE-RSA-AES128-GCM-SHA256",
        "ECDHE-ECDSA-AES256-GCM-SHA384",
        "ECDHE-RSA-AES256-GCM-SHA384",
        "ECDHE-ECDSA-CHACHA20-POLY1305",
        "ECDHE-RSA-CHACHA20-POLY1305",
        "ECDHE-RSA-AES128-SHA",
        "ECDHE-RSA-AES256-SHA",
        "AES128-GCM-SHA256",
        "AES256-GCM-SHA384",
        "AES128-SHA",
        "AES256-SHA",
    ],
    "extensions": [0, 23, 65281, 10, 11, 35, 16, 5, 13, 18, 51, 45, 43, 27, 17513, 21],
    "header_order": [
        "host", "connection", "cache-control", "sec-ch-ua", "sec-ch-ua-mobile",
        "sec-ch-ua-platform", "upgrade-insecure-requests", "user-agent", "accept",
        "sec-fetch-site", "sec-fetch-mode", "sec-fetch-user", "sec-fetch-dest",
        "accept-encoding", "accept-language", "priority"
    ],
}

# Chrome 124 - Windows 10
CHROME_124_WIN10 = {
    **CHROME_BASE,
    "name": "chrome_124_win10",
    "impersonate": "chrome124",
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "sec_ch_ua": '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
    "sec_ch_ua_platform": '"Windows"',
    "ja3": "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0",
    "ja3_hash": "cd08e31494f9531f560d64c695473da9",
    "ciphers": [
        "TLS_AES_128_GCM_SHA256",
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
        "ECDHE-ECDSA-AES128-GCM-SHA256",
        "ECDHE-RSA-AES128-GCM-SHA256",
        "ECDHE-ECDSA-AES256-GCM-SHA384",
        "ECDHE-RSA-AES256-GCM-SHA384",
        "ECDHE-ECDSA-CHACHA20-POLY1305",
        "ECDHE-RSA-CHACHA20-POLY1305",
        "ECDHE-RSA-AES128-SHA",
        "ECDHE-RSA-AES256-SHA",
        "AES128-GCM-SHA256",
        "AES256-GCM-SHA384",
        "AES128-SHA",
        "AES256-SHA",
    ],
    "extensions": [0, 23, 65281, 10, 11, 35, 16, 5, 13, 18, 51, 45, 43, 27, 17513, 21],
    "header_order": [
        "host", "connection", "cache-control", "sec-ch-ua", "sec-ch-ua-mobile",
        "sec-ch-ua-platform", "upgrade-insecure-requests", "user-agent", "accept",
        "sec-fetch-site", "sec-fetch-mode", "sec-fetch-user", "sec-fetch-dest",
        "accept-encoding", "accept-language", "priority"
    ],
}

# Chrome 124 - macOS
CHROME_124_MACOS = {
    **CHROME_BASE,
    "name": "chrome_124_macos",
    "impersonate": "chrome124",
    "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "sec_ch_ua": '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
    "sec_ch_ua_platform": '"macOS"',
    "ja3": "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0",
    "ja3_hash": "cd08e31494f9531f560d64c695473da9",
    "ciphers": [
        "TLS_AES_128_GCM_SHA256",
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
        "ECDHE-ECDSA-AES128-GCM-SHA256",
        "ECDHE-RSA-AES128-GCM-SHA256",
        "ECDHE-ECDSA-AES256-GCM-SHA384",
        "ECDHE-RSA-AES256-GCM-SHA384",
        "ECDHE-ECDSA-CHACHA20-POLY1305",
        "ECDHE-RSA-CHACHA20-POLY1305",
        "ECDHE-RSA-AES128-SHA",
        "ECDHE-RSA-AES256-SHA",
        "AES128-GCM-SHA256",
        "AES256-GCM-SHA384",
        "AES128-SHA",
        "AES256-SHA",
    ],
    "extensions": [0, 23, 65281, 10, 11, 35, 16, 5, 13, 18, 51, 45, 43, 27, 17513, 21],
    "header_order": [
        "host", "connection", "cache-control", "sec-ch-ua", "sec-ch-ua-mobile",
        "sec-ch-ua-platform", "upgrade-insecure-requests", "user-agent", "accept",
        "sec-fetch-site", "sec-fetch-mode", "sec-fetch-user", "sec-fetch-dest",
        "accept-encoding", "accept-language", "priority"
    ],
}

# Chrome 124 - Linux
CHROME_124_LINUX = {
    **CHROME_BASE,
    "name": "chrome_124_linux",
    "impersonate": "chrome124",
    "user_agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "sec_ch_ua": '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
    "sec_ch_ua_platform": '"Linux"',
    "ja3": "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0",
    "ja3_hash": "cd08e31494f9531f560d64c695473da9",
    "ciphers": [
        "TLS_AES_128_GCM_SHA256",
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
        "ECDHE-ECDSA-AES128-GCM-SHA256",
        "ECDHE-RSA-AES128-GCM-SHA256",
        "ECDHE-ECDSA-AES256-GCM-SHA384",
        "ECDHE-RSA-AES256-GCM-SHA384",
        "ECDHE-ECDSA-CHACHA20-POLY1305",
        "ECDHE-RSA-CHACHA20-POLY1305",
        "ECDHE-RSA-AES128-SHA",
        "ECDHE-RSA-AES256-SHA",
        "AES128-GCM-SHA256",
        "AES256-GCM-SHA384",
        "AES128-SHA",
        "AES256-SHA",
    ],
    "extensions": [0, 23, 65281, 10, 11, 35, 16, 5, 13, 18, 51, 45, 43, 27, 17513, 21],
    "header_order": [
        "host", "connection", "cache-control", "sec-ch-ua", "sec-ch-ua-mobile",
        "sec-ch-ua-platform", "upgrade-insecure-requests", "user-agent", "accept",
        "sec-fetch-site", "sec-fetch-mode", "sec-fetch-user", "sec-fetch-dest",
        "accept-encoding", "accept-language", "priority"
    ],
}

# Chrome 125 - All platforms
CHROME_125_WIN11 = {
    **CHROME_BASE,
    "name": "chrome_125_win11",
    "impersonate": "chrome124",  # curl_cffi may not have 125 yet
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "sec_ch_ua": '"Chromium";v="125", "Google Chrome";v="125", "Not-A.Brand";v="24"',
    "sec_ch_ua_platform": '"Windows"',
    "ja3": "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0",
    "ja3_hash": "cd08e31494f9531f560d64c695473da9",
    "ciphers": CHROME_124_WIN11["ciphers"],
    "extensions": CHROME_124_WIN11["extensions"],
    "header_order": CHROME_124_WIN11["header_order"],
}

CHROME_125_WIN10 = {**CHROME_125_WIN11, "name": "chrome_125_win10"}
CHROME_125_MACOS = {
    **CHROME_125_WIN11,
    "name": "chrome_125_macos",
    "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "sec_ch_ua_platform": '"macOS"',
}
CHROME_125_LINUX = {
    **CHROME_125_WIN11,
    "name": "chrome_125_linux",
    "user_agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "sec_ch_ua_platform": '"Linux"',
}

# =============================================================================
# FIREFOX PROFILES
# =============================================================================

FIREFOX_BASE = {
    "header_case": "title",  # Firefox uses Title-Case headers
    "http2_settings": {
        "HEADER_TABLE_SIZE": 65536,
        "ENABLE_PUSH": 1,
        "MAX_CONCURRENT_STREAMS": 100,
        "INITIAL_WINDOW_SIZE": 131072,
        "MAX_FRAME_SIZE": 16384,
        "MAX_HEADER_LIST_SIZE": 65536,
    },
    "randomization": {
        "cipher_shuffle": False,
        "extension_variance": 2,  # Firefox has some extension order variance
        "ua_minor_variance": True,
    }
}

# Firefox 120 - All platforms
FIREFOX_120_WIN11 = {
    **FIREFOX_BASE,
    "name": "firefox_120_win11",
    "impersonate": "firefox120",
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
    "ja3": "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-51-43-13-45-28-21,29-23-24-25-256-257,0",
    "ja3_hash": "579ccef312e5ce0e367e8d1a9a11add4",
    "ciphers": [
        "TLS_AES_128_GCM_SHA256",
        "TLS_CHACHA20_POLY1305_SHA256",
        "TLS_AES_256_GCM_SHA384",
        "ECDHE-ECDSA-AES128-GCM-SHA256",
        "ECDHE-RSA-AES128-GCM-SHA256",
        "ECDHE-ECDSA-CHACHA20-POLY1305",
        "ECDHE-RSA-CHACHA20-POLY1305",
        "ECDHE-ECDSA-AES256-GCM-SHA384",
        "ECDHE-RSA-AES256-GCM-SHA384",
        "ECDHE-ECDSA-AES256-SHA",
        "ECDHE-ECDSA-AES128-SHA",
        "ECDHE-RSA-AES128-SHA",
        "ECDHE-RSA-AES256-SHA",
        "AES128-GCM-SHA256",
        "AES256-GCM-SHA384",
        "AES128-SHA",
        "AES256-SHA",
    ],
    "extensions": [0, 23, 65281, 10, 11, 35, 16, 5, 34, 51, 43, 13, 45, 28, 21],
    "header_order": [
        "Host", "User-Agent", "Accept", "Accept-Language", "Accept-Encoding",
        "Connection", "Upgrade-Insecure-Requests", "Sec-Fetch-Dest", 
        "Sec-Fetch-Mode", "Sec-Fetch-Site", "Sec-Fetch-User"
    ],
}

FIREFOX_120_WIN10 = {
    **FIREFOX_120_WIN11,
    "name": "firefox_120_win10",
}

FIREFOX_120_MACOS = {
    **FIREFOX_120_WIN11,
    "name": "firefox_120_macos",
    "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:120.0) Gecko/20100101 Firefox/120.0",
}

FIREFOX_120_LINUX = {
    **FIREFOX_120_WIN11,
    "name": "firefox_120_linux",
    "user_agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
}

# Firefox 124 - All platforms
FIREFOX_124_WIN11 = {
    **FIREFOX_BASE,
    "name": "firefox_124_win11",
    "impersonate": "firefox120",  # curl_cffi fallback
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "ja3": "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-51-43-13-45-28-21,29-23-24-25-256-257,0",
    "ja3_hash": "579ccef312e5ce0e367e8d1a9a11add4",
    "ciphers": FIREFOX_120_WIN11["ciphers"],
    "extensions": FIREFOX_120_WIN11["extensions"],
    "header_order": FIREFOX_120_WIN11["header_order"],
}

FIREFOX_124_WIN10 = {**FIREFOX_124_WIN11, "name": "firefox_124_win10"}
FIREFOX_124_MACOS = {
    **FIREFOX_124_WIN11,
    "name": "firefox_124_macos",
    "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:124.0) Gecko/20100101 Firefox/124.0",
}
FIREFOX_124_LINUX = {
    **FIREFOX_124_WIN11,
    "name": "firefox_124_linux",
    "user_agent": "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
}

# =============================================================================
# SAFARI PROFILES
# =============================================================================

SAFARI_BASE = {
    "header_case": "title",
    "http2_settings": {
        "HEADER_TABLE_SIZE": 4096,
        "ENABLE_PUSH": 0,
        "MAX_CONCURRENT_STREAMS": 100,
        "INITIAL_WINDOW_SIZE": 65535,
        "MAX_FRAME_SIZE": 16384,
        "MAX_HEADER_LIST_SIZE": 16384,
    },
    "randomization": {
        "cipher_shuffle": False,
        "extension_variance": 0,
        "ua_minor_variance": False,
    }
}

# Safari iOS 17
SAFARI_IOS17 = {
    **SAFARI_BASE,
    "name": "safari_ios17",
    "impersonate": "safari17_0",
    "user_agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    "ja3": "771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49188-49187-49162-49161-49172-49171-157-156-53-47-255,0-23-65281-10-11-16-5-13-18-51-45-43-27-21,29-23-24-25,0",
    "ja3_hash": "773906b0efdefa24a7f2b8eb6985bf37",
    "ciphers": [
        "TLS_AES_128_GCM_SHA256",
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
        "ECDHE-ECDSA-AES256-GCM-SHA384",
        "ECDHE-ECDSA-AES128-GCM-SHA256",
        "ECDHE-ECDSA-CHACHA20-POLY1305",
        "ECDHE-RSA-AES256-GCM-SHA384",
        "ECDHE-RSA-AES128-GCM-SHA256",
        "ECDHE-RSA-CHACHA20-POLY1305",
    ],
    "extensions": [0, 23, 65281, 10, 11, 16, 5, 13, 18, 51, 45, 43, 27, 21],
    "header_order": [
        "Host", "Accept", "Accept-Language", "User-Agent", 
        "Accept-Encoding", "Connection"
    ],
}

# Safari iOS 16
SAFARI_IOS16 = {
    **SAFARI_BASE,
    "name": "safari_ios16",
    "impersonate": "safari16",
    "user_agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1",
    "ja3": "771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49188-49187-49162-49161-49172-49171-157-156-53-47-255,0-23-65281-10-11-16-5-13-18-51-45-43-27-21,29-23-24-25,0",
    "ja3_hash": "773906b0efdefa24a7f2b8eb6985bf37",
    "ciphers": SAFARI_IOS17["ciphers"],
    "extensions": SAFARI_IOS17["extensions"],
    "header_order": SAFARI_IOS17["header_order"],
}

# Safari macOS 14 (Sonoma)
SAFARI_MACOS14 = {
    **SAFARI_BASE,
    "name": "safari_macos14",
    "impersonate": "safari17_0",
    "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "ja3": "771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49188-49187-49162-49161-49172-49171-157-156-53-47-255,0-23-65281-10-11-16-5-13-18-51-45-43-27-21,29-23-24-25,0",
    "ja3_hash": "773906b0efdefa24a7f2b8eb6985bf37",
    "ciphers": SAFARI_IOS17["ciphers"],
    "extensions": SAFARI_IOS17["extensions"],
    "header_order": SAFARI_IOS17["header_order"],
}

# Safari macOS 13 (Ventura)
SAFARI_MACOS13 = {
    **SAFARI_BASE,
    "name": "safari_macos13",
    "impersonate": "safari16",
    "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15",
    "ja3": "771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49188-49187-49162-49161-49172-49171-157-156-53-47-255,0-23-65281-10-11-16-5-13-18-51-45-43-27-21,29-23-24-25,0",
    "ja3_hash": "773906b0efdefa24a7f2b8eb6985bf37",
    "ciphers": SAFARI_IOS17["ciphers"],
    "extensions": SAFARI_IOS17["extensions"],
    "header_order": SAFARI_IOS17["header_order"],
}

# =============================================================================
# EDGE PROFILES
# =============================================================================

EDGE_BASE = {
    **CHROME_BASE,  # Edge is Chromium-based
}

# Edge 120 - Windows 11
EDGE_120_WIN11 = {
    **EDGE_BASE,
    "name": "edge_120_win11",
    "impersonate": "edge120",
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    "sec_ch_ua": '"Not_A Brand";v="8", "Chromium";v="120", "Microsoft Edge";v="120"',
    "sec_ch_ua_platform": '"Windows"',
    "ja3": "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0",
    "ja3_hash": "cd08e31494f9531f560d64c695473da9",
    "ciphers": CHROME_120_WIN11["ciphers"],
    "extensions": CHROME_120_WIN11["extensions"],
    "header_order": CHROME_120_WIN11["header_order"],
}

# Edge 120 - Windows 10
EDGE_120_WIN10 = {
    **EDGE_120_WIN11,
    "name": "edge_120_win10",
}

# Edge 124 - Windows 11
EDGE_124_WIN11 = {
    **EDGE_BASE,
    "name": "edge_124_win11",
    "impersonate": "edge120",  # curl_cffi fallback
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    "sec_ch_ua": '"Chromium";v="124", "Microsoft Edge";v="124", "Not-A.Brand";v="99"',
    "sec_ch_ua_platform": '"Windows"',
    "ja3": EDGE_120_WIN11["ja3"],
    "ja3_hash": EDGE_120_WIN11["ja3_hash"],
    "ciphers": CHROME_124_WIN11["ciphers"],
    "extensions": CHROME_124_WIN11["extensions"],
    "header_order": CHROME_124_WIN11["header_order"],
}

# Edge 124 - Windows 10
EDGE_124_WIN10 = {
    **EDGE_124_WIN11,
    "name": "edge_124_win10",
}

# =============================================================================
# ANDROID CHROME PROFILES
# =============================================================================

CHROME_ANDROID_120 = {
    **CHROME_BASE,
    "name": "chrome_android_120",
    "impersonate": "chrome120_android",
    "user_agent": "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Mobile Safari/537.36",
    "sec_ch_ua": '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
    "sec_ch_ua_platform": '"Android"',
    "sec_ch_ua_mobile": "?1",
    "ja3": CHROME_120_WIN11["ja3"],
    "ja3_hash": CHROME_120_WIN11["ja3_hash"],
    "ciphers": CHROME_120_WIN11["ciphers"],
    "extensions": CHROME_120_WIN11["extensions"],
    "header_order": CHROME_120_WIN11["header_order"],
}

CHROME_ANDROID_124 = {
    **CHROME_ANDROID_120,
    "name": "chrome_android_124",
    "impersonate": "chrome124_android",
    "user_agent": "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.82 Mobile Safari/537.36",
    "sec_ch_ua": '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
}

# =============================================================================
# MAIN GALLERY DICTIONARY
# =============================================================================

FINGERPRINT_GALLERY: Dict[str, Dict[str, Any]] = {
    # Chrome - Windows 11
    "chrome_120_win11": CHROME_120_WIN11,
    "chrome_124_win11": CHROME_124_WIN11,
    "chrome_125_win11": CHROME_125_WIN11,
    
    # Chrome - Windows 10
    "chrome_120_win10": CHROME_120_WIN10,
    "chrome_124_win10": CHROME_124_WIN10,
    "chrome_125_win10": CHROME_125_WIN10,
    
    # Chrome - macOS
    "chrome_120_macos": CHROME_120_MACOS,
    "chrome_124_macos": CHROME_124_MACOS,
    "chrome_125_macos": CHROME_125_MACOS,
    
    # Chrome - Linux
    "chrome_120_linux": CHROME_120_LINUX,
    "chrome_124_linux": CHROME_124_LINUX,
    "chrome_125_linux": CHROME_125_LINUX,
    
    # Chrome - Android
    "chrome_android_120": CHROME_ANDROID_120,
    "chrome_android_124": CHROME_ANDROID_124,
    
    # Firefox - Windows 11
    "firefox_120_win11": FIREFOX_120_WIN11,
    "firefox_124_win11": FIREFOX_124_WIN11,
    
    # Firefox - Windows 10
    "firefox_120_win10": FIREFOX_120_WIN10,
    "firefox_124_win10": FIREFOX_124_WIN10,
    
    # Firefox - macOS
    "firefox_120_macos": FIREFOX_120_MACOS,
    "firefox_124_macos": FIREFOX_124_MACOS,
    
    # Firefox - Linux
    "firefox_120_linux": FIREFOX_120_LINUX,
    "firefox_124_linux": FIREFOX_124_LINUX,
    
    # Safari - iOS
    "safari_ios16": SAFARI_IOS16,
    "safari_ios17": SAFARI_IOS17,
    
    # Safari - macOS
    "safari_macos13": SAFARI_MACOS13,
    "safari_macos14": SAFARI_MACOS14,
    
    # Edge - Windows 11
    "edge_120_win11": EDGE_120_WIN11,
    "edge_124_win11": EDGE_124_WIN11,
    
    # Edge - Windows 10
    "edge_120_win10": EDGE_120_WIN10,
    "edge_124_win10": EDGE_124_WIN10,
}

# Aliases for convenience
FINGERPRINT_GALLERY["chrome_latest"] = CHROME_125_WIN11
FINGERPRINT_GALLERY["chrome_latest_win10"] = CHROME_125_WIN10
FINGERPRINT_GALLERY["chrome_latest_macos"] = CHROME_125_MACOS
FINGERPRINT_GALLERY["chrome_latest_linux"] = CHROME_125_LINUX
FINGERPRINT_GALLERY["firefox_latest"] = FIREFOX_124_WIN11
FINGERPRINT_GALLERY["firefox_latest_linux"] = FIREFOX_124_LINUX
FINGERPRINT_GALLERY["safari_latest"] = SAFARI_IOS17
FINGERPRINT_GALLERY["edge_latest"] = EDGE_124_WIN11
FINGERPRINT_GALLERY["mobile_safari"] = SAFARI_IOS17
FINGERPRINT_GALLERY["mobile_chrome"] = CHROME_ANDROID_124

# Legacy aliases (backward compatibility with profiles.py)
FINGERPRINT_GALLERY["chrome_120"] = CHROME_120_WIN11
FINGERPRINT_GALLERY["chrome_124"] = CHROME_124_WIN11
FINGERPRINT_GALLERY["firefox_120"] = FIREFOX_120_WIN11
FINGERPRINT_GALLERY["mobile_safari_17"] = SAFARI_IOS17
FINGERPRINT_GALLERY["ios_safari_17"] = SAFARI_IOS17


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def get_profile(name: str) -> Optional[Dict[str, Any]]:
    """Get a fingerprint profile by name."""
    return FINGERPRINT_GALLERY.get(name)


def get_all_profiles() -> List[str]:
    """Get list of all available profile names."""
    return list(FINGERPRINT_GALLERY.keys())


def get_profiles_by_browser(browser: str) -> List[str]:
    """Get all profiles for a specific browser (chrome, firefox, safari, edge)."""
    browser = browser.lower()
    return [name for name in FINGERPRINT_GALLERY.keys() if name.startswith(browser)]


def get_profiles_by_os(os_name: str) -> List[str]:
    """Get all profiles for a specific OS (win11, win10, macos, linux, ios, android)."""
    os_name = os_name.lower()
    return [name for name in FINGERPRINT_GALLERY.keys() if os_name in name]


def get_random_profile(browser: Optional[str] = None, os_name: Optional[str] = None) -> Dict[str, Any]:
    """Get a random profile, optionally filtered by browser and/or OS."""
    candidates = list(FINGERPRINT_GALLERY.keys())
    
    if browser:
        browser = browser.lower()
        candidates = [n for n in candidates if n.startswith(browser)]
    
    if os_name:
        os_name = os_name.lower()
        candidates = [n for n in candidates if os_name in n]
    
    if not candidates:
        # Fall back to default
        return FINGERPRINT_GALLERY["chrome_120_win11"]
    
    return FINGERPRINT_GALLERY[random.choice(candidates)]


def randomize_profile(profile: Dict[str, Any]) -> Dict[str, Any]:
    """
    Create a randomized variant of a profile.
    
    This creates slight variations that still look like the same browser
    but differ enough to avoid pattern detection.
    """
    variant = copy.deepcopy(profile)
    randomization = variant.get("randomization", {})
    
    # Minor User-Agent version variance
    if randomization.get("ua_minor_variance"):
        ua = variant.get("user_agent", "")
        # Randomly tweak patch version (last number)
        import re
        def bump_version(m):
            base = int(m.group(1))
            # Vary by -1 to +2
            new_ver = max(0, base + random.choice([-1, 0, 0, 1, 1, 2]))
            return f".{new_ver}"
        variant["user_agent"] = re.sub(r'\.(\d+)(?=\s|$)', bump_version, ua, count=1)
    
    # Extension order variance (Firefox mainly)
    ext_variance = randomization.get("extension_variance", 0)
    if ext_variance > 0 and "extensions" in variant:
        exts = list(variant["extensions"])
        # Swap a few adjacent extensions
        for _ in range(min(ext_variance, len(exts) - 1)):
            i = random.randint(0, len(exts) - 2)
            exts[i], exts[i + 1] = exts[i + 1], exts[i]
        variant["extensions"] = exts
    
    return variant
