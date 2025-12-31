"""
TLS-Chameleon HTTP/2 Simulator
=============================

Provides browser-specific HTTP/2 SETTINGS and priority simulation.

Different browsers send different HTTP/2 SETTINGS frames:
- Chrome: Large window sizes, conservative priorities
- Firefox: Smaller windows, aggressive priorities
- Safari: Minimal settings, simple priorities
"""

from typing import Dict, Any, Optional, List


# HTTP/2 SETTINGS Frame IDs
SETTINGS_HEADER_TABLE_SIZE = 1
SETTINGS_ENABLE_PUSH = 2
SETTINGS_MAX_CONCURRENT_STREAMS = 3
SETTINGS_INITIAL_WINDOW_SIZE = 4
SETTINGS_MAX_FRAME_SIZE = 5
SETTINGS_MAX_HEADER_LIST_SIZE = 6


class HTTP2Profile:
    """Browser-specific HTTP/2 configuration profiles."""
    
    # Chrome HTTP/2 Settings
    CHROME_SETTINGS = {
        SETTINGS_HEADER_TABLE_SIZE: 65536,
        SETTINGS_ENABLE_PUSH: 0,
        SETTINGS_MAX_CONCURRENT_STREAMS: 1000,
        SETTINGS_INITIAL_WINDOW_SIZE: 6291456,
        SETTINGS_MAX_FRAME_SIZE: 16384,
        SETTINGS_MAX_HEADER_LIST_SIZE: 262144,
    }
    
    # Firefox HTTP/2 Settings
    FIREFOX_SETTINGS = {
        SETTINGS_HEADER_TABLE_SIZE: 65536,
        SETTINGS_ENABLE_PUSH: 1,
        SETTINGS_MAX_CONCURRENT_STREAMS: 100,
        SETTINGS_INITIAL_WINDOW_SIZE: 131072,
        SETTINGS_MAX_FRAME_SIZE: 16384,
        SETTINGS_MAX_HEADER_LIST_SIZE: 65536,
    }
    
    # Safari HTTP/2 Settings
    SAFARI_SETTINGS = {
        SETTINGS_HEADER_TABLE_SIZE: 4096,
        SETTINGS_ENABLE_PUSH: 0,
        SETTINGS_MAX_CONCURRENT_STREAMS: 100,
        SETTINGS_INITIAL_WINDOW_SIZE: 65535,
        SETTINGS_MAX_FRAME_SIZE: 16384,
        SETTINGS_MAX_HEADER_LIST_SIZE: 16384,
    }
    
    # Edge HTTP/2 Settings (same as Chrome, Chromium-based)
    EDGE_SETTINGS = CHROME_SETTINGS
    
    # Browser settings mapping
    BROWSER_SETTINGS = {
        "chrome": CHROME_SETTINGS,
        "firefox": FIREFOX_SETTINGS,
        "safari": SAFARI_SETTINGS,
        "edge": EDGE_SETTINGS,
    }
    
    # HTTP/2 Priority patterns (stream weight and dependencies)
    # These represent the initial priority tree structure
    CHROME_PRIORITY = {
        "html": {"weight": 256, "exclusive": True, "depends_on": 0},
        "css": {"weight": 256, "exclusive": False, "depends_on": 0},
        "js": {"weight": 220, "exclusive": False, "depends_on": 0},
        "image": {"weight": 110, "exclusive": False, "depends_on": 0},
        "font": {"weight": 183, "exclusive": False, "depends_on": 0},
    }
    
    FIREFOX_PRIORITY = {
        # Firefox uses a more complex priority tree
        "leader": {"weight": 201, "exclusive": False, "depends_on": 0},
        "html": {"weight": 32, "exclusive": False, "depends_on": "leader"},
        "css": {"weight": 32, "exclusive": False, "depends_on": "leader"},
        "js": {"weight": 32, "exclusive": False, "depends_on": "leader"},
        "image": {"weight": 22, "exclusive": False, "depends_on": "leader"},
        "font": {"weight": 32, "exclusive": False, "depends_on": "leader"},
    }
    
    SAFARI_PRIORITY = {
        # Safari uses simpler priorities
        "html": {"weight": 255, "exclusive": False, "depends_on": 0},
        "css": {"weight": 255, "exclusive": False, "depends_on": 0},
        "js": {"weight": 255, "exclusive": False, "depends_on": 0},
        "image": {"weight": 255, "exclusive": False, "depends_on": 0},
        "font": {"weight": 255, "exclusive": False, "depends_on": 0},
    }
    
    BROWSER_PRIORITY = {
        "chrome": CHROME_PRIORITY,
        "firefox": FIREFOX_PRIORITY,
        "safari": SAFARI_PRIORITY,
        "edge": CHROME_PRIORITY,  # Same as Chrome
    }
    
    # Window update patterns (when browsers send WINDOW_UPDATE frames)
    CHROME_WINDOW_UPDATE = {
        "threshold": 0.5,  # Send when 50% consumed
        "increment": 15728640,  # 15MB increment
    }
    
    FIREFOX_WINDOW_UPDATE = {
        "threshold": 0.75,  # Send when 75% consumed
        "increment": 65536,  # 64KB increment
    }
    
    SAFARI_WINDOW_UPDATE = {
        "threshold": 0.5,
        "increment": 65535,
    }
    
    BROWSER_WINDOW_UPDATE = {
        "chrome": CHROME_WINDOW_UPDATE,
        "firefox": FIREFOX_WINDOW_UPDATE,
        "safari": SAFARI_WINDOW_UPDATE,
        "edge": CHROME_WINDOW_UPDATE,
    }
    
    @classmethod
    def get_settings(cls, browser: str) -> Dict[int, int]:
        """
        Get HTTP/2 SETTINGS frame values for a browser.
        
        Args:
            browser: Browser name (chrome, firefox, safari, edge)
            
        Returns:
            Dict mapping SETTINGS ID to value
        """
        browser = browser.lower().split("_")[0]  # Handle "chrome_120" -> "chrome"
        return cls.BROWSER_SETTINGS.get(browser, cls.CHROME_SETTINGS)
    
    @classmethod
    def get_priority_pattern(cls, browser: str) -> Dict[str, Dict[str, Any]]:
        """
        Get HTTP/2 stream priority pattern for a browser.
        
        Args:
            browser: Browser name
            
        Returns:
            Dict mapping resource type to priority info
        """
        browser = browser.lower().split("_")[0]
        return cls.BROWSER_PRIORITY.get(browser, cls.CHROME_PRIORITY)
    
    @classmethod
    def get_window_update_pattern(cls, browser: str) -> Dict[str, Any]:
        """
        Get HTTP/2 WINDOW_UPDATE behavior for a browser.
        
        Args:
            browser: Browser name
            
        Returns:
            Dict with threshold and increment values
        """
        browser = browser.lower().split("_")[0]
        return cls.BROWSER_WINDOW_UPDATE.get(browser, cls.CHROME_WINDOW_UPDATE)
    
    @classmethod
    def get_connection_preface_order(cls, browser: str) -> List[str]:
        """
        Get the order of frames in the HTTP/2 connection preface.
        
        Args:
            browser: Browser name
            
        Returns:
            List of frame types in order
        """
        browser = browser.lower().split("_")[0]
        
        if browser == "chrome":
            return ["SETTINGS", "WINDOW_UPDATE", "PRIORITY"]
        elif browser == "firefox":
            return ["SETTINGS", "PRIORITY", "WINDOW_UPDATE"]
        elif browser == "safari":
            return ["SETTINGS", "WINDOW_UPDATE"]
        else:
            return ["SETTINGS", "WINDOW_UPDATE", "PRIORITY"]
    
    @classmethod
    def format_settings_for_curl(cls, settings: Dict[int, int]) -> str:
        """
        Format HTTP/2 settings for curl command line.
        
        Note: curl doesn't support all settings customization,
        but this provides the format for documentation.
        """
        # curl uses --http2-prior-knowledge and similar flags
        # Full settings customization requires libcurl patches
        return f"INITIAL_WINDOW_SIZE={settings.get(SETTINGS_INITIAL_WINDOW_SIZE, 65535)}"


def get_http2_profile(browser: str) -> Dict[str, Any]:
    """
    Get complete HTTP/2 profile for a browser.
    
    Args:
        browser: Browser name (e.g., "chrome", "firefox", "chrome_124_win11")
        
    Returns:
        Dict with settings, priority, window_update, and preface_order
    """
    return {
        "settings": HTTP2Profile.get_settings(browser),
        "priority": HTTP2Profile.get_priority_pattern(browser),
        "window_update": HTTP2Profile.get_window_update_pattern(browser),
        "preface_order": HTTP2Profile.get_connection_preface_order(browser),
    }
