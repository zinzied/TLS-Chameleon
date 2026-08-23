"""Automatic redaction of secrets from diagnostics, captures, and reports.

Every diagnostic output in TLS-Chameleon passes through this module.
Sensitive values are replaced with :data:`REDACTED`; revealing them is an
explicit opt-in (callers keep the original data and choose to expose it).
"""

import re
from typing import Any, Dict, List, Mapping, Union
from urllib.parse import urlsplit, urlunsplit

__all__ = [
    "REDACTED",
    "is_sensitive_header",
    "redact_headers",
    "redact_mapping",
    "redact_url",
    "redact_value",
]

#: Placeholder used for every redacted value. Constant => deterministic JSON.
REDACTED = "[REDACTED]"

# Header names that always carry credentials or tracking state.
SENSITIVE_HEADERS = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "api-key",
    "apikey",
    "x-auth-token",
    "x-csrf-token",
    "x-xsrf-token",
    "www-authenticate",
}

# Substring patterns for generic dict keys (lowercase matching).
_SENSITIVE_KEY_PATTERNS = (
    "password",
    "passwd",
    "secret",
    "token",
    "authorization",
    "credential",
    "api_key",
    "apikey",
    "private_key",
)

_TOKEN_SPLIT = re.compile(r"[^a-z0-9]+")


def _normalize_key(key: str) -> List[str]:
    """'X-Api-Key' -> ['x', 'api', 'key'] for robust comparison."""
    return [part for part in _TOKEN_SPLIT.split(str(key).lower()) if part]


def is_sensitive_header(name: str) -> bool:
    """True when a header name carries sensitive material."""
    normalized = str(name).strip().lower()
    if normalized in SENSITIVE_HEADERS:
        return True
    tokens = _normalize_key(normalized)
    joined = "".join(tokens)
    # Covers Authorization / Proxy-Authorization and friends.
    if "authorization" in joined:
        return True
    # Bearer/session/CSRF style tokens: X-Auth-Token, X-Csrf-Token, ...
    if "token" in tokens and any(
        marker in tokens
        for marker in ("auth", "security", "csrf", "xsrf", "access", "refresh", "session")
    ):
        return True
    # API keys: X-Api-Key / Apikey / X-Access-Key variants.
    if "key" in tokens and ("api" in tokens or "access" in tokens):
        return True
    return "password" in tokens or "passwd" in tokens or "secret" in tokens


def redact_value(value: Any) -> str:
    """Placeholder for a redacted secret; never echo the original."""
    del value
    return REDACTED


def redact_headers(headers: Union[Mapping[str, Any], None]) -> Dict[str, str]:
    """Return a copy of a header mapping with sensitive entries redacted.

    Header names are preserved (they are not secrets); only values are
    replaced. Comparison is case-insensitive.
    """
    if headers is None:
        return {}
    out: Dict[str, str] = {}
    for name, value in headers.items():
        out[name] = redact_value(value) if is_sensitive_header(name) else str(value)
    return out


def redact_mapping(obj: Any) -> Any:
    """Deep-redact dict/list structures by key patterns.

    Redacts keys containing: password/passwd/secret/token/authorization/
    credential/api_key/apikey/private_key. Unknown object types are returned
    unchanged so reports never crash on unexpected payloads.
    """
    if isinstance(obj, Mapping):
        out: Dict[Any, Any] = {}
        for key, value in obj.items():
            key_str = str(key).lower()
            if isinstance(key, str) and any(p in key_str for p in _SENSITIVE_KEY_PATTERNS):
                out[key] = REDACTED
            else:
                out[key] = redact_mapping(value)
        return out
    if isinstance(obj, list):
        return [redact_mapping(item) for item in obj]
    if isinstance(obj, tuple):
        return tuple(redact_mapping(item) for item in obj)
    return obj


def redact_url(url: str) -> str:
    """Strip userinfo credentials from a URL, preserving everything else."""
    try:
        parts = urlsplit(str(url))
    except ValueError:  # pragma: no cover - defensive
        return REDACTED
    if parts.username is None and parts.password is None:
        return str(url)
    host = parts.hostname or ""
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    if parts.port:
        host = f"{host}:{parts.port}"
    netloc = host
    return urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))
