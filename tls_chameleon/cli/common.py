"""Shared CLI helpers: exit codes, client construction, output formatting."""

import json
import sys
from typing import Any, Dict, Optional

from ..client import TLSChameleon

__all__ = [
    "build_client",
    "emit",
    "parse_headers",
    "EXIT_OK",
    "EXIT_ERROR",
    "EXIT_FAILED_CHECK",
    "EXIT_NOT_IMPLEMENTED",
]

# Documented, stable CLI exit codes:
#   0  success (doctor 'warn' still counts as success -- it is informational)
#   1  operational failure / failed check / invalid input
#   2  usage error (argparse convention)
#   3  feature not yet available (benchmark stub)
EXIT_OK = 0
EXIT_ERROR = 1
EXIT_FAILED_CHECK = 1
EXIT_NOT_IMPLEMENTED = 3


def build_client(args: Any) -> TLSChameleon:
    """Construct a TLSChameleon from shared CLI flags."""
    kwargs: Dict[str, Any] = {
        "timeout": args.timeout,
        "verify": args.verify,
    }
    engine = getattr(args, "engine", None)
    if engine and engine != "auto":
        kwargs["engine"] = engine
    profile = getattr(args, "profile", None)
    if profile:
        kwargs["profile"] = profile
    seed = getattr(args, "random_seed", None)
    if seed is not None:
        # Accept both numeric seeds and arbitrary strings.
        try:
            seed = int(seed)
        except (TypeError, ValueError):
            pass
        kwargs["random_seed"] = seed
    return TLSChameleon(**kwargs)


def emit(payload: Dict[str, Any], as_json: bool) -> None:
    """Print JSON payload or let the caller's text stand."""
    if as_json:
        print(json.dumps(payload, indent=2))


def parse_headers(pairs: Optional[list]) -> Dict[str, str]:
    """Parse repeated '-H Name: Value' arguments.

    Values are NOT redacted here: these headers are intended to be sent.
    Output-side redaction happens in the diagnostics layer.
    """
    headers: Dict[str, str] = {}
    for item in pairs or []:
        if ":" not in item:
            print(f"invalid header (expected 'Name: Value'): {item}",
                  file=sys.stderr)
            continue
        name, _, value = item.partition(":")
        headers[name.strip()] = value.strip()
    return headers
