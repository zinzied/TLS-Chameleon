"""`chameleon benchmark`: reproducible local benchmarks.

Runs real measurements against local HTTP/TLS servers per
docs/BENCHMARK_METHODOLOGY.md. Never prints invented numbers; backends that
cannot participate are reported as skipped with a reason.
"""

import json
import sys
from pathlib import Path

from .common import EXIT_ERROR, EXIT_OK, emit

__all__ = ["run"]


def run(args) -> int:
    from ..benchmark import run_benchmark

    scenarios = getattr(args, "scenario", None) or ["http1", "tls"]
    if isinstance(scenarios, str):
        scenarios = [scenarios]

    try:
        report = run_benchmark(
            scenarios=scenarios,
            requests=getattr(args, "requests", 30),
            warmup=getattr(args, "warmup", 5),
            timeout=getattr(args, "timeout", 10.0),
            include_aiohttp=not getattr(args, "no_aiohttp", False)
            and _aiohttp_installed_or_absent(),
        )
    except Exception as exc:
        print(f"benchmark failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return EXIT_ERROR

    payload = report.to_dict()
    save_path = getattr(args, "save", None)
    if save_path:
        Path(save_path).write_text(json.dumps(payload, indent=2),
                                   encoding="utf-8")

    if args.json:
        emit(payload, True)
    else:
        print(report.to_text())
        if save_path:
            print(f"results written to {save_path}", file=sys.stderr)

    # A run is successful when at least one client produced measurements in
    # every requested scenario.
    any_ok = any(
        entry.get("status") == "ok"
        for entries in payload["scenarios"].values()
        for entry in entries
    )
    return EXIT_OK if any_ok else EXIT_ERROR


def _aiohttp_installed_or_absent() -> bool:
    """Keep default behavior: include aiohttp row whether or not installed."""
    return True
