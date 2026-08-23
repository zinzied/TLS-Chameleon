"""CLI entry point: argument parsing and dispatch (stdlib argparse only)."""

import argparse
import sys
from typing import List, Optional

from .common import EXIT_ERROR, EXIT_OK, emit
from .. import __version__

__all__ = ["main", "build_parser", "EXIT_OK", "EXIT_ERROR"]


def _add_client_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--engine", choices=("auto", "curl", "httpx"),
                        default=None, help="Networking backend")
    parser.add_argument("--profile", default=None,
                        help="Fingerprint profile name")
    parser.add_argument("--timeout", type=float, default=20.0,
                        help="Request timeout in seconds")
    verify = parser.add_mutually_exclusive_group()
    verify.add_argument("--verify", dest="verify", action="store_true",
                        default=True, help="Verify TLS certificates (default)")
    verify.add_argument("--no-verify", dest="verify", action="store_false",
                        help="Disable certificate verification (unsafe)")
    parser.add_argument("--random-seed", default=None,
                        help="Seed for deterministic randomization")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="chameleon",
        description=(
            "TLS-Chameleon: fingerprint-aware HTTP networking toolkit. "
            "Diagnostics and research tool -- not a bypass or anonymity product."
        ),
    )
    parser.add_argument("--version", action="version",
                        version=f"tls-chameleon {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    # get -------------------------------------------------------------
    p_get = sub.add_parser("get", help="Fetch a URL with a spoofed client")
    _add_client_args(p_get)
    p_get.add_argument("url")
    p_get.add_argument("-X", "--method", default="GET",
                       choices=("GET", "POST", "PUT", "PATCH", "DELETE",
                                "HEAD", "OPTIONS"))
    p_get.add_argument("-H", "--header", action="append", default=[],
                       metavar="NAME: VALUE", help="Repeatable request header")
    p_get.add_argument("--max-body", type=int, default=2000,
                       help="Max body characters to print (0 disables body)")
    p_get.add_argument("--trace", action="store_true",
                       help="Include a structured network trace")
    p_get.add_argument("--json", action="store_true",
                       help="Machine-readable output")

    # inspect -----------------------------------------------------------
    p_inspect = sub.add_parser("inspect", help="Structured single-URL inspection")
    _add_client_args(p_inspect)
    p_inspect.add_argument("url")
    p_inspect.add_argument("--echo-endpoint", default=None,
                           help="TLS echo endpoint for observed fingerprint")
    p_inspect.add_argument("--json", action="store_true")

    # doctor ------------------------------------------------------------
    p_doctor = sub.add_parser("doctor", help="Diagnose connection behavior")
    _add_client_args(p_doctor)
    p_doctor.add_argument("url")
    p_doctor.add_argument("--echo-endpoint", default=None,
                          help="Compare observed fingerprint vs profile")
    p_doctor.add_argument("--json", action="store_true")

    # capture -----------------------------------------------------------
    p_capture = sub.add_parser("capture",
                               help="Capture network-observed fingerprint")
    _add_client_args(p_capture)
    p_capture.add_argument("url", nargs="?",
                           default=None,
                           help="Echo endpoint URL (default: tls.peet.ws)")
    p_capture.add_argument("--raw", action="store_true",
                           help="Include the (redacted) raw endpoint payload")
    p_capture.add_argument("--json", action="store_true")

    # diff --------------------------------------------------------------
    p_diff = sub.add_parser("diff", help="Diff two fingerprint JSON files")
    p_diff.add_argument("file_a")
    p_diff.add_argument("file_b")
    p_diff.add_argument("--json", action="store_true")

    # fingerprint -------------------------------------------------------
    p_fp = sub.add_parser("fingerprint", help="Manage fingerprint profiles")
    fp_sub = p_fp.add_subparsers(dest="fingerprint_command", metavar="SUBCOMMAND")
    fp_list = fp_sub.add_parser("list", help="List profile names")
    fp_list.add_argument("--browser", default=None,
                         help="Filter by browser family prefix")
    fp_list.add_argument("--json", action="store_true")
    fp_show = fp_sub.add_parser("show", help="Show one profile as JSON")
    fp_show.add_argument("name")
    fp_show.add_argument("--json", action="store_true",
                         help="Same as default output (stable schema)")
    fp_validate = fp_sub.add_parser("validate",
                                    help="Validate a fingerprint JSON file")
    fp_validate.add_argument("file")

    # benchmark ---------------------------------------------------------
    p_bench = sub.add_parser(
        "benchmark",
        help="Reproducible local benchmarks (see docs/BENCHMARK_METHODOLOGY.md)",
    )
    p_bench.add_argument("--scenario", action="append",
                         choices=("http1", "tls"), default=None,
                         help="Scenario to run (repeatable; default: all)")
    p_bench.add_argument("--requests", type=int, default=30,
                         help="Measured requests per client (default 30)")
    p_bench.add_argument("--warmup", type=int, default=5,
                         help="Discarded warm-up requests (default 5)")
    p_bench.add_argument("--save", default=None, metavar="PATH",
                         help="Also write the full JSON report to PATH")
    p_bench.add_argument("--json", action="store_true")

    # version -----------------------------------------------------------
    p_version = sub.add_parser("version", help="Print version information")
    p_version.add_argument("--json", action="store_true")

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return EXIT_ERROR

    # Imported lazily so --help/--version stay fast and dependency-light.
    from . import get as cmd_get, inspect as cmd_inspect, doctor as cmd_doctor
    from . import capture as cmd_capture, diff as cmd_diff
    from . import fingerprint as cmd_fingerprint, benchmark as cmd_benchmark

    def _run_version(args) -> int:
        payload = {
            "schema": "tls-chameleon.version/1",
            "name": "tls-chameleon",
            "version": __version__,
        }
        if getattr(args, "json", False):
            emit(payload, True)
        else:
            print(f"tls-chameleon {__version__}")
        return EXIT_OK

    handlers = {
        "get": cmd_get.run,
        "inspect": cmd_inspect.run,
        "doctor": cmd_doctor.run,
        "capture": cmd_capture.run,
        "diff": cmd_diff.run,
        "fingerprint": cmd_fingerprint.run,
        "benchmark": cmd_benchmark.run,
        "version": _run_version,
    }
    handler = handlers.get(args.command)
    if handler is None:  # pragma: no cover - argparse guards this
        parser.print_help()
        return EXIT_ERROR

    if args.command in ("get", "inspect", "doctor", "capture"):
        from .common import build_client

        args.client = build_client(args)
    try:
        return handler(args)
    except KeyboardInterrupt:  # pragma: no cover - interactive use
        print("interrupted", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
