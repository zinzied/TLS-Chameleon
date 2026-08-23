"""`chameleon doctor`: diagnose why a connection behaves as it does."""

from ..diagnostics.doctor import doctor
from .common import EXIT_FAILED_CHECK, EXIT_OK, emit

__all__ = ["run"]


def run(args) -> int:
    report = doctor(
        args.url,
        args.client,
        echo_endpoint=getattr(args, "echo_endpoint", None),
        timeout=args.timeout,
    )
    if args.json:
        emit(report.to_dict(), True)
    else:
        print(report.to_text())
    # warn keeps exit 0 (informational); fail is a real failure for automation.
    return EXIT_OK if report.verdict != "fail" else EXIT_FAILED_CHECK
