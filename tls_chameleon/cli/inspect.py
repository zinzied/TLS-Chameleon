"""`chameleon inspect`: structured single-URL inspection."""

from ..diagnostics.inspector import inspect_url
from .common import EXIT_ERROR, EXIT_OK, emit

__all__ = ["run"]


def run(args) -> int:
    echo = getattr(args, "echo_endpoint", None)
    result = inspect_url(
        args.url,
        args.client,
        echo_endpoint=echo,
        timeout=args.timeout,
    )
    if result.error:
        # Still emit the structured payload so agents get machine-readable
        # failure information, then fail.
        if args.json:
            emit(result.to_dict(), True)
        else:
            print(result.to_text())
        return EXIT_ERROR
    if args.json:
        emit(result.to_dict(), True)
    else:
        print(result.to_text())
    return EXIT_OK
