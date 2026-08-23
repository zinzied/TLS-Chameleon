"""`chameleon get`: fetch a URL with a spoofed client."""

import sys
import time
from urllib.parse import urlsplit

from ..security.redaction import redact_headers, redact_url
from .common import EXIT_ERROR, EXIT_OK, emit, parse_headers

__all__ = ["run"]


def run(args) -> int:
    headers = parse_headers(args.header)
    started = time.perf_counter()
    error = None
    response = None
    trace = None
    try:
        response = args.client.request(
            args.method, args.url, headers=headers or None, trace=args.trace
        )
        if args.trace:
            trace = getattr(response, "trace", None)
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"

    if error is not None:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_ERROR

    total_ms = (time.perf_counter() - started) * 1000.0
    status = getattr(response, "status_code", 0)
    resp_headers = dict(getattr(response, "headers", {}) or {})

    if args.json:
        payload = {
            "schema": "tls-chameleon.get/1",
            "url": redact_url(args.url),
            "method": args.method,
            "status_code": status,
            "elapsed_ms": round(total_ms, 2),
            "headers": redact_headers(resp_headers),
            "profile": getattr(args.client, "profile_name", None),
            "backend": getattr(args.client, "engine", None),
        }
        if args.max_body > 0 and args.method not in ("HEAD",):
            try:
                body = getattr(response, "text", "") or ""
            except Exception:
                body = "<binary body>"
            payload["body"] = body[: args.max_body]
            payload["body_truncated"] = len(body) > args.max_body
        if trace is not None:
            payload["trace"] = trace.to_dict()
        emit(payload, True)
    else:
        host = urlsplit(args.url).netloc or args.url
        print(f"{status} {args.method} {host} ({total_ms:.0f}ms)")
        for name in ("server", "content-type", "content-length"):
            value = resp_headers.get(name)
            if value:
                print(f"{name}: {value}")
        sensitive = [k for k in resp_headers
                     if k.lower() in ("set-cookie", "authorization")]
        if sensitive:
            print(f"({len(sensitive)} sensitive header(s) hidden)")
        if args.trace and trace is not None:
            print("---")
            print(trace.to_text())
        elif args.max_body > 0 and args.method != "HEAD":
            try:
                body = getattr(response, "text", "") or ""
            except Exception:
                body = "<binary body>"
            print(body[: args.max_body])
            if len(body) > args.max_body:
                print(f"... [{len(body) - args.max_body} more characters]")

    return EXIT_OK if status < 400 else EXIT_ERROR
