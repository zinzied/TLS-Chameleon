"""`chameleon capture`: capture the network-observed fingerprint."""

from ..fingerprint.capture import DEFAULT_ECHO_URL, capture
from ..security.redaction import redact_mapping
from .common import EXIT_OK, emit

__all__ = ["run"]


def run(args) -> int:
    url = args.url or DEFAULT_ECHO_URL
    session = getattr(args.client, "session", None)
    result = capture(url=url, session=session, timeout=args.timeout,
                     name="cli_capture")

    payload = result.to_dict()
    if getattr(args, "raw", False):
        payload["raw"] = redact_mapping(result.raw)

    if args.json:
        emit(payload, True)
    else:
        fp = result.fingerprint
        tls = fp.tls.to_dict()
        print(f"endpoint      {result.endpoint}")
        print(f"captured_at   {result.captured_at}")
        print(f"ja3_hash      {tls.get('ja3_hash')}")
        if tls.get("ja4"):
            print(f"ja4           {tls['ja4']}")
        print(f"user_agent    {fp.user_agent or '-'}")
        print(f"source        {fp.metadata.source} (verified={fp.metadata.verified})")
        if getattr(args, "raw", False):
            import json

            print("raw:")
            print(json.dumps(payload["raw"], indent=2)[:2000])
    return EXIT_OK
