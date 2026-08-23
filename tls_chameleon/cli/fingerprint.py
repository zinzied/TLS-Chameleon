"""`chameleon fingerprint`: list / show / validate profiles."""

import json
import sys
from pathlib import Path

from ..fingerprint.headers import check_header_consistency
from ..fingerprint.registry import FingerprintRegistry
from ..fingerprint.validator import (
    validate_fingerprint,
    validate_profile_dict,
)
from .common import EXIT_ERROR, EXIT_FAILED_CHECK, EXIT_OK, emit

__all__ = ["run"]


def run(args) -> int:
    command = getattr(args, "fingerprint_command", None)
    if command == "list":
        return _list(args)
    if command == "show":
        return _show(args)
    if command == "validate":
        return _validate(args)
    print("usage: chameleon fingerprint {list|show|validate} ...",
          file=sys.stderr)
    return EXIT_ERROR


def _list(args) -> int:
    registry = FingerprintRegistry()
    names = registry.list()
    browser = getattr(args, "browser", None)
    if browser:
        prefix = browser.lower()
        names = [n for n in names if n.startswith(prefix)]
    if args.json:
        emit({"schema": "tls-chameleon.fingerprint-list/1",
              "count": len(names), "profiles": names}, True)
    else:
        for name in names:
            print(name)
        print(f"-- {len(names)} profile(s)", file=sys.stderr)
    return EXIT_OK


def _show(args) -> int:
    registry = FingerprintRegistry()
    try:
        fingerprint = registry.get(args.name)
    except KeyError:
        print(f"error: unknown profile '{args.name}'", file=sys.stderr)
        return EXIT_ERROR
    if args.json or True:
        emit(fingerprint.to_dict(), True)
    else:  # pragma: no cover - unreachable, kept for symmetry
        print(json.dumps(fingerprint.to_dict(), indent=2))
    return EXIT_OK


def _load_pairs(data):
    """Normalize any supported layout into (Fingerprint|None, legacy_dict).

    Returns a list of tuples. A ``None`` fingerprint means the entry is a
    legacy/gallery-style profile dict and must go through
    ``validate_profile_dict``.
    """
    from ..fingerprint.model import Fingerprint

    pairs = []
    entries = data.get("fingerprints") if isinstance(data, dict) else None
    if isinstance(entries, list):  # registry export
        for entry in entries:
            pairs.append((Fingerprint.from_dict(entry), entry))
    elif isinstance(data, dict) and "fingerprint" in data:  # capture file
        entry = data["fingerprint"]
        pairs.append((Fingerprint.from_dict(entry), entry))
    elif isinstance(data, dict) and "tls" in data:  # bare model fingerprint
        pairs.append((Fingerprint.from_dict(data), data))
    else:  # legacy / gallery-style profile dict
        pairs.append((None, data))
    return pairs


def _validate(args) -> int:
    path = Path(args.file)
    if not path.exists():
        print(f"error: file not found: {path}", file=sys.stderr)
        return EXIT_ERROR
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(f"error: invalid JSON: {exc}", file=sys.stderr)
        return EXIT_ERROR

    from ..fingerprint.adapter import fingerprint_to_legacy

    errors, warnings = [], []
    for fingerprint, source in _load_pairs(data):
        if fingerprint is not None:
            issues = validate_fingerprint(fingerprint)
            legacy = fingerprint_to_legacy(fingerprint)
        else:
            issues = validate_profile_dict(
                source, name=str(source.get("name", "unnamed"))
            )
            legacy = source
        errors.extend(i for i in issues if i.severity == "error")
        warnings.extend(i for i in issues if i.severity == "warning")
        header_errors = [i for i in check_header_consistency(legacy)
                         if i.severity == "error"]
        errors.extend(header_errors)

    is_valid = not errors
    emit(
        {
            "schema": "tls-chameleon.validate/1",
            "file": str(path),
            "valid": is_valid,
            "errors": [i.to_dict() for i in errors],
            "warnings": [i.to_dict() for i in warnings],
        },
        True,
    )
    return EXIT_OK if is_valid else EXIT_FAILED_CHECK
