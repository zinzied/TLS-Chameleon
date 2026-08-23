"""`chameleon diff`: compare two fingerprint JSON files.

Accepts any of:
  * a single fingerprint dict (schema tls-chameleon.fingerprint/1),
  * a capture file (schema tls-chameleon.capture/1, nested "fingerprint"),
  * a registry export (nested "fingerprints" list -- uses the first entry,
    or pass the file twice for intra-file comparisons).
"""

import json
import sys
from pathlib import Path

from ..fingerprint.diff import diff_fingerprints
from ..fingerprint.model import Fingerprint
from .common import EXIT_ERROR, EXIT_OK, emit

__all__ = ["run", "load_fingerprint"]


def load_fingerprint(path: str) -> Fingerprint:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(data, dict) and "fingerprint" in data:  # capture schema
        data = data["fingerprint"]
    if isinstance(data, dict) and "fingerprints" in data:  # registry export
        entries = data["fingerprints"]
        if not entries:
            raise ValueError(f"{path}: empty fingerprints list")
        data = entries[0]
    return Fingerprint.from_dict(data)


def run(args) -> int:
    try:
        fp_a = load_fingerprint(args.file_a)
        fp_b = load_fingerprint(args.file_b)
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        print(f"error loading fingerprint files: {exc}", file=sys.stderr)
        return EXIT_ERROR

    report = diff_fingerprints(fp_a, fp_b)
    if args.json:
        emit(report.to_dict(), True)
    else:
        print(report.to_text())
    return EXIT_OK
