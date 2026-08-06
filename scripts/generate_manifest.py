#!/usr/bin/env python3
"""Generate or verify the release SHA-256 manifest."""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "MANIFEST.sha256"
EXCLUDED_NAMES = {".DS_Store", "MANIFEST.sha256"}
EXCLUDED_PARTS = {".git", "__pycache__", ".venv"}


def release_files() -> list[Path]:
    return sorted(
        (
            path
            for path in ROOT.rglob("*")
            if path.is_file()
            and path.name not in EXCLUDED_NAMES
            and not any(part in EXCLUDED_PARTS for part in path.parts)
        ),
        key=lambda path: path.relative_to(ROOT).as_posix(),
    )


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def expected_manifest() -> str:
    return "".join(
        f"{digest(path)}  {path.relative_to(ROOT).as_posix()}\n"
        for path in release_files()
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify the existing manifest instead of replacing it",
    )
    args = parser.parse_args()
    expected = expected_manifest()

    if args.check:
        if not MANIFEST.is_file():
            print("MANIFEST.sha256 is not present; generate it after freezing the release.", file=sys.stderr)
            return 1
        actual = MANIFEST.read_text(encoding="utf-8")
        if actual != expected:
            print("MANIFEST.sha256 does not match the repository tree.", file=sys.stderr)
            return 1
        print(f"Verified {len(release_files())} release files.")
        return 0

    MANIFEST.write_text(expected, encoding="utf-8", newline="\n")
    print(f"Wrote checksums for {len(release_files())} release files to MANIFEST.sha256.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

