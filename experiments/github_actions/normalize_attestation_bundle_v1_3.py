#!/usr/bin/env python3
"""Normalize GitHub CLI attestation bundle names without changing their bytes."""

from __future__ import annotations

import argparse
import re
from pathlib import Path


BUNDLE_NAME = re.compile(r"sha256(?P<separator>[-:])(?P<digest>[0-9a-f]{64})\.jsonl")


class BundleNameError(ValueError):
    """Raised when a downloaded attestation directory is not unambiguous."""


def normalize_bundle(directory: Path) -> Path:
    if not directory.is_dir():
        raise BundleNameError(f"attestation directory does not exist: {directory}")

    matches = sorted(
        path
        for path in directory.iterdir()
        if BUNDLE_NAME.fullmatch(path.name)
    )
    if len(matches) != 1:
        raise BundleNameError(
            f"expected exactly one SHA-256 attestation bundle; found {len(matches)}"
        )

    source = matches[0]
    if source.is_symlink() or not source.is_file():
        raise BundleNameError("attestation bundle must be one regular, non-symlink file")

    match = BUNDLE_NAME.fullmatch(source.name)
    assert match is not None
    target = directory / f"sha256-{match.group('digest')}.jsonl"
    if source == target:
        return source
    if target.exists() or target.is_symlink():
        raise BundleNameError(f"refusing to overwrite normalized bundle: {target.name}")
    source.rename(target)
    return target


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    try:
        print(normalize_bundle(args.directory))
    except BundleNameError as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
