#!/usr/bin/env python3
"""Generate or verify a SHA-256 manifest for the tracked release tree."""

from __future__ import annotations

import argparse
import hashlib
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST_NAME = "MANIFEST-v1.3.0.sha256"
EXCLUDED_NAMES = {".DS_Store"}
EXCLUDED_PARTS = {".git", "__pycache__", ".venv"}


def resolve_manifest(raw_name: str) -> Path:
    candidate = Path(raw_name)
    if candidate.is_absolute() or ".." in candidate.parts:
        raise ValueError("--manifest must be a safe repository-relative path")
    manifest = (ROOT / candidate).resolve()
    try:
        manifest.relative_to(ROOT.resolve())
    except ValueError as exc:
        raise ValueError("--manifest must remain inside the repository") from exc
    return manifest


def git_tracked_paths() -> list[Path] | None:
    """Return index paths when ROOT is a checkout; otherwise signal archive mode."""

    if not (ROOT / ".git").exists():
        return None
    result = subprocess.run(
        ["git", "ls-files", "-z", "--cached"],
        cwd=ROOT,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"cannot enumerate tracked release files: {detail}")
    names = [name for name in result.stdout.split(b"\0") if name]
    return [ROOT / name.decode("utf-8", errors="strict") for name in names]


def release_files(manifest: Path) -> list[Path]:
    tracked = git_tracked_paths()
    candidates = tracked if tracked is not None else list(ROOT.rglob("*"))
    files: list[Path] = []
    missing: list[str] = []
    for path in candidates:
        if path.resolve() == manifest:
            continue
        if path.name in EXCLUDED_NAMES or any(part in EXCLUDED_PARTS for part in path.parts):
            continue
        if path.is_symlink():
            raise RuntimeError(f"release tree contains a symbolic link: {path.relative_to(ROOT)}")
        if not path.is_file():
            if tracked is not None:
                missing.append(path.relative_to(ROOT).as_posix())
            continue
        files.append(path)
    if missing:
        raise RuntimeError(f"tracked release files are missing from disk: {missing}")
    return sorted(files, key=lambda path: path.relative_to(ROOT).as_posix())


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def expected_manifest(manifest: Path) -> tuple[str, int]:
    files = release_files(manifest)
    content = "".join(
        f"{digest(path)}  {path.relative_to(ROOT).as_posix()}\n" for path in files
    )
    return content, len(files)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--manifest",
        default=DEFAULT_MANIFEST_NAME,
        help=f"repository-relative manifest path (default: {DEFAULT_MANIFEST_NAME})",
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true", help="verify an existing manifest")
    mode.add_argument("--write", action="store_true", help="write the manifest explicitly")
    args = parser.parse_args()

    try:
        manifest = resolve_manifest(args.manifest)
        expected, count = expected_manifest(manifest)
    except (OSError, RuntimeError, UnicodeError, ValueError) as exc:
        print(f"Cannot define release manifest: {exc}", file=sys.stderr)
        return 1

    label = manifest.relative_to(ROOT).as_posix()
    if args.check:
        if not manifest.is_file():
            print(f"{label} is not present; generate it after freezing the release.", file=sys.stderr)
            return 1
        actual = manifest.read_text(encoding="utf-8")
        if actual != expected:
            print(f"{label} does not match the tracked release tree.", file=sys.stderr)
            return 1
        print(f"Verified {count} tracked release files in {label}.")
        return 0

    manifest.parent.mkdir(parents=True, exist_ok=True)
    manifest.write_text(expected, encoding="utf-8", newline="\n")
    print(f"Wrote checksums for {count} tracked release files to {label}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
