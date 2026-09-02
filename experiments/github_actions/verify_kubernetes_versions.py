#!/usr/bin/env python3
"""Verify that kubectl, API server, and kubelet match a declared target."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any, Sequence


VERSION = re.compile(r"v[0-9]+\.[0-9]+\.[0-9]+")


class VersionError(ValueError):
    pass


def observed_versions(snapshot: dict[str, Any], kubelet_text: str) -> dict[str, str | None]:
    kubelet = kubelet_text.strip().removeprefix("Kubernetes ")
    return {
        "kubectl client": snapshot.get("clientVersion", {}).get("gitVersion"),
        "Kubernetes server": snapshot.get("serverVersion", {}).get("gitVersion"),
        "kubelet": kubelet or None,
    }


def verify(snapshot: dict[str, Any], kubelet_text: str, expected: str) -> dict[str, str]:
    if not VERSION.fullmatch(expected):
        raise VersionError(f"invalid expected Kubernetes version: {expected!r}")
    observed = observed_versions(snapshot, kubelet_text)
    mismatches = {name: value for name, value in observed.items() if value != expected}
    if mismatches:
        raise VersionError(f"declared Kubernetes profile {expected!r} mismatches {mismatches!r}")
    return {name: str(value) for name, value in observed.items()}


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser()
    value.add_argument("--version-json", type=Path, required=True)
    value.add_argument("--kubelet-file", type=Path, required=True)
    value.add_argument("--expected", required=True)
    return value


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    snapshot = json.loads(args.version_json.read_text(encoding="utf-8"))
    if not isinstance(snapshot, dict):
        raise VersionError("kubectl version output must be a JSON object")
    verify(snapshot, args.kubelet_file.read_text(encoding="utf-8"), args.expected)
    print(f"Validated exact client/server/kubelet profile: {args.expected}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
