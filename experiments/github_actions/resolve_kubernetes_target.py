#!/usr/bin/env python3
"""Fail-closed resolver for the live experiment's pinned Kubernetes target."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any, Sequence


SCHEMA = "eacp.kubernetes-targets/1.3.0"
TARGETS = {"v1.34.8", "v1.35.5", "v1.36.1"}
TAG_PATTERN = re.compile(
    r"eacp-v1\.3-evidence/k8s-(v1\.(?:34\.8|35\.5|36\.1))/run-0[1-3]"
)
HEX64 = re.compile(r"[0-9a-f]{64}")


class TargetError(ValueError):
    pass


def load_manifest(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or value.get("schema_version") != SCHEMA:
        raise TargetError("unexpected Kubernetes-target manifest schema")
    kind = value.get("kind")
    targets = value.get("targets")
    if not isinstance(kind, dict) or not isinstance(targets, dict):
        raise TargetError("target manifest requires kind and targets objects")
    if set(targets) != TARGETS:
        raise TargetError(f"target manifest must contain exactly {sorted(TARGETS)}")
    if kind.get("version") != "v0.32.0" or not HEX64.fullmatch(
        str(kind.get("linux_amd64_sha256") or "")
    ):
        raise TargetError("kind version or checksum is not pinned as expected")
    for version, target in targets.items():
        if not isinstance(target, dict):
            raise TargetError(f"target {version} must be an object")
        node_image = str(target.get("node_image") or "")
        kubectl_digest = str(target.get("kubectl_linux_amd64_sha256") or "")
        if not node_image.startswith(f"kindest/node:{version}@sha256:"):
            raise TargetError(f"target {version} has a mismatched node image")
        if not HEX64.fullmatch(node_image.rsplit("sha256:", 1)[-1]):
            raise TargetError(f"target {version} node image is not digest pinned")
        if not HEX64.fullmatch(kubectl_digest):
            raise TargetError(f"target {version} kubectl checksum is invalid")
    return value


def select_version(
    *, event: str, ref_type: str, ref_name: str, requested: str
) -> str:
    if event == "workflow_dispatch":
        selected = requested
    elif event == "push" and ref_type == "tag":
        match = TAG_PATTERN.fullmatch(ref_name)
        if not match:
            raise TargetError(f"unapproved evidence tag: {ref_name!r}")
        selected = match.group(1)
    else:
        raise TargetError(
            f"unsupported trigger event={event!r} ref_type={ref_type!r} ref={ref_name!r}"
        )
    if selected not in TARGETS:
        raise TargetError(f"Kubernetes profile is not allowlisted: {selected!r}")
    return selected


def resolve(
    manifest: dict[str, Any], *, event: str, ref_type: str, ref_name: str, requested: str
) -> dict[str, str]:
    selected = select_version(
        event=event, ref_type=ref_type, ref_name=ref_name, requested=requested
    )
    target = manifest["targets"][selected]
    return {
        "KUBERNETES_PROFILE": selected,
        "EACP_EXPECTED_KUBERNETES_VERSION": selected,
        "KIND_VERSION": manifest["kind"]["version"],
        "KIND_LINUX_AMD64_SHA256": manifest["kind"]["linux_amd64_sha256"],
        "KIND_NODE_IMAGE": target["node_image"],
        "KUBECTL_LINUX_AMD64_SHA256": target["kubectl_linux_amd64_sha256"],
    }


def write_github_env(path: Path, values: dict[str, str]) -> None:
    with path.open("a", encoding="utf-8") as stream:
        for key, value in values.items():
            if "\n" in value or "\r" in value:
                raise TargetError(f"unsafe control character in {key}")
            stream.write(f"{key}={value}\n")


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser()
    value.add_argument("--manifest", type=Path, required=True)
    value.add_argument("--event", required=True)
    value.add_argument("--ref-type", required=True)
    value.add_argument("--ref-name", required=True)
    value.add_argument("--requested", default="")
    value.add_argument("--github-env", type=Path, required=True)
    return value


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    values = resolve(
        load_manifest(args.manifest),
        event=args.event,
        ref_type=args.ref_type,
        ref_name=args.ref_name,
        requested=args.requested,
    )
    write_github_env(args.github_env, values)
    print(f"Resolved {values['KUBERNETES_PROFILE']} to {values['KIND_NODE_IMAGE']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
