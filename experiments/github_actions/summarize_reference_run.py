#!/usr/bin/env python3
"""Validate and summarize the frozen three-attempt cross-plane reference run."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path
from typing import Any, Sequence


REPOSITORY = "obedebessa/eacp-operational-provenance"
RUN_ID = 33682116347
HEAD_SHA = "76b2ed54381ae52cf0f54cd22a20341c3216b77b"
SUBJECT_DIGEST = "sha256:ee6521f290b2168b6e0935a181d4cff9be1ac3f505666ef0e3c98fae8199917a"
JOIN_STATUS = "observed_cross_plane_link_with_subject_digest"
DEFAULT_ROOT = Path(__file__).resolve().parent / "results/reference/run-33682116347"
REFERENCE_MANIFEST = "REFERENCE_SHA256SUMS"


class ReferenceError(ValueError):
    pass


def sha256(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ReferenceError(f"expected a JSON object: {path}")
    return value


def exactly_one(paths: list[Path], description: str) -> Path:
    if len(paths) != 1:
        raise ReferenceError(f"expected one {description}, found {len(paths)}")
    return paths[0]


def verify_manifest(root: Path, manifest: Path) -> int:
    count = 0
    for line_number, raw in enumerate(manifest.read_text(encoding="utf-8").splitlines(), 1):
        if not raw.strip():
            continue
        try:
            expected, relative = raw.split(None, 1)
        except ValueError as exc:
            raise ReferenceError(f"malformed manifest line {manifest}:{line_number}") from exc
        relative = relative.strip()
        if relative.startswith("*"):
            relative = relative[1:]
        candidate = Path(relative)
        if candidate.is_absolute() or ".." in candidate.parts:
            raise ReferenceError(f"unsafe manifest path {relative!r} in {manifest}")
        target = (root / candidate).resolve()
        if root.resolve() not in target.parents and target != root.resolve():
            raise ReferenceError(f"manifest path escapes its root: {relative!r}")
        if not target.is_file() or sha256(target) != expected.lower():
            raise ReferenceError(f"checksum mismatch for {target}")
        count += 1
    if not count:
        raise ReferenceError(f"empty checksum manifest: {manifest}")
    return count


def decode_statement(bundle_path: Path) -> dict[str, Any]:
    lines = [line for line in bundle_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if len(lines) != 1:
        raise ReferenceError(f"expected one attestation bundle in {bundle_path}")
    bundle = json.loads(lines[0])
    if bundle.get("mediaType") != "application/vnd.dev.sigstore.bundle.v0.3+json":
        raise ReferenceError(f"unexpected Sigstore media type in {bundle_path}")
    encoded = bundle.get("dsseEnvelope", {}).get("payload")
    if not isinstance(encoded, str):
        raise ReferenceError(f"missing DSSE payload in {bundle_path}")
    statement = json.loads(base64.b64decode(encoded).decode("utf-8"))
    if not isinstance(statement, dict):
        raise ReferenceError(f"invalid DSSE statement in {bundle_path}")
    return statement


def summarize_attempt(root: Path, attempt: int) -> dict[str, Any]:
    attempt_root = root / f"attempt-{attempt}"
    downloaded = attempt_root / "downloaded-artifact"
    runtime = downloaded / "eacp-cross-plane-v1.3-results"
    finalized = attempt_root / "finalized"
    archive = downloaded / f"eacp-cross-plane-v1.3-{RUN_ID}-{attempt}.tar.gz"
    archive_manifest = archive.with_suffix(archive.suffix + ".sha256")
    attestation = exactly_one(list((attempt_root / "attestation").glob("*.jsonl")), "attestation bundle")

    archive_checks = verify_manifest(downloaded, archive_manifest)
    public_checks = verify_manifest(runtime, runtime / "PUBLIC_SHA256SUMS")
    github_checks = verify_manifest(runtime / "github", runtime / "github/SHA256SUMS")
    audit_checks = verify_manifest(
        runtime / "kubernetes/audit", runtime / "kubernetes/audit/SHA256SUMS"
    )
    final_checks = verify_manifest(finalized, finalized / "SHA256SUMS")

    environment = load_json(runtime / "environment.json")
    runtime_join = load_json(runtime / "cross_plane_join.json")
    completed_join = load_json(finalized / "cross_plane_join_completed.json")
    audit = load_json(runtime / "kubernetes/audit/audit_summary.json")
    completed_source = load_json(finalized / "github_completed/source/github_actions.json")
    finalization = load_json(finalized / "finalization.json")

    expected_correlation = f"eacp-gha-1324720646-{RUN_ID}-{attempt}"
    if environment.get("run_id") != RUN_ID or environment.get("run_attempt") != attempt:
        raise ReferenceError(f"run identity mismatch in attempt {attempt}")
    if environment.get("head_sha") != HEAD_SHA:
        raise ReferenceError(f"source revision mismatch in attempt {attempt}")
    if environment.get("correlation_id") != expected_correlation:
        raise ReferenceError(f"correlation mismatch in attempt {attempt}")
    for report in (runtime_join, completed_join):
        if report.get("status") != JOIN_STATUS or report.get("correlation_id") != expected_correlation:
            raise ReferenceError(f"join status or identity mismatch in attempt {attempt}")
    run = completed_source.get("run", {})
    if (
        run.get("id") != RUN_ID
        or run.get("run_attempt") != attempt
        or run.get("head_sha") != HEAD_SHA
        or run.get("status") != "completed"
        or run.get("conclusion") != "success"
    ):
        raise ReferenceError(f"completed GitHub state mismatch in attempt {attempt}")
    if finalization.get("github_run_conclusion") != "success":
        raise ReferenceError(f"finalization did not close successfully in attempt {attempt}")

    kubernetes = completed_join.get("kubernetes", {})
    negative = kubernetes.get("negative_control", {})
    rbac = kubernetes.get("rbac_denial_binding", {})
    pods = kubernetes.get("pods", {})
    if not negative.get("correlation_annotation_absent"):
        raise ReferenceError(f"negative control failed in attempt {attempt}")
    if (
        rbac.get("binding_method") != "adapter_explicit_exact_target"
        or rbac.get("matching_http_403_records") != 1
        or rbac.get("source_native_correlation_records") != 0
    ):
        raise ReferenceError(f"RBAC binding boundary mismatch in attempt {attempt}")
    if not (
        pods.get("all_pods_have_exact_correlation_id")
        and pods.get("pod_spec_subject_exact_match")
        and pods.get("runtime_image_id_exact_subject_digest_match")
    ):
        raise ReferenceError(f"Pod identity or subject mismatch in attempt {attempt}")
    positive = audit.get("positive_control", {})
    if positive.get("matching_audit_records") != 8:
        raise ReferenceError(f"unexpected source-native positive count in attempt {attempt}")

    archive_digest = sha256(archive)
    statement = decode_statement(attestation)
    subjects = statement.get("subject")
    expected_subject = {
        "name": archive.name,
        "digest": {"sha256": archive_digest},
    }
    if subjects != [expected_subject]:
        raise ReferenceError(f"attestation subject mismatch in attempt {attempt}")
    if statement.get("predicateType") != "https://slsa.dev/provenance/v1":
        raise ReferenceError(f"unexpected attestation predicate in attempt {attempt}")

    return {
        "attempt": attempt,
        "correlation_id": expected_correlation,
        "github_completed_evidence_records": completed_join["github_actions"]["evidence_rows"],
        "kubernetes_namespace_records": audit["scope"]["namespace_records"],
        "kubernetes_source_native_positive_records": positive["matching_audit_records"],
        "kubernetes_projected_records_with_exact_id": kubernetes["csv_rows_with_exact_id"],
        "negative_control_audit_records": audit["negative_control"]["audit_records"],
        "negative_control_unjoined": True,
        "target_bound_http_403_records": 1,
        "rbac_correlation_evidence_method": "explicit",
        "rbac_source_native_correlation_records": 0,
        "pod_spec_and_runtime_subject_digest_exact": True,
        "archive_sha256": archive_digest,
        "attestation_bundle_sha256": sha256(attestation),
        "attestation_statement_subject_matches_archive": True,
        "verified_manifest_entries": (
            archive_checks + public_checks + github_checks + audit_checks + final_checks
        ),
    }


def summarize(root: Path) -> dict[str, Any]:
    attempts = [summarize_attempt(root, attempt) for attempt in (1, 2, 3)]
    if len({row["correlation_id"] for row in attempts}) != 3:
        raise ReferenceError("attempt correlation identifiers are not distinct")
    return {
        "schema_version": "eacp.github-actions.reference-run-summary/1.3.0",
        "source_classification": "real_public_github_actions_and_kubernetes_api_evidence",
        "run": {
            "repository": REPOSITORY,
            "run_id": RUN_ID,
            "url": f"https://github.com/{REPOSITORY}/actions/runs/{RUN_ID}",
            "head_sha": HEAD_SHA,
            "attempts": 3,
            "all_conclusions": "success",
        },
        "subject": {
            "uri": "registry.k8s.io/pause",
            "digest": SUBJECT_DIGEST,
        },
        "attempt_results": attempts,
        "aggregate": {
            "successful_exact_link_attempts": 3,
            "successful_negative_controls": 3,
            "successful_target_bound_rbac_controls": 3,
            "archive_attestation_statements_matching_subject": 3,
            "distinct_attempt_specific_correlation_ids": 3,
        },
        "attestation_boundary": (
            "Bundled DSSE statements name the exact archive digests. Cryptographic identity and "
            "transparency-log verification is performed separately with gh attestation verify."
        ),
        "claim_boundary": (
            "Three controlled attempts demonstrate reproducible exact delivery-to-runtime composition "
            "for this workflow and ephemeral single-node cluster. They do not establish semantic "
            "causality, source truth, production effectiveness, or managed-cluster scalability."
        ),
    }


def render_reference_manifest(root: Path) -> str:
    paths = sorted(
        (
            path
            for path in root.rglob("*")
            if path.is_file() and path.name != REFERENCE_MANIFEST
        ),
        key=lambda path: path.relative_to(root).as_posix(),
    )
    return "".join(
        f"{sha256(path)}  ./{path.relative_to(root).as_posix()}\n" for path in paths
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=DEFAULT_ROOT)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--verify", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    summary = summarize(args.root)
    output = args.root / "reference_summary.json"
    rendered = json.dumps(summary, indent=2, sort_keys=True) + "\n"
    if args.write:
        output.write_text(rendered, encoding="utf-8")
        (args.root / REFERENCE_MANIFEST).write_text(
            render_reference_manifest(args.root), encoding="utf-8"
        )
        print(f"Wrote {output}")
    else:
        if not output.is_file() or output.read_text(encoding="utf-8") != rendered:
            raise SystemExit("reference_summary.json differs from validated source bundles")
        manifest = args.root / REFERENCE_MANIFEST
        expected_manifest = render_reference_manifest(args.root)
        if not manifest.is_file() or manifest.read_text(encoding="utf-8") != expected_manifest:
            raise SystemExit(f"{REFERENCE_MANIFEST} differs from the frozen file inventory")
        verify_manifest(args.root, manifest)
        print(f"Verified {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
