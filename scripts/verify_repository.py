#!/usr/bin/env python3
"""Check the public EACP artifact for release boundaries and frozen integrity."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import re
import struct
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

REQUIRED_FILES = (
    "README.md",
    "CITATION.cff",
    "LICENSE",
    "NOTICE",
    "LICENSES/CC-BY-4.0.txt",
    "LICENSES/README.md",
    "THIRD_PARTY_NOTICES.md",
    "pyproject.toml",
    ".gitignore",
    ".github/workflows/reproduce-small.yml",
    "scripts/reproduce_small.sh",
)

REQUIRED_DIRECTORIES = (
    "benchmark/sqlite",
    "experiments/kubernetes",
    "experiments/comparison/opentelemetry",
    "data/sqlite",
    "data/kubernetes",
    "data/comparison",
    "figures",
    "paper",
    "tests",
)

RELEASE_REQUIRED_FILES = (
    "benchmark/sqlite/eacp_benchmark.py",
    "data/sqlite/environment.json",
    "data/sqlite/query_plans.json",
    "data/sqlite/summary_results.csv",
    "data/sqlite/summary_results.json",
    "data/sqlite/trial_results.csv",
    "experiments/kubernetes/analyze_audit.py",
    "experiments/kubernetes/audit-policy.yaml",
    "experiments/kubernetes/kind-config.template.yaml",
    "experiments/kubernetes/run_experiment.sh",
    "experiments/kubernetes/workload.yaml",
    "experiments/kubernetes/RESULTS_REPORT.md",
    "data/kubernetes/20260806T031453Z/analysis/public_filtered_audit.jsonl",
    "data/kubernetes/20260806T031453Z/analysis/normalized_evidence.csv",
    "data/kubernetes/20260806T031453Z/analysis/summary.json",
    "data/kubernetes/20260806T031453Z/operations.csv",
    "data/kubernetes/20260806T031453Z/policy-denials.txt",
    "data/kubernetes/20260806T031453Z/kubernetes-version.json",
    "data/kubernetes/20260806T031453Z/nodes.txt",
    "data/kubernetes/20260806T031453Z/environment.txt",
    "experiments/comparison/opentelemetry/collector-config.yaml",
    "experiments/comparison/opentelemetry/run_comparison.py",
    "data/comparison/20260806T032418Z/environment.json",
    "data/comparison/20260806T032418Z/summary.json",
    "data/comparison/20260806T032418Z/trials.csv",
    "data/comparison/20260806T032418Z/SHA256SUMS",
    "figures/generate_figures.py",
    "figures/eacp_architecture.png",
    "figures/eacp_benchmark_results.png",
    "figures/eacp_kubernetes_preservation_results_v1_2.png",
    "figures/generate_vector_figures.py",
    "figures/figure_1_eacp_architecture_v1_2.svg",
    "figures/figure_1_eacp_architecture_v1_2.pdf",
    "figures/figure_2_reproducible_pilot_benchmark_v1_2.svg",
    "figures/figure_2_reproducible_pilot_benchmark_v1_2.pdf",
    "figures/figure_3_kubernetes_preservation_v1_2.svg",
    "figures/figure_3_kubernetes_preservation_v1_2.pdf",
    "paper/EACP_preprint.pdf",
    "RELEASE_NOTES_v1.2.0.md",
    "MANIFEST.sha256",
)

CANDIDATE_SENTINELS = (
    "spec/EACP_PROFILE_v1.3.md",
    "REVIEWER_GUIDE_v1.3.md",
    "experiments/github_actions/results/reference/run-33682116347/reference_summary.json",
)

CANDIDATE_REQUIRED_FILES = (
    ".github/workflows/eacp-cross-plane-v1.3.yml",
    "CLAIMS_AND_EVIDENCE_v1.3.md",
    "EVIDENCE_BRIEF_v1.3.md",
    "EXPERT_REVIEW_REQUEST_v1.3.md",
    "RELEASE_NOTES_v1.3-candidate.md",
    "REVIEWER_GUIDE_v1.3.md",
    "spec/EACP_PROFILE_v1.3.md",
    "spec/schema/eacp-core-evidence-record-v1.3.schema.json",
    "spec/schema/eacp-evidence-collection-v1.3.schema.json",
    "spec/schema/eacp-link-resolution-v1.3.schema.json",
    "spec/examples/valid-record-v1.3.json",
    "spec/tools/eacp_profile.py",
    "spec/tests/test_eacp_profile.py",
    "experiments/correlation_robustness/README.md",
    "experiments/correlation_robustness/LIMITATIONS_AND_NEXT_PROTOCOL.md",
    "experiments/correlation_robustness/correlation_robustness.py",
    "experiments/correlation_robustness/generate_figure.py",
    "experiments/correlation_robustness/test_correlation_robustness.py",
    "experiments/correlation_robustness/results/reference/SHA256SUMS",
    "experiments/correlation_robustness/results/reference/summary_results.json",
    "experiments/index_ablation/README.md",
    "experiments/index_ablation/index_ablation.py",
    "experiments/index_ablation/test_index_ablation.py",
    "experiments/index_ablation/results/reference/SHA256SUMS",
    "experiments/index_ablation/results/reference/method.json",
    "experiments/index_ablation/results/reference/summary_results.json",
    "experiments/github_actions/README.md",
    "experiments/github_actions/EXTERNAL_REPLICATION_PROTOCOL_v1.3.md",
    "experiments/github_actions/capture_completed_run_v1_3.sh",
    "experiments/github_actions/capture_run_outcome_v1_3.py",
    "experiments/github_actions/capture_tag_invocation_v1_3.py",
    "experiments/github_actions/normalize_attestation_bundle_v1_3.py",
    "experiments/github_actions/cross_version_protocol_amendment_v1.3.1.json",
    "experiments/github_actions/cross_version_protocol_plan_v1.3.json",
    "experiments/github_actions/kubernetes_targets_v1.3.json",
    "experiments/github_actions/replication-report.template.json",
    "experiments/github_actions/resolve_kubernetes_target.py",
    "experiments/github_actions/summarize_cross_version_run_set.py",
    "experiments/github_actions/summarize_reference_run.py",
    "experiments/github_actions/tests/test_kubernetes_versions.py",
    "experiments/github_actions/tests/test_cross_version_run_set.py",
    "experiments/github_actions/tests/test_attestation_bundle_filename.py",
    "experiments/github_actions/tests/test_run_outcome.py",
    "experiments/github_actions/tests/test_tag_invocation.py",
    "experiments/github_actions/tests/test_target_resolution.py",
    "experiments/github_actions/verify_kubernetes_versions.py",
    "experiments/github_actions/results/reference/run-33682116347/README.md",
    "experiments/github_actions/results/reference/run-33682116347/REFERENCE_SHA256SUMS",
    "experiments/github_actions/results/reference/run-33682116347/reference_summary.json",
    "experiments/github_actions/results/reference/cross-version-initial-failed-cohort-v1.3/README.md",
    "experiments/github_actions/results/reference/cross-version-initial-failed-cohort-v1.3/REFERENCE_SHA256SUMS",
    "experiments/github_actions/results/reference/cross-version-initial-failed-cohort-v1.3/cross_version_summary.json",
    "experiments/github_actions/results/reference/cross-version-initial-failed-cohort-v1.3/protocol_plan.json",
    "experiments/github_actions/results/reference/cross-version-initial-failed-cohort-v1.3/run_set.json",
    "experiments/github_actions/results/reference/cross-version-confirmatory-cohort-v1.3/README.md",
    "experiments/github_actions/results/reference/cross-version-confirmatory-cohort-v1.3/REFERENCE_SHA256SUMS",
    "experiments/github_actions/results/reference/cross-version-confirmatory-cohort-v1.3/cross_version_summary.json",
    "experiments/github_actions/results/reference/cross-version-confirmatory-cohort-v1.3/protocol_amendment.json",
    "experiments/github_actions/results/reference/cross-version-confirmatory-cohort-v1.3/run_set.json",
    "figures/README.md",
    "figures/generate_v1_3_figures.py",
    "figures/eacp_architecture_v1_3.png",
    "figures/eacp_correlation_robustness_v1_3.png",
    "figures/eacp_live_cross_plane_v1_3.png",
    "paper/EACP_preprint_v1.3_candidate.pdf",
)

CANDIDATE_REQUIRED_DIRECTORIES = (
    "spec/examples",
    "spec/schema",
    "spec/tests",
    "spec/tools",
    "experiments/correlation_robustness/results/reference",
    "experiments/index_ablation/results/reference",
    "experiments/github_actions/results/reference/run-33682116347",
    "experiments/github_actions/results/reference/cross-version-initial-failed-cohort-v1.3",
    "experiments/github_actions/results/reference/cross-version-confirmatory-cohort-v1.3",
)

CORRELATION_RESULT_FILES = {
    "environment.json",
    "figure_correlation_robustness.svg",
    "summary_results.csv",
    "summary_results.json",
    "trial_results.csv",
    "trial_results.json",
}

INDEX_ABLATION_RESULT_FILES = {
    "cold_open_measurements.csv",
    "environment.json",
    "method.json",
    "query_measurements.csv",
    "query_plans.json",
    "summary_results.csv",
    "summary_results.json",
    "trial_results.csv",
    "trial_results.json",
}

CORRELATION_MANIFEST_SHA256 = "5407328c9d9249214710f2fb92fec0c0dccf016e45dc9e67e5adb784f2169796"
INDEX_ABLATION_MANIFEST_SHA256 = "c19b701d1a2865ff8a32204e00d02cdaf6a3cbf5eb793ba56a9b985974e004c6"
GITHUB_ACTIONS_REFERENCE_MANIFEST_SHA256 = (
    "38129b4fce63ed6e1ca4528f8b427f4c61cd8a4fabda19592d81549930bbb2c5"
)
GITHUB_ACTIONS_REFERENCE_SUMMARY_SHA256 = (
    "06b2a0f206630df72b5985286d2c0d93b67e55d763fcfaac281a10b99f383dee"
)
GITHUB_ACTIONS_RUN_ID = 33682116347
GITHUB_ACTIONS_HEAD_SHA = "76b2ed54381ae52cf0f54cd22a20341c3216b77b"
GITHUB_ACTIONS_SUBJECT_DIGEST = (
    "sha256:ee6521f290b2168b6e0935a181d4cff9be1ac3f505666ef0e3c98fae8199917a"
)

EXPECTED_CROSS_VERSION_TARGETS = {
    "schema_version": "eacp.kubernetes-targets/1.3.0",
    "kind": {
        "version": "v0.32.0",
        "linux_amd64_sha256": (
            "50030de23cf40a18505f20426f6a8506bedf13c6e509244bd1fa9463721b0f54"
        ),
    },
    "targets": {
        "v1.34.8": {
            "node_image": (
                "kindest/node:v1.34.8@sha256:"
                "02722c2dedddcfc00febf5d27fbeb9b7b2c14294c82109ff4a85d89ac9ba3256"
            ),
            "kubectl_linux_amd64_sha256": (
                "f6249132865c13abe3c9dd5038f5da65849cb86eee1608c001831504e481aa8c"
            ),
        },
        "v1.35.5": {
            "node_image": (
                "kindest/node:v1.35.5@sha256:"
                "ce977ae6d65918d0b58a5f8b5e940429c2ce42fa3a5619ec2bbc60b949c0ac95"
            ),
            "kubectl_linux_amd64_sha256": (
                "90f75ea6ecc9ea5633262e1c0b83a40560003b30fc94a04cb099404fcef0c224"
            ),
        },
        "v1.36.1": {
            "node_image": (
                "kindest/node:v1.36.1@sha256:"
                "3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
            ),
            "kubectl_linux_amd64_sha256": (
                "629d3f410e09bf49b64ae7079f7f0bda1191efed311f7d37fdbab0ad5b0ec2b7"
            ),
        },
    },
}

EXPECTED_CROSS_VERSION_COHORT = [
    {
        "kubernetes_version": "v1.34.8",
        "evidence_tag": "eacp-v1.3-evidence/k8s-v1.34.8/run-01",
    },
    {
        "kubernetes_version": "v1.35.5",
        "evidence_tag": "eacp-v1.3-evidence/k8s-v1.35.5/run-01",
    },
    {
        "kubernetes_version": "v1.36.1",
        "evidence_tag": "eacp-v1.3-evidence/k8s-v1.36.1/run-01",
    },
    {
        "kubernetes_version": "v1.34.8",
        "evidence_tag": "eacp-v1.3-evidence/k8s-v1.34.8/run-02",
    },
    {
        "kubernetes_version": "v1.35.5",
        "evidence_tag": "eacp-v1.3-evidence/k8s-v1.35.5/run-02",
    },
    {
        "kubernetes_version": "v1.36.1",
        "evidence_tag": "eacp-v1.3-evidence/k8s-v1.36.1/run-02",
    },
    {
        "kubernetes_version": "v1.34.8",
        "evidence_tag": "eacp-v1.3-evidence/k8s-v1.34.8/run-03",
    },
    {
        "kubernetes_version": "v1.35.5",
        "evidence_tag": "eacp-v1.3-evidence/k8s-v1.35.5/run-03",
    },
    {
        "kubernetes_version": "v1.36.1",
        "evidence_tag": "eacp-v1.3-evidence/k8s-v1.36.1/run-03",
    },
]

INITIAL_CROSS_VERSION_PROTOCOL_COMMIT = "15d72da095a0c7640b9318b50b28728e76d68928"
CONFIRMATORY_CROSS_VERSION_PROTOCOL_COMMIT = (
    "4cbf7d2fa0bb44585d258a3f37ce0c0d39ddea43"
)
CROSS_VERSION_AMENDMENT_SHA256 = (
    "ba5bf6fdb21900cdfbcbab66ccd10ab317f38fc688f76112294ed2d8d0998ac8"
)
EXPECTED_INITIAL_FAILED_RUN_IDS = {
    "eacp-v1.3-evidence/k8s-v1.34.8/run-01": 33689275761,
    "eacp-v1.3-evidence/k8s-v1.35.5/run-01": 33689279446,
    "eacp-v1.3-evidence/k8s-v1.36.1/run-01": 33689281853,
    "eacp-v1.3-evidence/k8s-v1.34.8/run-02": 33689284057,
    "eacp-v1.3-evidence/k8s-v1.35.5/run-02": 33689287000,
    "eacp-v1.3-evidence/k8s-v1.36.1/run-02": 33689288013,
    "eacp-v1.3-evidence/k8s-v1.34.8/run-03": 33689294904,
    "eacp-v1.3-evidence/k8s-v1.35.5/run-03": 33689291864,
    "eacp-v1.3-evidence/k8s-v1.36.1/run-03": 33689302997,
}
EXPECTED_CONFIRMATORY_CROSS_VERSION_COHORT = [
    {
        "kubernetes_version": version,
        "evidence_tag": f"eacp-v1.3-evidence/k8s-{version}/run-{run_index:02d}",
    }
    for run_index in (4, 5, 6)
    for version in ("v1.34.8", "v1.35.5", "v1.36.1")
]
EXPECTED_CONFIRMATORY_RUN_IDS = {
    "eacp-v1.3-evidence/k8s-v1.34.8/run-04": 33690426246,
    "eacp-v1.3-evidence/k8s-v1.35.5/run-04": 33690427562,
    "eacp-v1.3-evidence/k8s-v1.36.1/run-04": 33690429641,
    "eacp-v1.3-evidence/k8s-v1.34.8/run-05": 33690432444,
    "eacp-v1.3-evidence/k8s-v1.35.5/run-05": 33690433602,
    "eacp-v1.3-evidence/k8s-v1.36.1/run-05": 33690436849,
    "eacp-v1.3-evidence/k8s-v1.34.8/run-06": 33690438222,
    "eacp-v1.3-evidence/k8s-v1.35.5/run-06": 33690440169,
    "eacp-v1.3-evidence/k8s-v1.36.1/run-06": 33690443082,
}
EXPECTED_CROSS_VERSION_WORKFLOW_TAGS = {
    *(row["evidence_tag"] for row in EXPECTED_CROSS_VERSION_COHORT),
    *(row["evidence_tag"] for row in EXPECTED_CONFIRMATORY_CROSS_VERSION_COHORT),
}

EXPECTED_CANDIDATE_FIGURES = {
    "figures/eacp_architecture_v1_3.png": (2400, 1500),
    "figures/eacp_correlation_robustness_v1_3.png": (2400, 1520),
    "figures/eacp_live_cross_plane_v1_3.png": (2400, 1520),
}

APPROVED_KUBERNETES_RESULT_FILES = {
    "analysis/public_filtered_audit.jsonl",
    "analysis/normalized_evidence.csv",
    "analysis/summary.json",
    "operations.csv",
    "policy-denials.txt",
    "kubernetes-version.json",
    "nodes.txt",
    "environment.txt",
}

KUBERNETES_INPUT_SHA256 = "6aa39ee1cf8d3cbf58cb683ed6c7977ce851ab442c7057b7a85e974cb5400e01"
KUBERNETES_PROJECTION_CSV_SHA256 = "ff03698e83a764651aec912fc806a50464374567ae862936fe32251523d796b5"
CANONICAL_PROJECTION_SHA256 = "196d4a1bf8d057d9fe9e6f18062b7c5ac5228642df3098b28c84fb48d7a67da6"
OTEL_IMAGE_DIGEST = "sha256:c5918f78992ee73b0d6f0e599423ac5ec52dd5d9726733114d6eca53d5a32ed5"
ARTIFACT_VERSION = "1.2.0"
ARTIFACT_DOI = "10.5281/zenodo.21818550"
CONCEPT_DOI = "10.5281/zenodo.21817376"
REPOSITORY_URL = "https://github.com/obedebessa/eacp-operational-provenance"

TEXT_SUFFIXES = {
    "",
    ".bib",
    ".cff",
    ".csv",
    ".json",
    ".md",
    ".py",
    ".sh",
    ".toml",
    ".txt",
    ".yaml",
    ".yml",
}

PLACEHOLDER_RE = re.compile(r"\bTODO_[A-Z0-9_]+\b")
ABSOLUTE_PATH_RES = (
    re.compile("/" + r"Users/[^/\s]+/"),
    re.compile("/" + r"home/[^/\s]+/"),
    re.compile(r"[A-Za-z]:\\Users\\[^\\\s]+\\"),
)
PRIVATE_MATERIAL_RES = (
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"(?im)^\s*(?:authorization|bearer[_-]?token|client[_-]?secret)\s*[:=]\s*\S+"),
)

SKIP_PARTS = {".git", "__pycache__", ".venv"}


def iter_text_files() -> list[Path]:
    files: list[Path] = []
    for path in ROOT.rglob("*"):
        if not path.is_file() or any(part in SKIP_PARTS for part in path.parts):
            continue
        if path.suffix.lower() in TEXT_SUFFIXES:
            files.append(path)
    return files


def relative(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def sha256(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def load_json_object(path: Path, label: str, errors: list[str]) -> dict[str, object] | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        errors.append(f"cannot parse {label}: {exc}")
        return None
    if not isinstance(value, dict):
        errors.append(f"{label} must contain a JSON object")
        return None
    return value


def validate_checksum_manifest(
    *,
    result_root: Path,
    manifest_name: str,
    expected_files: set[str],
    expected_manifest_sha256: str,
    label: str,
    errors: list[str],
) -> None:
    """Validate one frozen, flat checksum inventory without shell utilities."""

    manifest = result_root / manifest_name
    if not manifest.is_file():
        errors.append(f"missing {label} checksum manifest: {relative(manifest)}")
        return
    if sha256(manifest) != expected_manifest_sha256:
        errors.append(f"{label} checksum manifest differs from the frozen candidate")

    listed: set[str] = set()
    try:
        lines = manifest.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        errors.append(f"cannot read {label} checksum manifest: {exc}")
        return

    resolved_root = result_root.resolve()
    for line_number, raw in enumerate(lines, start=1):
        if not raw.strip():
            continue
        parts = raw.split(maxsplit=1)
        if len(parts) != 2 or not re.fullmatch(r"[0-9a-f]{64}", parts[0]):
            errors.append(f"malformed {label} checksum line {line_number}")
            continue
        expected, raw_name = parts
        name = raw_name.strip()
        if name.startswith("*"):
            name = name[1:]
        candidate = Path(name)
        if candidate.is_absolute() or ".." in candidate.parts:
            errors.append(f"unsafe path in {label} checksum manifest: {name!r}")
            continue
        normalized = candidate.as_posix()
        if normalized.startswith("./"):
            normalized = normalized[2:]
        if normalized in listed:
            errors.append(f"duplicate path in {label} checksum manifest: {normalized}")
            continue
        listed.add(normalized)
        target = (result_root / candidate).resolve()
        try:
            target.relative_to(resolved_root)
        except ValueError:
            errors.append(f"path escapes {label} result root: {name!r}")
            continue
        if not target.is_file():
            errors.append(f"missing {label} checksummed file: {normalized}")
        elif sha256(target) != expected:
            errors.append(f"{label} checksum mismatch: {normalized}")

    if listed != expected_files:
        errors.append(
            f"{label} checksum inventory differs "
            f"(missing={sorted(expected_files - listed)}, "
            f"extra={sorted(listed - expected_files)})"
        )
    actual = {
        path.relative_to(result_root).as_posix()
        for path in result_root.rglob("*")
        if path.is_file() and path != manifest
    }
    if actual != expected_files:
        errors.append(
            f"{label} frozen directory inventory differs "
            f"(missing={sorted(expected_files - actual)}, "
            f"extra={sorted(actual - expected_files)})"
        )


def csv_data_row_count(path: Path, label: str, errors: list[str]) -> int | None:
    try:
        with path.open("r", encoding="utf-8", newline="") as stream:
            reader = csv.reader(stream)
            next(reader)
            return sum(1 for _ in reader)
    except (OSError, UnicodeDecodeError, csv.Error, StopIteration) as exc:
        errors.append(f"cannot count {label} rows: {exc}")
        return None


def run_offline_check(command: list[str], label: str, errors: list[str]) -> None:
    try:
        result = subprocess.run(
            command,
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
            timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        errors.append(f"could not execute {label}: {exc}")
        return
    if result.returncode == 0:
        return
    detail_lines = (result.stderr + "\n" + result.stdout).strip().splitlines()
    detail = " | ".join(detail_lines[-4:]) if detail_lines else "no diagnostic output"
    errors.append(f"{label} failed: {detail}")


def validate_profile_candidate(errors: list[str]) -> None:
    schema_paths = (
        ROOT / "spec/schema/eacp-core-evidence-record-v1.3.schema.json",
        ROOT / "spec/schema/eacp-evidence-collection-v1.3.schema.json",
        ROOT / "spec/schema/eacp-link-resolution-v1.3.schema.json",
    )
    for path in schema_paths:
        if not path.is_file():
            continue
        schema = load_json_object(path, relative(path), errors)
        if schema is not None:
            if schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
                errors.append(f"{relative(path)} is not declared as JSON Schema Draft 2020-12")

    core_path = schema_paths[0]
    if core_path.is_file():
        core = load_json_object(core_path, relative(core_path), errors)
        if core is not None:
            required = core.get("required")
            required_members = {
                "profile",
                "source_type",
                "source_id",
                "source_ts",
                "observed_ts",
                "actors",
                "service",
                "intent",
                "policy",
                "action",
                "outcome",
                "source_pointer",
                "links",
            }
            if not isinstance(required, list) or not all(
                member in required for member in required_members
            ):
                errors.append("Profile 1.3 core schema omits a normative tuple member")
            properties = core.get("properties")
            if not isinstance(properties, dict) or properties.get("profile") != {
                "const": "eacp.profile/1.3"
            }:
                errors.append("Profile 1.3 core schema does not fix the profile identifier")

    example = ROOT / "spec/examples/valid-record-v1.3.json"
    tool = ROOT / "spec/tools/eacp_profile.py"
    if example.is_file() and tool.is_file():
        try:
            result = subprocess.run(
                [sys.executable, str(tool), "validate", str(example)],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
                timeout=120,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            errors.append(f"could not validate the Profile 1.3 example: {exc}")
        else:
            if result.returncode != 0:
                detail = (result.stderr or result.stdout).strip().splitlines()
                errors.append(
                    "Profile 1.3 example failed the reference validator: "
                    + (detail[-1] if detail else "no diagnostic output")
                )
            else:
                try:
                    report = json.loads(result.stdout)
                except json.JSONDecodeError as exc:
                    errors.append(f"Profile 1.3 validator emitted invalid JSON: {exc}")
                else:
                    if report.get("valid") is not True or report.get("record_count") != 1:
                        errors.append("Profile 1.3 example validation did not report one valid record")

    tests = ROOT / "spec/tests/test_eacp_profile.py"
    if tests.is_file():
        test_count = len(
            re.findall(r"(?m)^\s+def test_[A-Za-z0-9_]+\(", tests.read_text(encoding="utf-8"))
        )
        if test_count != 19:
            errors.append(f"Profile 1.3 reference test inventory is {test_count}, expected 19")


def validate_correlation_candidate(errors: list[str]) -> None:
    result_root = ROOT / "experiments/correlation_robustness/results/reference"
    validate_checksum_manifest(
        result_root=result_root,
        manifest_name="SHA256SUMS",
        expected_files=CORRELATION_RESULT_FILES,
        expected_manifest_sha256=CORRELATION_MANIFEST_SHA256,
        label="correlation robustness",
        errors=errors,
    )
    summary_path = result_root / "summary_results.json"
    if not summary_path.is_file():
        return
    summary = load_json_object(summary_path, relative(summary_path), errors)
    if summary is None:
        return
    scenarios = summary.get("scenario_definitions")
    rows = summary.get("summaries")
    configuration = summary.get("configuration")
    if summary.get("schema_version") != "1.0":
        errors.append("correlation robustness summary schema version mismatch")
    if summary.get("data_classification") != "fully synthetic; contains no user or production data":
        errors.append("correlation robustness data classification mismatch")
    if not isinstance(scenarios, list) or len(scenarios) != 25:
        errors.append("correlation robustness summary must define 25 scenarios")
    if not isinstance(configuration, dict) or configuration.get("chains_per_seed") != 600:
        errors.append("correlation robustness summary must declare 600 chains per seed")
    seeds = configuration.get("seeds") if isinstance(configuration, dict) else None
    if not isinstance(seeds, list) or len(seeds) != 30:
        errors.append("correlation robustness summary must declare 30 seeds")
    if not isinstance(rows, list) or len(rows) != 75:
        errors.append("correlation robustness summary must contain 75 scenario-policy rows")
    else:
        identities = {
            (row.get("scenario"), row.get("algorithm"))
            for row in rows
            if isinstance(row, dict)
            and isinstance(row.get("scenario"), str)
            and isinstance(row.get("algorithm"), str)
        }
        algorithms = {identity[1] for identity in identities}
        if len(identities) != 75 or algorithms != {
            "strict_service_plus_correlation",
            "correlation_id_only_ablation",
            "naive_temporal_window",
        }:
            errors.append("correlation robustness scenario-policy matrix is incomplete")
        if any(not isinstance(row, dict) or row.get("trials") != 30 for row in rows):
            errors.append("correlation robustness summary rows must each aggregate 30 trials")

        selected = {
            row.get("scenario"): row
            for row in rows
            if isinstance(row, dict)
            and isinstance(row.get("scenario"), str)
            and row.get("algorithm") == "strict_service_plus_correlation"
        }
        expected_metrics = {
            "control": (1.0, 0.0, 0.0),
            "missing_random_1pct": (0.9416666666666667, 0.01, 0.0),
            "missing_random_20pct": (0.26166666666666666, 0.2, 0.0),
            "compound_adversarial": (0.47333333333333333, 0.19013888888888889, 0.0),
        }
        for scenario, expected in expected_metrics.items():
            row = selected.get(scenario)
            observed = (
                row.get("exact_chain_accuracy_median") if row else None,
                row.get("abstention_rate_median") if row else None,
                row.get("false_join_rate_median") if row else None,
            )
            if any(
                not isinstance(actual, (int, float))
                or not math.isclose(float(actual), target, rel_tol=0.0, abs_tol=1e-12)
                for actual, target in zip(observed, expected)
            ):
                errors.append(f"correlation robustness frozen metrics differ: {scenario}")

    trial_count = csv_data_row_count(result_root / "trial_results.csv", "correlation trial", errors)
    if trial_count is not None and trial_count != 2250:
        errors.append(f"correlation robustness trial row count is {trial_count}, expected 2250")


def validate_index_ablation_candidate(errors: list[str]) -> None:
    result_root = ROOT / "experiments/index_ablation/results/reference"
    validate_checksum_manifest(
        result_root=result_root,
        manifest_name="SHA256SUMS",
        expected_files=INDEX_ABLATION_RESULT_FILES,
        expected_manifest_sha256=INDEX_ABLATION_MANIFEST_SHA256,
        label="index ablation",
        errors=errors,
    )
    verifier = ROOT / "experiments/index_ablation/index_ablation.py"
    if verifier.is_file() and result_root.is_dir():
        run_offline_check(
            [sys.executable, str(verifier), "--verify", str(result_root)],
            "index-ablation source and result verification",
            errors,
        )

    summary_path = result_root / "summary_results.json"
    if not summary_path.is_file():
        return
    summary = load_json_object(summary_path, relative(summary_path), errors)
    if summary is None:
        return
    rows = summary.get("rows")
    if summary.get("result_schema_version") != "1.0":
        errors.append("index ablation summary schema version mismatch")
    if summary.get("analysis_unit") != "one event-count/seed trial":
        errors.append("index ablation analysis unit mismatch")
    if summary.get("inferential_statistics") is not False:
        errors.append("index ablation must not claim inferential statistics")
    if not isinstance(rows, list) or len(rows) != 12:
        errors.append("index ablation summary must contain 12 size-variant rows")
    else:
        identities = {
            (row.get("event_count"), row.get("variant"))
            for row in rows
            if isinstance(row, dict)
            and isinstance(row.get("event_count"), int)
            and not isinstance(row.get("event_count"), bool)
            and isinstance(row.get("variant"), str)
        }
        expected_identities = {
            (size, variant)
            for size in (10000, 50000, 100000)
            for variant in (
                "full_indexes",
                "no_service_index",
                "no_correlation_index",
                "no_lookup_indexes",
            )
        }
        if identities != expected_identities:
            errors.append("index ablation size-treatment matrix is incomplete")
        if any(
            not isinstance(row, dict)
            or row.get("trials") != 10
            or row.get("all_outputs_equivalent") != 1
            for row in rows
        ):
            errors.append("index ablation rows must report 10 equivalent-output trials")

        keyed = {
            (row.get("event_count"), row.get("variant")): row
            for row in rows
            if isinstance(row, dict)
            and isinstance(row.get("event_count"), int)
            and not isinstance(row.get("event_count"), bool)
            and isinstance(row.get("variant"), str)
        }
        service = keyed.get((100000, "no_service_index"), {})
        correlation = keyed.get((100000, "no_correlation_index"), {})
        neither = keyed.get((100000, "no_lookup_indexes"), {})
        checks = (
            (service.get("warm_service_p95_ratio_to_full_median"), 5.651081309441061),
            (correlation.get("warm_correlation_p95_ratio_to_full_median"), 73.91221766021741),
            (neither.get("database_bytes_reduction_vs_full_percent_median"), 22.77629365786089),
            (neither.get("ingest_time_reduction_vs_full_percent_median"), 17.89957879997673),
        )
        if any(
            not isinstance(actual, (int, float))
            or not math.isclose(float(actual), expected, rel_tol=0.0, abs_tol=1e-12)
            for actual, expected in checks
        ):
            errors.append("index ablation frozen 100,000-event metrics differ")

    expected_row_counts = {
        "trial_results.csv": 120,
        "query_measurements.csv": 18000,
        "cold_open_measurements.csv": 1200,
    }
    for name, expected in expected_row_counts.items():
        count = csv_data_row_count(result_root / name, f"index ablation {name}", errors)
        if count is not None and count != expected:
            errors.append(f"index ablation {name} row count is {count}, expected {expected}")


def validate_github_actions_candidate(errors: list[str]) -> None:
    result_root = (
        ROOT
        / "experiments/github_actions/results/reference"
        / f"run-{GITHUB_ACTIONS_RUN_ID}"
    )
    manifest = result_root / "REFERENCE_SHA256SUMS"
    summary_path = result_root / "reference_summary.json"
    if manifest.is_file() and sha256(manifest) != GITHUB_ACTIONS_REFERENCE_MANIFEST_SHA256:
        errors.append("GitHub Actions reference manifest differs from the frozen candidate")
    if summary_path.is_file() and sha256(summary_path) != GITHUB_ACTIONS_REFERENCE_SUMMARY_SHA256:
        errors.append("GitHub Actions reference summary differs from the frozen candidate")

    summarizer = ROOT / "experiments/github_actions/summarize_reference_run.py"
    if summarizer.is_file() and result_root.is_dir():
        run_offline_check(
            [sys.executable, str(summarizer), "--verify"],
            "GitHub Actions frozen-run checksum and invariant verification",
            errors,
        )

    if not summary_path.is_file():
        return
    summary = load_json_object(summary_path, relative(summary_path), errors)
    if summary is None:
        return
    run = summary.get("run")
    subject = summary.get("subject")
    aggregate = summary.get("aggregate")
    attempts = summary.get("attempt_results")
    if summary.get("schema_version") != "eacp.github-actions.reference-run-summary/1.3.0":
        errors.append("GitHub Actions reference summary schema version mismatch")
    if not isinstance(run, dict) or (
        run.get("run_id"), run.get("head_sha"), run.get("attempts"), run.get("all_conclusions")
    ) != (GITHUB_ACTIONS_RUN_ID, GITHUB_ACTIONS_HEAD_SHA, 3, "success"):
        errors.append("GitHub Actions reference run identity or completion state mismatch")
    if not isinstance(subject, dict) or subject.get("digest") != GITHUB_ACTIONS_SUBJECT_DIGEST:
        errors.append("GitHub Actions reference subject digest mismatch")
    expected_aggregate = {
        "successful_exact_link_attempts": 3,
        "successful_negative_controls": 3,
        "successful_target_bound_rbac_controls": 3,
        "archive_attestation_statements_matching_subject": 3,
        "distinct_attempt_specific_correlation_ids": 3,
    }
    if not isinstance(aggregate, dict) or any(
        aggregate.get(key) != value for key, value in expected_aggregate.items()
    ):
        errors.append("GitHub Actions three-attempt aggregate invariants mismatch")
    if not isinstance(attempts, list) or len(attempts) != 3:
        errors.append("GitHub Actions reference summary must contain three attempts")
    else:
        for expected_attempt, attempt in enumerate(attempts, start=1):
            if not isinstance(attempt, dict) or (
                attempt.get("attempt") != expected_attempt
                or attempt.get("github_completed_evidence_records") != 3
                or attempt.get("kubernetes_source_native_positive_records") != 8
                or attempt.get("kubernetes_projected_records_with_exact_id") != 9
                or attempt.get("negative_control_audit_records") != 3
                or attempt.get("negative_control_unjoined") is not True
                or attempt.get("target_bound_http_403_records") != 1
                or attempt.get("rbac_correlation_evidence_method") != "explicit"
                or attempt.get("rbac_source_native_correlation_records") != 0
                or attempt.get("pod_spec_and_runtime_subject_digest_exact") is not True
                or attempt.get("attestation_statement_subject_matches_archive") is not True
                or attempt.get("verified_manifest_entries") != 37
            ):
                errors.append(f"GitHub Actions attempt {expected_attempt} invariants mismatch")


def expected_cross_version_run_set_rows(
    cohort: list[dict[str, str]], run_ids: dict[str, int] | None = None
) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for member in cohort:
        tag = member["evidence_tag"]
        run_id = run_ids[tag] if run_ids is not None else 0
        rows.append(
            {
                "kubernetes_version": member["kubernetes_version"],
                "evidence_tag": tag,
                "run_id": run_id,
                "run_url": f"{REPOSITORY_URL}/actions/runs/{run_id}",
            }
        )
    return rows


def validate_cross_version_run_set_binding(
    *,
    cohort_root: Path,
    expected_members: list[dict[str, str]],
    expected_indices: list[int],
    label: str,
    errors: list[str],
    expected_protocol_commit: str,
    expected_run_ids: dict[str, int],
) -> None:
    """Validate a frozen cohort's exact generation and prospective commit binding."""

    if not cohort_root.is_dir():
        return
    run_set_path = cohort_root / "run_set.json"
    if not run_set_path.is_file():
        errors.append(f"{label} is present without run_set.json")
        return
    run_set = load_json_object(run_set_path, relative(run_set_path), errors)
    if run_set is None:
        return
    expected_keys = {"schema_version", "protocol_commit", "tag_run_indices", "runs"}
    if set(run_set) != expected_keys:
        errors.append(f"{label} run set fields differ from the exact schema")
    if run_set.get("schema_version") != "eacp.cross-version-run-set/1.3.0":
        errors.append(f"{label} run set schema version mismatch")
    if run_set.get("tag_run_indices") != expected_indices:
        errors.append(f"{label} run set evidence-tag generation mismatch")

    protocol_commit = run_set.get("protocol_commit")
    if (
        not isinstance(protocol_commit, str)
        or re.fullmatch(r"[0-9a-f]{40}", protocol_commit) is None
    ):
        errors.append(f"{label} lacks one lowercase 40-hex protocol commit")
        protocol_commit = None
    elif protocol_commit != expected_protocol_commit:
        errors.append(f"{label} does not bind its exact frozen protocol commit")

    rows = run_set.get("runs")
    if not isinstance(rows, list) or len(rows) != 9 or any(
        not isinstance(row, dict) for row in rows
    ):
        errors.append(f"{label} run set must contain nine object rows")
        return
    expected_row_keys = {"kubernetes_version", "evidence_tag", "run_id", "run_url"}
    if any(set(row) != expected_row_keys for row in rows):
        errors.append(f"{label} run rows differ from the exact schema")

    expected_pairs = {
        (member["kubernetes_version"], member["evidence_tag"])
        for member in expected_members
    }
    observed_pairs = {
        (row.get("kubernetes_version"), row.get("evidence_tag")) for row in rows
    }
    if observed_pairs != expected_pairs or len(observed_pairs) != 9:
        errors.append(f"{label} members differ from the exact balanced 3-by-3 generation")

    observed_ids: list[int] = []
    for row in rows:
        run_id = row.get("run_id")
        tag = row.get("evidence_tag")
        if isinstance(run_id, bool) or not isinstance(run_id, int) or run_id <= 0:
            errors.append(f"{label} contains an invalid workflow run ID: {run_id!r}")
            continue
        observed_ids.append(run_id)
        if row.get("run_url") != f"{REPOSITORY_URL}/actions/runs/{run_id}":
            errors.append(f"{label} contains a non-canonical run URL for {run_id}")
        if expected_run_ids.get(tag) != run_id:
            errors.append(f"{label} changes the preserved run ID for {tag!r}")
    if len(observed_ids) == 9 and len(set(observed_ids)) != 9:
        errors.append(f"{label} workflow run IDs are not distinct")

    expected_rows = expected_cross_version_run_set_rows(expected_members, expected_run_ids)
    if rows != expected_rows:
        errors.append(f"{label} does not preserve the exact run order and identities")

    if (
        protocol_commit == CONFIRMATORY_CROSS_VERSION_PROTOCOL_COMMIT
        and (ROOT / ".git").is_dir()
    ):
        amendment_path = "experiments/github_actions/cross_version_protocol_amendment_v1.3.1.json"
        try:
            amendment_at_commit = subprocess.run(
                ["git", "show", f"{protocol_commit}:{amendment_path}"],
                cwd=ROOT,
                capture_output=True,
                check=False,
                timeout=30,
            )
            parent_at_commit = subprocess.run(
                ["git", "rev-parse", f"{protocol_commit}^"],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
                timeout=30,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            errors.append(f"could not verify {label} amendment commit binding: {exc}")
        else:
            if (
                amendment_at_commit.returncode != 0
                or hashlib.sha256(amendment_at_commit.stdout).hexdigest()
                != CROSS_VERSION_AMENDMENT_SHA256
            ):
                errors.append(f"{label} protocol commit does not contain the frozen amendment")
            if (
                parent_at_commit.returncode != 0
                or parent_at_commit.stdout.strip() != INITIAL_CROSS_VERSION_PROTOCOL_COMMIT
            ):
                errors.append(
                    f"{label} protocol commit is not the single corrective child of the initial protocol"
                )


def validate_cross_version_summary_contract(
    *,
    cohort_root: Path,
    expected_members: list[dict[str, str]],
    expected_indices: list[int],
    expected_protocol_commit: str,
    expected_run_ids: dict[str, int],
    expected_successes: int,
    label: str,
    errors: list[str],
) -> None:
    """Validate headline results and epistemic limits independently of the summarizer."""

    summary_path = cohort_root / "cross_version_summary.json"
    if not summary_path.is_file():
        return
    summary = load_json_object(summary_path, relative(summary_path), errors)
    if summary is None:
        return

    expected_summary_keys = {
        "schema_version",
        "source_classification",
        "overall_status",
        "protocol_commit",
        "tag_run_indices",
        "kind_version",
        "target_versions",
        "run_results",
        "per_version",
        "aggregate",
        "attestation_verification_boundary",
        "claim_boundary",
    }
    if set(summary) != expected_summary_keys:
        errors.append(f"{label} summary fields differ from the hardened schema")

    expected_failures = 9 - expected_successes
    expected_status = "complete_success" if expected_successes == 9 else "failed"
    expected_source = (
        "controlled_public_github_actions_and_kubernetes_api_evidence"
        if expected_successes == 9
        else "preserved_public_github_actions_outcomes_without_successful_kubernetes_evidence"
    )
    expected_scalars: dict[str, object] = {
        "schema_version": "eacp.cross-version-summary/1.3.0",
        "source_classification": expected_source,
        "overall_status": expected_status,
        "protocol_commit": expected_protocol_commit,
        "tag_run_indices": expected_indices,
        "kind_version": "v0.32.0",
        "target_versions": ["v1.34.8", "v1.35.5", "v1.36.1"],
    }
    for field, expected in expected_scalars.items():
        observed = summary.get(field)
        if observed != expected or type(observed) is not type(expected):
            errors.append(
                f"{label} summary {field}={observed!r}; expected {expected!r}"
            )

    expected_aggregate: dict[str, object] = {
        "preserved_first_attempt_outcomes": 9,
        "successful_runs_satisfying_all_predeclared_criteria": expected_successes,
        "non_successful_first_attempt_runs": expected_failures,
        "distinct_successful_correlation_ids": expected_successes,
        "first_attempt_outcomes_per_version": 3,
        "exact_client_server_kubelet_version_checks": expected_successes,
        "successful_positive_controls": expected_successes,
        "successful_negative_controls": expected_successes,
        "successful_adapter_explicit_403_controls": expected_successes,
        "successful_separate_oci_digest_checks": expected_successes,
        "sole_exact_tag_invocations_observed_at_capture": 9,
        "failure_logs_with_exact_version_validation_marker": expected_failures,
        "failure_logs_with_premature_artifact_assertion_marker": expected_failures,
        "attested_in_run_tar_parity_checks": expected_successes,
        "capture_time_default_trust_attestation_verifications": expected_successes,
        "capture_time_captured_root_attestation_verifications": expected_successes,
        "completed_finalizations_checksum_and_identity_validated": expected_successes,
        "completed_finalizations_builder_attested": 0,
        "external_reproductions": 0,
        "independent_organizations": 0,
        "identifier_discovery_evaluated": False,
    }
    aggregate = summary.get("aggregate")
    if not isinstance(aggregate, dict) or set(aggregate) != set(expected_aggregate):
        errors.append(f"{label} aggregate fields differ from the hardened schema")
    elif any(
        aggregate.get(field) != expected
        or type(aggregate.get(field)) is not type(expected)
        for field, expected in expected_aggregate.items()
    ):
        errors.append(f"{label} aggregate result or boundary invariant mismatch")

    members_by_version = {
        version: [
            member
            for member in expected_members
            if member["kubernetes_version"] == version
        ]
        for version in ("v1.34.8", "v1.35.5", "v1.36.1")
    }
    expected_per_version = {
        version: {
            "first_attempt_outcomes": 3,
            "successful_runs_satisfying_all_predeclared_criteria": (
                3 if expected_successes == 9 else 0
            ),
            "non_successful_runs": 0 if expected_successes == 9 else 3,
            "predeclared_criteria_satisfied": 3 if expected_successes == 9 else 0,
            "run_ids": sorted(
                expected_run_ids[member["evidence_tag"]]
                for member in members_by_version[version]
            ),
            "run_indices": expected_indices,
            "evidence_tags": sorted(
                member["evidence_tag"] for member in members_by_version[version]
            ),
        }
        for version in members_by_version
    }
    if summary.get("per_version") != expected_per_version:
        errors.append(f"{label} per-version results differ from the exact 3-by-3 cohort")

    run_results = summary.get("run_results")
    if not isinstance(run_results, list) or len(run_results) != 9 or any(
        not isinstance(row, dict) for row in run_results
    ):
        errors.append(f"{label} summary must contain exactly nine run-result objects")
    else:
        observed_ids = {row.get("run_id") for row in run_results}
        if observed_ids != set(expected_run_ids.values()):
            errors.append(f"{label} summary run IDs differ from the frozen cohort")
        expected_identity_by_id = {
            expected_run_ids[member["evidence_tag"]]: {
                "evidence_tag": member["evidence_tag"],
                "kubernetes_version": member["kubernetes_version"],
                "run_index": int(member["evidence_tag"].rsplit("-", 1)[1]),
            }
            for member in expected_members
        }
        for row in run_results:
            run_id = row.get("run_id")
            if expected_identity_by_id.get(run_id) is None or any(
                row.get(field) != expected
                for field, expected in expected_identity_by_id.get(run_id, {}).items()
            ):
                errors.append(f"{label} run {run_id!r} identity mismatch")
            expected_success = expected_successes == 9
            expected_conclusion = "success" if expected_success else "failure"
            expected_criteria = "satisfied" if expected_success else "not_satisfied"
            required_values: dict[str, object] = {
                "head_sha": expected_protocol_commit,
                "status": "completed",
                "conclusion": expected_conclusion,
                "criteria_status": expected_criteria,
                "all_predeclared_criteria_validated": expected_success,
                "sole_exact_tag_invocation_at_capture": True,
                "in_run_tar_builder_attestation_verified": expected_success,
                "completed_finalization_checksum_and_identity_validated": expected_success,
                "completed_finalization_builder_attested": False,
            }
            if any(
                row.get(field) != expected
                or type(row.get(field)) is not type(expected)
                for field, expected in required_values.items()
            ):
                errors.append(f"{label} run {run_id!r} result-boundary mismatch")
            if expected_success:
                successful_values: dict[str, object] = {
                    "in_run_tar_builder_attestation_scope": True,
                    "attested_tar_matches_sibling_results_tree": True,
                    "capture_time_default_trust_verification_records": 1,
                    "capture_time_captured_root_verification_records": 1,
                    "negative_control_unjoined": True,
                    "rbac_source_native_correlation_records": 0,
                    "target_bound_http_403_records": 1,
                    "separate_oci_digest_check": True,
                }
                if any(
                    row.get(field) != expected
                    or type(row.get(field)) is not type(expected)
                    for field, expected in successful_values.items()
                ):
                    errors.append(f"{label} run {run_id!r} hardened evidence mismatch")
            else:
                markers = row.get("recognized_failure_log_markers")
                if row.get("failure_evidence_classification") != (
                    "frozen_github_run_job_step_and_minimized_log_observation"
                ) or not isinstance(markers, list) or any(
                    not isinstance(marker, str) for marker in markers
                ) or set(markers) != {
                    "exact_client_server_kubelet_profile_validated",
                    "premature_completed_artifact_row_assertion",
                }:
                    errors.append(f"{label} run {run_id!r} failure evidence mismatch")

    boundary = summary.get("attestation_verification_boundary")
    expected_boundary_keys = {
        "capture_time",
        "repository_verify_mode",
        "trust_bootstrap",
        "post_run_finalization",
        "semantic_limit",
    }
    if not isinstance(boundary, dict) or set(boundary) != expected_boundary_keys:
        errors.append(f"{label} attestation boundary fields differ from the hardened schema")
    else:
        required_boundary_text = {
            "capture_time": (
                "verified twice with gh attestation verify",
                "default trust configuration",
                "captured trusted root",
                "exact repository, workflow, signer digest, source digest, source ref, predicate, and hosted-runner constraints",
            ),
            "repository_verify_mode": (
                "re-performs cryptographic verification",
                "Rekor timestamp",
            ),
            "trust_bootstrap": (
                "captured root is not self-authenticating",
                "external trust bootstrap",
            ),
            "post_run_finalization": (
                "checksum-bound and identity-validated",
                "not part of the GitHub-builder-attested in-run TAR",
            ),
            "semantic_limit": (
                "does not establish the semantic truth",
            ),
        }
        for field, phrases in required_boundary_text.items():
            value = boundary.get(field)
            if not isinstance(value, str) or any(phrase not in value for phrase in phrases):
                errors.append(f"{label} weakens attestation boundary {field}")

    claim_boundary = summary.get("claim_boundary")
    required_claim_boundary = (
        "procedural repeatability only",
        "no confidence interval, failure-rate inference, or production reliability claim",
        "capture-time public API observation",
        "not a signed API response",
        "GitHub attestation authenticates the in-run TAR only",
        "not builder-attested",
        "workflow generates the joining identifier",
        "not identifier discovery",
        "cross-provider or cross-organization replication",
        "field deployment",
        "external reproduction",
    )
    if not isinstance(claim_boundary, str) or any(
        phrase not in claim_boundary for phrase in required_claim_boundary
    ):
        errors.append(f"{label} weakens the cross-version claim boundary")


def validate_cross_version_amendment(errors: list[str]) -> None:
    """Validate the frozen prospective correction, failures, and confirmatory design."""

    path = (
        ROOT
        / "experiments/github_actions/cross_version_protocol_amendment_v1.3.1.json"
    )
    if not path.is_file():
        return
    if sha256(path) != CROSS_VERSION_AMENDMENT_SHA256:
        errors.append("cross-version protocol amendment differs from the frozen candidate")
    amendment = load_json_object(path, relative(path), errors)
    if amendment is None:
        return

    expected_keys = {
        "schema_version",
        "status",
        "repository",
        "workflow_path",
        "initial_protocol",
        "failure_diagnosis",
        "correction_scope",
        "amendment_commit_binding",
        "runner_class",
        "kind_version",
        "target_manifest",
        "target_manifest_sha256",
        "design",
        "execution_order",
        "execution_order_interpretation",
        "planned_runs",
        "first_attempts_per_version",
        "inferential_statistics",
        "subject",
        "cohort",
        "held_constant",
        "varied",
        "acceptance_criteria",
        "failure_policy",
        "failure_capture",
        "analysis_policy",
        "claim_boundary",
        "external_reproductions",
        "independent_organizations",
        "identifier_discovery_evaluated",
    }
    if set(amendment) != expected_keys:
        errors.append("cross-version amendment fields differ from the exact schema")

    expected_scalars = {
        "schema_version": "eacp.cross-version-protocol-amendment/1.3.1",
        "status": "prospective_before_confirmatory_execution",
        "repository": "obedebessa/eacp-operational-provenance",
        "workflow_path": ".github/workflows/eacp-cross-plane-v1.3.yml",
        "runner_class": "ubuntu-24.04 GitHub-hosted",
        "kind_version": "v0.32.0",
        "target_manifest": "experiments/github_actions/kubernetes_targets_v1.3.json",
        "target_manifest_sha256": (
            "4f67f91090b4540cec4031b4db793f1cbed2a526688a37fe91b0c95e485bff7e"
        ),
        "design": "balanced 3-by-3 confirmatory controlled procedural-repetition cohort",
        "execution_order": (
            "round-robin by replicate: v1.34.8, v1.35.5, v1.36.1; "
            "repeat for run-05 and run-06"
        ),
        "execution_order_interpretation": (
            "Evidence-tag pushes are issued in this order; GitHub queue and start order "
            "are observed rather than controlled."
        ),
        "planned_runs": 9,
        "first_attempts_per_version": 3,
        "inferential_statistics": False,
        "external_reproductions": 0,
        "independent_organizations": 0,
        "identifier_discovery_evaluated": False,
    }
    for key, expected in expected_scalars.items():
        observed = amendment.get(key)
        if observed != expected or type(observed) is not type(expected):
            errors.append(
                f"cross-version amendment {key}={observed!r}; expected {expected!r}"
            )

    target_path = ROOT / "experiments/github_actions/kubernetes_targets_v1.3.json"
    if target_path.is_file() and amendment.get("target_manifest_sha256") != sha256(target_path):
        errors.append("cross-version amendment does not bind the exact unchanged target manifest")
    if amendment.get("subject") != {
        "uri": "registry.k8s.io/pause",
        "digest": GITHUB_ACTIONS_SUBJECT_DIGEST,
    }:
        errors.append("cross-version amendment changes the OCI subject")
    if amendment.get("cohort") != EXPECTED_CONFIRMATORY_CROSS_VERSION_COHORT:
        errors.append("cross-version amendment confirmatory cohort or tags differ")

    expected_initial_runs = [
        {
            **member,
            "run_id": EXPECTED_INITIAL_FAILED_RUN_IDS[member["evidence_tag"]],
            "run_attempt": 1,
            "conclusion": "failure",
            "head_sha": INITIAL_CROSS_VERSION_PROTOCOL_COMMIT,
        }
        for member in EXPECTED_CROSS_VERSION_COHORT
    ]
    expected_initial = {
        "plan_path": "experiments/github_actions/cross_version_protocol_plan_v1.3.json",
        "protocol_commit": INITIAL_CROSS_VERSION_PROTOCOL_COMMIT,
        "planned_runs": 9,
        "observed_outcome": "nine_first_attempt_failures",
        "preservation": (
            "All nine original first-attempt failures remain part of the record and are not "
            "replaced by the confirmatory cohort."
        ),
        "runs": expected_initial_runs,
    }
    if amendment.get("initial_protocol") != expected_initial:
        errors.append("cross-version amendment does not preserve all nine exact initial failures")

    expected_diagnosis = {
        "classification": "experiment_harness_lifecycle_defect",
        "common_failure_point": (
            "after_exact_kubernetes_version_validation_before_artifact_creation"
        ),
        "cause": (
            "The in-job acceptance check expected the completed-run GitHub artifact row before "
            "the Upload evidence artifact step created that artifact."
        ),
        "scope": (
            "All nine first attempts reached the same lifecycle assertion after exact "
            "kubectl-client, API-server, and kubelet version validation."
        ),
        "interpretation": (
            "The failures are preserved as failed workflow outcomes; they are not evidence that "
            "the cross-plane acceptance criteria passed and they are not silently replaced."
        ),
    }
    if amendment.get("failure_diagnosis") != expected_diagnosis:
        errors.append("cross-version amendment changes the observed failure lifecycle diagnosis")

    correction = amendment.get("correction_scope")
    if not isinstance(correction, dict) or set(correction) != {
        "policy",
        "allowed_changes",
        "confirmatory_tag_enablement",
        "unchanged",
    }:
        errors.append("cross-version amendment correction scope differs")
    else:
        changes = correction.get("allowed_changes")
        expected_change_paths = [
            "experiments/github_actions/run_cross_plane_v1_3.sh",
            "experiments/github_actions/capture_completed_run_v1_3.sh",
            "experiments/github_actions/capture_run_outcome_v1_3.py",
            "experiments/github_actions/summarize_cross_version_run_set.py",
        ]
        if (
            not isinstance(changes, list)
            or [change.get("path") for change in changes if isinstance(change, dict)]
            != expected_change_paths
            or any(set(change) != {"path", "change"} for change in changes if isinstance(change, dict))
        ):
            errors.append("cross-version amendment expands the scientific correction paths")
        correction_text = json.dumps(correction, sort_keys=True)
        for phrase in (
            "Remove the artifact-dependent three-GitHub-row acceptance assertion",
            "completed-run finalization, after GitHub has created the artifact",
            "exact workflow and tag identity",
            "generation-specific balanced-cohort tag indices",
            "run-04..06",
            "descriptive-only analysis boundary",
        ):
            if phrase not in correction_text:
                errors.append(
                    f"cross-version amendment correction scope omits {phrase!r}"
                )

    binding = amendment.get("amendment_commit_binding")
    if not isinstance(binding, str) or any(
        phrase not in binding
        for phrase in (
            "single Git commit containing this amendment and the limited correction",
            "confirmatory run set",
            "not edited back into this file",
        )
    ):
        errors.append("cross-version amendment lacks a prospective single-commit binding")

    acceptance = amendment.get("acceptance_criteria")
    required_acceptance = (
        "nine distinct workflow run IDs at one shared amendment commit",
        "run attempt one and successful conclusion",
        "requested Kubernetes version equals kubectl client, API server, and kubelet version",
        "present no-ID negative-control evidence remains unjoined",
        "exactly three GitHub evidence rows are accepted only during completed-run finalization",
        "all nested and cohort SHA-256 manifests verify",
        "SLSA bundle verifies offline",
    )
    if (
        not isinstance(acceptance, list)
        or len(acceptance) != 10
        or any(not isinstance(item, str) for item in acceptance)
        or any(not any(phrase in item for item in acceptance) for phrase in required_acceptance)
    ):
        errors.append("cross-version amendment weakens the confirmatory acceptance criteria")

    policy_text = "\n".join(
        str(amendment.get(field, ""))
        for field in ("failure_policy", "failure_capture", "analysis_policy", "claim_boundary")
    )
    for phrase in (
        "Do not replace a failed confirmatory cohort member",
        "even when no evidence archive exists",
        "initial nine failures and the nine confirmatory outcomes as separate generations",
        "descriptive procedural repetitions, not inferential samples",
        "not identifier discovery",
        "cross-provider or cross-organization replication",
        "managed-cluster or field deployment",
        "third-party reproduction",
        "production reliability estimate",
        "initial nine failed runs passed",
    ):
        if phrase not in policy_text:
            errors.append(f"cross-version amendment policy omits {phrase!r}")


def validate_cross_version_protocol(errors: list[str]) -> None:
    """Validate both predeclared cross-version generations and their boundaries."""

    experiment_root = ROOT / "experiments/github_actions"
    target_path = experiment_root / "kubernetes_targets_v1.3.json"
    plan_path = experiment_root / "cross_version_protocol_plan_v1.3.json"
    workflow_path = ROOT / ".github/workflows/eacp-cross-plane-v1.3.yml"
    ledger_path = ROOT / "CLAIMS_AND_EVIDENCE_v1.3.md"

    validate_cross_version_amendment(errors)

    if target_path.is_file():
        targets = load_json_object(target_path, relative(target_path), errors)
        if targets is not None and targets != EXPECTED_CROSS_VERSION_TARGETS:
            errors.append(
                "cross-version Kubernetes target manifest differs from the exact "
                "kind, node-image, or kubectl checksum pins"
            )

    plan = None
    if plan_path.is_file():
        plan = load_json_object(plan_path, relative(plan_path), errors)
    if plan is not None:
        expected_scalars = {
            "schema_version": "eacp.cross-version-protocol-plan/1.3.0",
            "status": "prospective_before_execution",
            "repository": "obedebessa/eacp-operational-provenance",
            "workflow_path": ".github/workflows/eacp-cross-plane-v1.3.yml",
            "runner_class": "ubuntu-24.04 GitHub-hosted",
            "kind_version": "v0.32.0",
            "target_manifest": "experiments/github_actions/kubernetes_targets_v1.3.json",
            "design": "balanced 3-by-3 controlled procedural-repetition cohort",
            "execution_order": (
                "round-robin by replicate: v1.34.8, v1.35.5, v1.36.1; "
                "repeat for run-02 and run-03"
            ),
            "execution_order_interpretation": (
                "Evidence-tag pushes are issued in this order; GitHub queue and start order "
                "are observed rather than controlled."
            ),
            "planned_runs": 9,
            "first_attempts_per_version": 3,
            "inferential_statistics": False,
            "external_reproductions": 0,
            "independent_organizations": 0,
            "identifier_discovery_evaluated": False,
        }
        for key, expected in expected_scalars.items():
            observed = plan.get(key)
            if observed != expected or type(observed) is not type(expected):
                errors.append(
                    f"cross-version prospective plan {key}={observed!r}; "
                    f"expected {expected!r}"
                )

        expected_subject = {
            "uri": "registry.k8s.io/pause",
            "digest": GITHUB_ACTIONS_SUBJECT_DIGEST,
        }
        if plan.get("subject") != expected_subject:
            errors.append("cross-version prospective plan subject URI or digest differs")

        if plan.get("cohort") != EXPECTED_CROSS_VERSION_COHORT:
            errors.append("cross-version prospective plan cohort or evidence tags differ")

        expected_held_constant = {
            "protocol commit",
            "workflow path",
            "kind binary version and checksum",
            "GitHub-hosted runner label",
            "workload and subject image digest",
            "adapter, resolver, controls, and acceptance criteria",
        }
        held_constant = plan.get("held_constant")
        if (
            not isinstance(held_constant, list)
            or len(held_constant) != len(expected_held_constant)
            or not all(isinstance(value, str) for value in held_constant)
            or set(held_constant) != expected_held_constant
        ):
            errors.append("cross-version prospective plan does not freeze the declared constants")

        expected_varied = {
            "checksum-pinned kind node image",
            "matching checksum-pinned kubectl",
            "Kubernetes minor version",
        }
        varied = plan.get("varied")
        if (
            not isinstance(varied, list)
            or len(varied) != len(expected_varied)
            or not all(isinstance(value, str) for value in varied)
            or set(varied) != expected_varied
        ):
            errors.append("cross-version prospective plan varies undeclared factors")

        acceptance = plan.get("acceptance_criteria")
        expected_acceptance = [
            "nine distinct workflow run IDs at one shared protocol commit, with three first attempts per Kubernetes version",
            "run attempt one and successful conclusion for every evidence tag",
            "requested Kubernetes version equals kubectl client, API server, and kubelet version",
            "positive raw Kubernetes audit evidence retains the workflow-generated correlation annotation",
            "present no-ID negative-control evidence remains unjoined",
            "one exact-target HTTP 403 is adapter-explicit and has no source-native operational correlation",
            "Deployment image, Pod specification, and runtime image ID match the OCI digest as a separate check",
            "all nested and cohort SHA-256 manifests verify",
            "each downloaded SLSA bundle verifies offline under exact repository, workflow, source digest, source ref, and hosted-runner constraints",
        ]
        if acceptance != expected_acceptance:
            errors.append("cross-version prospective plan acceptance criteria differ")

        protocol_binding = plan.get("protocol_commit_binding")
        if not isinstance(protocol_binding, str) or any(
            phrase not in protocol_binding
            for phrase in (
                "single Git commit containing this plan",
                "not edited into this file",
            )
        ):
            errors.append("cross-version plan does not bind evidence tags prospectively")

        policy_requirements = {
            "failure_policy": (
                "Preserve and report every first-run failure",
                "Do not replace a failed cohort member with a rerun",
            ),
            "failure_capture": (
                "capture_run_outcome_v1_3.py",
                "minimized job/step outcome metadata",
                "even when no evidence archive exists",
            ),
            "analysis_policy": (
                "Report every run and each version separately",
                "Three runs per version are descriptive procedural repetitions",
                "not inferential samples",
                "earlier three rerun attempts",
            ),
            "claim_boundary": (
                "controlled cross-version compatibility, sensitivity, and within-version procedural-repetition cohort",
                "not identifier discovery",
                "cross-provider or cross-organization replication",
                "managed-cluster or field deployment",
                "third-party reproduction",
                "inferential evidence",
                "production reliability estimate",
            ),
        }
        for field, phrases in policy_requirements.items():
            value = plan.get(field)
            if not isinstance(value, str) or any(phrase not in value for phrase in phrases):
                errors.append(f"cross-version prospective plan weakens {field}")

    if workflow_path.is_file():
        workflow = workflow_path.read_text(encoding="utf-8")
        workflow_tags = re.findall(
            r'(?m)^\s*-\s+"(eacp-v1\.3-evidence/k8s-[^"]+)"\s*$', workflow
        )
        if (
            len(workflow_tags) != len(EXPECTED_CROSS_VERSION_WORKFLOW_TAGS)
            or set(workflow_tags) != EXPECTED_CROSS_VERSION_WORKFLOW_TAGS
        ):
            errors.append(
                "cross-version workflow evidence-tag allowlist differs from the exact union "
                "of nine initial and nine confirmatory tags"
            )
        if re.search(r"(?m)^\s+branches(?:-ignore)?:", workflow):
            errors.append("cross-version evidence workflow must not run on branch pushes")
        required_workflow_text = (
            "resolve_kubernetes_target.py",
            "kubernetes_targets_v1.3.json",
            "Install checksum-pinned kind and matching kubectl",
            "KIND_LINUX_AMD64_SHA256",
            "KUBECTL_LINUX_AMD64_SHA256",
            "The workflow generated the correlation key",
            "controlled propagation and exact composition of an introduced key",
            "not discovery of a naturally occurring identifier",
            "A present no-ID control remained unjoined",
            "adapter-explicit rather than source-native",
            "the OCI digest is checked separately",
            "does not prove the semantic truth of upstream events",
        )
        missing = [text for text in required_workflow_text if text not in workflow]
        if missing:
            errors.append(
                "cross-version workflow omits pinning or claim-boundary text: "
                + ", ".join(repr(text) for text in missing)
            )

    if ledger_path.is_file():
        ledger = ledger_path.read_text(encoding="utf-8")
        claim_ids = [int(match) for match in re.findall(r"(?m)^\| C([0-9]+) \|", ledger)]
        if claim_ids != list(range(1, 14)):
            errors.append("v1.3 claims ledger must contain exactly claims C1 through C13")
        required_ledger_text = (
            "The workflow generated and planted the key",
            "controlled propagation and composition",
            "not identifier discovery",
            "independent organizational corroboration",
            "A present no-ID Kubernetes control remains unjoined",
            "`adapter_explicit_exact_target`",
            "checked separately from operational correlation",
            "names only the in-run TAR as its subject",
            "not builder-attested",
            "captured root enables offline re-verification relative to captured bytes",
            "0/9 runs satisfying all predeclared criteria",
            "neither retained capture is an origin-signed response",
            "9/9 first-attempt workflow successes",
            "not pooled",
            "only an external operator can establish independent reproduction",
        )
        missing = [text for text in required_ledger_text if text not in ledger]
        if missing:
            errors.append(
                "v1.3 claims ledger omits evidence boundaries: "
                + ", ".join(repr(text) for text in missing)
            )

    summarizer = experiment_root / "summarize_cross_version_run_set.py"
    frozen_protocol_copies = (
        (
            plan_path,
            experiment_root
            / "results/reference/cross-version-initial-failed-cohort-v1.3/protocol_plan.json",
            "initial cohort protocol copy",
        ),
        (
            experiment_root / "cross_version_protocol_amendment_v1.3.1.json",
            experiment_root
            / "results/reference/cross-version-confirmatory-cohort-v1.3/protocol_amendment.json",
            "confirmatory cohort amendment copy",
        ),
    )
    for source, frozen_copy, label in frozen_protocol_copies:
        if source.is_file() and frozen_copy.is_file():
            source_value = load_json_object(source, relative(source), errors)
            copy_value = load_json_object(frozen_copy, relative(frozen_copy), errors)
            if source_value is not None and copy_value is not None and source_value != copy_value:
                errors.append(f"{label} differs semantically from its repository source")

    required_cohorts = (
        (
            experiment_root
            / "results/reference/cross-version-initial-failed-cohort-v1.3",
            EXPECTED_CROSS_VERSION_COHORT,
            [1, 2, 3],
            "initial failed cross-version cohort",
            INITIAL_CROSS_VERSION_PROTOCOL_COMMIT,
            EXPECTED_INITIAL_FAILED_RUN_IDS,
            0,
        ),
        (
            experiment_root
            / "results/reference/cross-version-confirmatory-cohort-v1.3",
            EXPECTED_CONFIRMATORY_CROSS_VERSION_COHORT,
            [4, 5, 6],
            "confirmatory cross-version cohort",
            CONFIRMATORY_CROSS_VERSION_PROTOCOL_COMMIT,
            EXPECTED_CONFIRMATORY_RUN_IDS,
            9,
        ),
    )
    for (
        cohort_root,
        expected_members,
        expected_indices,
        label,
        expected_commit,
        expected_run_ids,
        expected_successes,
    ) in required_cohorts:
        validate_cross_version_run_set_binding(
            cohort_root=cohort_root,
            expected_members=expected_members,
            expected_indices=expected_indices,
            label=label,
            errors=errors,
            expected_protocol_commit=expected_commit,
            expected_run_ids=expected_run_ids,
        )
        validate_cross_version_summary_contract(
            cohort_root=cohort_root,
            expected_members=expected_members,
            expected_indices=expected_indices,
            expected_protocol_commit=expected_commit,
            expected_run_ids=expected_run_ids,
            expected_successes=expected_successes,
            label=label,
            errors=errors,
        )
        if cohort_root.is_dir() and summarizer.is_file():
            run_offline_check(
                [
                    sys.executable,
                    str(summarizer),
                    "--root",
                    str(cohort_root),
                    "--target-manifest",
                    str(target_path),
                    "--verify",
                ],
                f"{label} checksum and invariant verification",
                errors,
            )


def png_dimensions(path: Path, errors: list[str]) -> tuple[int, int] | None:
    try:
        with path.open("rb") as stream:
            header = stream.read(24)
    except OSError as exc:
        errors.append(f"cannot read candidate figure {relative(path)}: {exc}")
        return None
    if len(header) != 24 or header[:8] != b"\x89PNG\r\n\x1a\n" or header[12:16] != b"IHDR":
        errors.append(f"candidate figure is not a valid PNG header: {relative(path)}")
        return None
    return struct.unpack(">II", header[16:24])


def validate_candidate_figures_and_docs(errors: list[str]) -> None:
    for name, expected in EXPECTED_CANDIDATE_FIGURES.items():
        path = ROOT / name
        if path.is_file():
            dimensions = png_dimensions(path, errors)
            if dimensions is not None and dimensions != expected:
                errors.append(
                    f"candidate figure dimensions differ for {name}: "
                    f"{dimensions[0]}x{dimensions[1]}, expected {expected[0]}x{expected[1]}"
                )

    release_notes = ROOT / "RELEASE_NOTES_v1.3-candidate.md"
    reviewer_guide = ROOT / "REVIEWER_GUIDE_v1.3.md"
    for path in (release_notes, reviewer_guide):
        if not path.is_file():
            continue
        content = path.read_text(encoding="utf-8")
        for required_text in (
            "reviewer candidate",
            "no v1.3 DOI",
            ARTIFACT_DOI,
            str(GITHUB_ACTIONS_RUN_ID),
        ):
            if required_text not in content:
                errors.append(f"{relative(path)} omits candidate boundary text: {required_text}")


def validate_candidate_additions(errors: list[str]) -> None:
    if not any((ROOT / name).exists() for name in CANDIDATE_SENTINELS):
        return
    for name in CANDIDATE_REQUIRED_FILES:
        if not (ROOT / name).is_file():
            errors.append(f"missing v1.3 candidate file: {name}")
    for name in CANDIDATE_REQUIRED_DIRECTORIES:
        if not (ROOT / name).is_dir():
            errors.append(f"missing v1.3 candidate directory: {name}")

    validate_profile_candidate(errors)
    validate_correlation_candidate(errors)
    validate_index_ablation_candidate(errors)
    validate_github_actions_candidate(errors)
    validate_cross_version_protocol(errors)
    validate_candidate_figures_and_docs(errors)


def validate_frozen_results(errors: list[str]) -> None:
    k8s_run = ROOT / "data/kubernetes/20260806T031453Z"
    if k8s_run.is_dir():
        actual = {
            path.relative_to(k8s_run).as_posix()
            for path in k8s_run.rglob("*")
            if path.is_file()
        }
        if actual != APPROVED_KUBERNETES_RESULT_FILES:
            missing = sorted(APPROVED_KUBERNETES_RESULT_FILES - actual)
            extra = sorted(actual - APPROVED_KUBERNETES_RESULT_FILES)
            errors.append(
                "canonical Kubernetes result set differs from the approved eight files "
                f"(missing={missing}, extra={extra})"
            )

        public_jsonl = k8s_run / "analysis/public_filtered_audit.jsonl"
        projection_csv = k8s_run / "analysis/normalized_evidence.csv"
        if public_jsonl.is_file() and sha256(public_jsonl) != KUBERNETES_INPUT_SHA256:
            errors.append("canonical Kubernetes JSONL checksum mismatch")
        if projection_csv.is_file() and sha256(projection_csv) != KUBERNETES_PROJECTION_CSV_SHA256:
            errors.append("canonical Kubernetes projection CSV checksum mismatch")

        summary_path = k8s_run / "analysis/summary.json"
        if summary_path.is_file():
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
            if summary.get("scope", {}).get("namespace_audit_records") != 374:
                errors.append("Kubernetes summary does not report 374 retained records")
            if summary.get("integrity", {}).get("stored_rows") != 374:
                errors.append("Kubernetes summary does not report 374 stored rows")
            if summary.get("rbac_denials", {}).get("count") != 3:
                errors.append("Kubernetes summary does not report three RBAC denials")
            privacy = summary.get("privacy", {})
            for key in (
                "absolute_filesystem_paths_redacted",
                "certificates_redacted",
                "credential_identifiers_removed",
                "audit_sourceIPs_fields_removed",
                "token_subresource_records_excluded",
            ):
                if privacy.get(key) is not True:
                    errors.append(f"Kubernetes privacy assertion is not true: {key}")

    comparison_run = ROOT / "data/comparison/20260806T032418Z"
    comparison_summary_path = comparison_run / "summary.json"
    if comparison_summary_path.is_file():
        summary = json.loads(comparison_summary_path.read_text(encoding="utf-8"))
        if summary.get("input", {}).get("sha256") != KUBERNETES_INPUT_SHA256:
            errors.append("comparison summary input checksum mismatch")
        if summary.get("input", {}).get("canonical_projection_sha256") != CANONICAL_PROJECTION_SHA256:
            errors.append("comparison summary projection checksum mismatch")
        collector = summary.get("solutions", {}).get("opentelemetry", {})
        if collector.get("resolved_digest") != OTEL_IMAGE_DIGEST:
            errors.append("comparison summary Collector image digest mismatch")
        if collector.get("collector_natively_maps_eacp_13_field_projection") is not False:
            errors.append("comparison summary must reject a Collector-native EACP mapping claim")
        preservation = summary.get("validation", {}).get(
            "post_export_canonical_projection_preservation", {}
        )
        if preservation.get("mapping_performed_by") != (
            "shared external validator after Collector export; not by the Collector configuration"
        ):
            errors.append("comparison summary does not identify the post-export external validator")
        equality = preservation.get("field_value_equality", {})
        if equality.get("compared_field_values") != 4862 or equality.get("correct_field_values") != 4862:
            errors.append("comparison summary does not report 4,862/4,862 equal field values")

    checksum_path = comparison_run / "SHA256SUMS"
    if checksum_path.is_file():
        for line in checksum_path.read_text(encoding="utf-8").splitlines():
            expected, name = line.split(maxsplit=1)
            target = comparison_run / name.strip()
            if not target.is_file() or sha256(target) != expected:
                errors.append(f"comparison run checksum mismatch: {name.strip()}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--release",
        action="store_true",
        help="also reject unresolved placeholders and missing frozen release files",
    )
    args = parser.parse_args()

    errors: list[str] = []
    warnings: list[str] = []

    for name in REQUIRED_FILES:
        if not (ROOT / name).is_file():
            errors.append(f"missing required file: {name}")
    for name in REQUIRED_DIRECTORIES:
        if not (ROOT / name).is_dir():
            errors.append(f"missing required directory: {name}")

    validate_frozen_results(errors)
    validate_candidate_additions(errors)

    cff_path = ROOT / "CITATION.cff"
    if cff_path.is_file():
        cff = cff_path.read_text(encoding="utf-8")
        if f"version: {ARTIFACT_VERSION}" not in cff:
            errors.append(f"CITATION.cff does not declare artifact version {ARTIFACT_VERSION}")
        if f'doi: "{ARTIFACT_DOI}"' not in cff:
            errors.append("CITATION.cff does not declare the reserved artifact DOI")
        if f'repository-code: "{REPOSITORY_URL}"' not in cff:
            errors.append("CITATION.cff does not declare the canonical repository URL")
        if re.search(r"(?m)^\s*email\s*:", cff):
            errors.append("CITATION.cff must not publish a personal email address")
        if args.release and not re.search(r"(?m)^\s*doi\s*:\s*[\"']?10\.", cff):
            errors.append("release CITATION.cff is missing the published DOI")

    readme_path = ROOT / "README.md"
    if readme_path.is_file():
        readme = readme_path.read_text(encoding="utf-8")
        if ARTIFACT_DOI not in readme:
            errors.append("README.md does not declare the version-specific artifact DOI")
        if CONCEPT_DOI not in readme:
            errors.append("README.md does not declare the Zenodo Concept DOI")

    for path in iter_text_files():
        try:
            content = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for pattern in ABSOLUTE_PATH_RES:
            if pattern.search(content):
                errors.append(f"local absolute path found in {relative(path)}")
                break
        for pattern in PRIVATE_MATERIAL_RES:
            if pattern.search(content):
                errors.append(f"possible private material found in {relative(path)}")
                break
        placeholders = sorted(set(PLACEHOLDER_RE.findall(content)))
        if placeholders:
            message = f"{relative(path)}: {', '.join(placeholders)}"
            if args.release:
                errors.append(f"unresolved placeholder(s): {message}")
            else:
                warnings.append(f"scaffold placeholder(s): {message}")

    if args.release:
        paper_notice_path = ROOT / "paper/README.md"
        if paper_notice_path.is_file():
            paper_notice = paper_notice_path.read_text(encoding="utf-8")
            if "All rights reserved" not in paper_notice:
                errors.append("paper/README.md is missing the preprint rights notice")
            if "not an article" not in paper_notice:
                errors.append("paper/README.md does not distinguish the artifact DOI")
        for name in RELEASE_REQUIRED_FILES:
            if not (ROOT / name).is_file():
                errors.append(f"missing frozen release file: {name}")
        for path in ROOT.rglob("*"):
            if not path.is_file():
                continue
            lowered_name = path.name.lower()
            if (
                lowered_name == "audit.log"
                or lowered_name == "cluster-state.yaml"
                or lowered_name == "kind-config.yaml"
                or lowered_name.startswith("analysis-console")
                or "preprivacy" in lowered_name
                or "kubeconfig" in lowered_name
                or lowered_name.endswith((".key", ".pem", ".p12", ".pfx"))
            ):
                errors.append(f"forbidden runtime or credential file: {relative(path)}")
            if relative(path).startswith("data/kubernetes/"):
                try:
                    kubernetes_data = path.read_text(encoding="utf-8")
                except UnicodeDecodeError:
                    continue
                if re.search(r"[\"']sourceIPs[\"']\s*:", kubernetes_data):
                    errors.append(f"unsanitized sourceIPs field found in {relative(path)}")
        manifest_script = ROOT / "scripts/generate_manifest.py"
        if (ROOT / "MANIFEST.sha256").is_file() and manifest_script.is_file():
            result = subprocess.run(
                [sys.executable, str(manifest_script), "--check"],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            if result.returncode != 0:
                errors.append("MANIFEST.sha256 does not match the frozen repository tree")

    for warning in warnings:
        print(f"WARNING: {warning}")
    for error in errors:
        print(f"ERROR: {error}", file=sys.stderr)

    if errors:
        print(f"Repository verification failed with {len(errors)} error(s).", file=sys.stderr)
        return 1

    candidate = any((ROOT / name).exists() for name in CANDIDATE_SENTINELS)
    mode = "release" if args.release else "candidate" if candidate else "scaffold"
    print(f"Repository {mode} verification passed with {len(warnings)} warning(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
