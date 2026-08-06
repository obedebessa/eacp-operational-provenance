#!/usr/bin/env python3
"""Check the public EACP artifact for structure and common release leaks."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
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
    "figures/eacp_kubernetes_otel_results.png",
    "paper/EACP_preprint.pdf",
    "MANIFEST.sha256",
)

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
ARTIFACT_DOI = "10.5281/zenodo.21817377"
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

    cff_path = ROOT / "CITATION.cff"
    if cff_path.is_file():
        cff = cff_path.read_text(encoding="utf-8")
        if "version: 1.1.0" not in cff:
            errors.append("CITATION.cff does not declare artifact version 1.1.0")
        if f'doi: "{ARTIFACT_DOI}"' not in cff:
            errors.append("CITATION.cff does not declare the reserved artifact DOI")
        if f'repository-code: "{REPOSITORY_URL}"' not in cff:
            errors.append("CITATION.cff does not declare the canonical repository URL")
        if re.search(r"(?m)^\s*email\s*:", cff):
            errors.append("CITATION.cff must not publish a personal email address")
        if args.release and not re.search(r"(?m)^\s*doi\s*:\s*[\"']?10\.", cff):
            errors.append("release CITATION.cff is missing the published DOI")

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

    mode = "release" if args.release else "scaffold"
    print(f"Repository {mode} verification passed with {len(warnings)} warning(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
