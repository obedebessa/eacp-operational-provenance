#!/usr/bin/env python3
"""Reprocess frozen public audit evidence in memory; publish counts and hashes.

This does not collect new events, independently reproduce the live experiment,
or overwrite any historical result. Colocated checksums bind compared bytes,
not upstream authenticity or freshness.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any, Sequence


ROOT = Path(__file__).resolve().parents[1]
COHORT = Path("experiments/github_actions/results/reference/cross-version-confirmatory-cohort-v1.3")
AUDIT_SUFFIX = Path("downloaded-artifact/eacp-cross-plane-v1.3-results/kubernetes/audit")
AUDIT_FILES = {"public_filtered_audit.jsonl", "normalized_evidence.csv", "profile_records.jsonl", "audit_summary.json"}
IMPLEMENTATION_FILES = (
    "eacp_hardening/common.py", "eacp_hardening/privacy.py",
    "experiments/github_actions/extract_kubernetes_audit_v1_4.py",
    "experiments/github_actions/extract_kubernetes_audit_v1_3.py",
    "experiments/github_actions/eacp_gha_v1_3.py", "spec/tools/eacp_profile.py",
    "scripts/reprocess_frozen_privacy_v1_4.py",
)
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "experiments/github_actions"))
from eacp_hardening.common import HardeningError, canonical_bytes  # noqa: E402
from eacp_hardening.privacy import POLICY  # noqa: E402
from extract_kubernetes_audit_v1_4 import extract_records  # noqa: E402


def _source_bytes(path: Path, root: Path) -> bytes:
    try:
        path.resolve().relative_to(root.resolve())
        if path.is_symlink() or not path.is_file():
            raise HardeningError("reprocessing source must be a regular file")
        return path.read_bytes()
    except (OSError, ValueError):
        raise HardeningError("cannot read a bounded reprocessing source") from None


def _source_descriptor(path: Path, root: Path, content: bytes) -> dict[str, Any]:
    return {"path": path.relative_to(root).as_posix(), "sha256": hashlib.sha256(content).hexdigest(),
            "bytes": len(content)}


def _verified_audit_sources(folder: Path, root: Path) -> tuple[dict[str, bytes], list[dict[str, Any]]]:
    manifest_path = folder / "SHA256SUMS"
    manifest = _source_bytes(manifest_path, root)
    try:
        lines = manifest.decode("utf-8").splitlines()
    except UnicodeError:
        raise HardeningError("frozen audit manifest is not UTF-8") from None
    expected: dict[str, str] = {}
    for line in lines:
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9_.-]+)", line)
        if match is None or match[2] not in AUDIT_FILES or match[2] in expected:
            raise HardeningError("frozen audit manifest has an invalid inventory")
        expected[match[2]] = match[1]
    if set(expected) != AUDIT_FILES:
        raise HardeningError("frozen audit manifest does not bind the exact audit file set")
    sources: dict[str, bytes] = {}
    descriptors = [_source_descriptor(manifest_path, root, manifest)]
    for filename in sorted(expected):
        path = folder / filename
        content = _source_bytes(path, root)
        if hashlib.sha256(content).hexdigest() != expected[filename]:
            raise HardeningError("frozen audit source checksum mismatch")
        sources[filename] = content
        descriptors.append(_source_descriptor(path, root, content))
    return sources, sorted(descriptors, key=lambda item: item["path"])


def reprocess_frozen_corpus(repository_root: Path = ROOT) -> dict[str, Any]:
    """Verify and project the nine archived confirmatory audit corpora in memory.

    `repository_root` selects input files, not imported implementation code; the
    implementation descriptors always identify this helper's actual checkout.
    """
    repository_root = Path(repository_root).resolve()
    cohort_root = repository_root / COHORT
    paths = sorted(cohort_root.glob("run-*/" + AUDIT_SUFFIX.as_posix()))
    if len(paths) != 9 or any(not re.fullmatch(r"run-[0-9]+", path.parents[3].name) for path in paths):
        raise HardeningError("the frozen confirmatory cohort requires nine named audit directories")
    runs = []
    totals = {"input_records": 0, "retained_records": 0, "native_positive_records": 0,
              "adapter_explicit_403_records": 0, "present_unjoined_no_id_records": 0,
              "source_file_checks": 0, "excluded_scope_records": 0, "excluded_unscoped_records": 0}
    for folder in paths:
        sources, descriptors = _verified_audit_sources(folder, repository_root)
        try:
            metadata = json.loads(sources["audit_summary.json"])
            records = [json.loads(line) for line in sources["public_filtered_audit.jsonl"].decode("utf-8").splitlines() if line.strip()]
            target = metadata["rbac_denial"]["expected_target"]
            result = extract_records(
                records, namespace=metadata["scope"]["namespace"],
                correlation_id=metadata["positive_control"]["correlation_id"],
                denied_principal=metadata["rbac_denial"]["expected_principal"],
                denied_target_api_group=target["api_group"], denied_target_resource=target["resource"],
                denied_target_name=target["name"], negative_control_name=metadata["negative_control"]["object_name"],
                cluster_id=metadata["scope"]["cluster_id"],
            )
        except (UnicodeError, ValueError, KeyError, TypeError):
            raise HardeningError("frozen audit source failed parsing, public projection or control validation") from None
        summary, privacy = result["summary"], result["privacy_report"]
        counts = {
            "input_records": len(records), "retained_records": summary["records"],
            "native_positive_records": summary["positive_control_records"],
            "adapter_explicit_403_records": summary["adapter_explicit_exact_target_principal_http403_records"],
            "present_unjoined_no_id_records": summary["present_unjoined_no_id_records"],
            "source_file_checks": len(AUDIT_FILES), "excluded_scope_records": privacy["excluded_scope_records"],
            "excluded_unscoped_records": privacy["excluded_unscoped_records"],
        }
        for name, count in counts.items():
            totals[name] += count
        runs.append({"run_directory": folder.parents[3].relative_to(repository_root).as_posix(),
                     "source_integrity_checks_passed": True, "controls_passed": True,
                     "counts": counts, "sources": descriptors,
                     "public_projection_sha256": hashlib.sha256(canonical_bytes(result["public_records"])).hexdigest(),
                     "privacy_report_sha256": hashlib.sha256(canonical_bytes(privacy)).hexdigest(),
                     "separate_runtime_oci_digest_comparison_performed": False})
    expected = {"input_records": 457, "retained_records": 457, "native_positive_records": 69,
                "adapter_explicit_403_records": 9, "present_unjoined_no_id_records": 27,
                "source_file_checks": 36, "excluded_scope_records": 0, "excluded_unscoped_records": 0}
    if totals != expected:
        raise HardeningError("frozen privacy reprocessing counts differ from the declared reference")
    implementation = [_source_descriptor(ROOT / name, ROOT, _source_bytes(ROOT / name, ROOT)) for name in IMPLEMENTATION_FILES]
    return {
        "schema": "eacp.frozen-privacy-reprocessing/1.4.0",
        "method": "author_reprocessing_frozen_corpus", "policy": POLICY,
        "cohort": COHORT.as_posix(), "cohort_count": len(runs), "totals": totals, "runs": runs,
        "implementation_sources": implementation,
        "assertions": {
            "all_colocated_source_checksums_match": True, "all_declared_controls_pass": True,
            "historical_files_modified": False, "raw_or_minimized_records_written": False,
            "new_live_collection": False, "independent_reproduction": False,
            "upstream_completeness_established": False, "source_authenticity_established": False,
            "freshness_or_rollback_protection_established": False,
            "separate_runtime_oci_digest_comparison_performed": False,
            "manual_publication_review_required": True,
        },
        "verification_boundary": "Compared source bytes match their colocated checksums. The output records the exact input and implementation hashes; it does not authenticate origins or establish the latest state.",
    }


def write_summary_exclusive(path: Path, summary: dict[str, Any]) -> None:
    content = canonical_bytes(summary) + b"\n"
    try:
        with Path(path).open("xb") as handle:
            handle.write(content)
    except FileExistsError:
        raise HardeningError("summary destination already exists") from None
    except OSError:
        raise HardeningError("cannot write summary destination") from None


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository-root", type=Path, default=ROOT)
    parser.add_argument("--output", type=Path, help="exclusively create a JSON summary; never overwrite")
    args = parser.parse_args(argv)
    try:
        summary = reprocess_frozen_corpus(args.repository_root)
        if args.output is not None:
            write_summary_exclusive(args.output, summary)
    except HardeningError as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 2
    sys.stdout.write(canonical_bytes(summary).decode("utf-8") + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
