#!/usr/bin/env python3
"""Publish only v1.4 allowlisted Kubernetes metadata using Profile 1.3 records.

This is an opt-in new extractor. Frozen v1.3 source and outputs are untouched.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import sys
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any, Sequence

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import extract_kubernetes_audit_v1_3 as legacy  # noqa: E402
from eacp_hardening.common import HardeningError, canonical_bytes, identifier  # noqa: E402
from eacp_hardening.privacy import POLICY, check_oci_digest, project_kubernetes_audit  # noqa: E402


def _metadata_view(record: dict[str, Any]) -> dict[str, Any]:
    """Unify compatible public metadata for normalization, never source output.

    The frozen helpers select the first body with metadata. A merge-patch request
    can omit a link that is present in the response, so that precedence is unsafe
    for claiming ID absence. Both bodies are checked here. This derived view is
    only consumed by normalization; source digests still bind the actual public
    record, whose request and response bodies remain separate and unchanged.
    """
    merged: dict[str, Any] = {}
    for body_name in ("requestObject", "responseObject"):
        metadata = record.get(body_name, {}).get("metadata", {})
        for key, value in metadata.items():
            if key in {"annotations", "labels"}:
                current = merged.setdefault(key, {})
                if any(name in current and current[name] != item for name, item in value.items()):
                    raise HardeningError("audit body metadata declarations conflict")
                current.update(value)
            elif key in merged and merged[key] != value:
                raise HardeningError("audit body object identities conflict")
            else:
                merged[key] = value
    reference = record["objectRef"]
    if any(key in merged and key in reference and merged[key] != reference[key]
           for key in ("name", "namespace", "uid")):
        raise HardeningError("audit body identity conflicts with its source reference")
    return {**record, "requestObject": {"metadata": merged}}


def extract_records(records: Sequence[Any], *, namespace: str, correlation_id: str,
                    denied_principal: str, denied_target_api_group: str,
                    denied_target_resource: str, denied_target_name: str,
                    negative_control_name: str, cluster_id: str,
                    expected_subject_digest: str | None = None,
                    observed_subject_digest: str | None = None) -> dict[str, Any]:
    """Validate all controls before returning any publication payload."""
    for item in (namespace, correlation_id, denied_principal, denied_target_resource,
                 denied_target_name, negative_control_name, cluster_id):
        identifier(item, "extractor configuration")
    if not isinstance(denied_target_api_group, str):
        raise HardeningError("invalid extractor API group")
    if negative_control_name == denied_target_name:
        raise HardeningError("negative control must be a distinct object")
    if (expected_subject_digest is None) != (observed_subject_digest is None):
        raise HardeningError("OCI comparison requires both declared and observed digests")
    target = {"api_group": denied_target_api_group, "resource": denied_target_resource,
              "namespace": namespace, "name": denied_target_name}
    public = []
    drops: Counter[tuple[str, str]] = Counter()
    excluded = 0
    unscoped = 0
    for record in records:
        if not isinstance(record, dict):
            raise HardeningError("audit input is not a JSON object")
        if "objectRef" not in record:
            unscoped += 1
            continue
        if not isinstance(record["objectRef"], dict):
            raise HardeningError("audit object reference is malformed")
        ref = record["objectRef"]
        # No URI fallback: query strings and arbitrary URLs never become source
        # identity. Out-of-scope source records are neither retained nor echoed.
        if "namespace" not in ref:
            unscoped += 1
            continue
        if not isinstance(ref["namespace"], str):
            raise HardeningError("audit namespace is malformed")
        if ref["namespace"] != namespace:
            excluded += 1
            continue
        result = project_kubernetes_audit(record, namespace=namespace)
        public.append(result.payload)
        for item in result.report["drops"]:
            drops[item["path"], item["reason"]] += item["count"]
    if not public:
        raise HardeningError("no records remain in the declared publication scope")
    keys = [(record["auditID"], record["stage"]) for record in public]
    if len(set(keys)) != len(keys):
        raise HardeningError("duplicate audit source identity")
    views = [_metadata_view(record) for record in public]
    positive = [record for record in views if legacy.correlation_of(record) == correlation_id]
    denials = [record for record in views
               if legacy.object_target(record) == target
               and legacy.effective_actor(record) == denied_principal
               and legacy.status_value(record)[0] == 403]
    negative = [record for record in views if legacy.object_name(record) == negative_control_name]
    if not positive:
        raise HardeningError("positive correlation control failed")
    if not any(legacy.object_target(record) == target for record in positive):
        raise HardeningError("positive correlation is not observed on the declared adapter target")
    if not denials:
        raise HardeningError("exact target, principal and HTTP 403 control failed")
    if any(legacy.correlation_of(record) is not None for record in denials):
        raise HardeningError("adapter-explicit HTTP 403 control carries a native correlation declaration")
    if not negative or any(legacy.correlation_of(record) is not None for record in negative):
        raise HardeningError("present no-ID negative control failed")
    digest_check = {"performed": False, "independent_of_correlation": True}
    if expected_subject_digest is not None:
        digest_check = {"performed": True, **check_oci_digest(expected_subject_digest, observed_subject_digest)}
        if not digest_check["matched"]:
            raise HardeningError("separate OCI digest comparison failed")
        declared = {legacy.annotations_of(record).get("eacp.io/subject-digest") for record in positive}
        if declared != {expected_subject_digest}:
            raise HardeningError("positive evidence does not consistently declare the expected OCI digest")
    rows, profile = [], []
    for record, view in zip(public, views):
        # Only an exact principal+target+403 gets an explicit adapter assertion.
        # v1.3 helpers accept a target-only binding, so pass it only for the
        # already validated denial records; no frozen helper is changed.
        explicit = correlation_id if view in denials else None
        row = legacy.normalize(view, namespace, adapter_correlation_id=explicit, adapter_target=target)
        # The normalized view is not a new source observation. Bind the retained
        # original public record with its separate request/response bodies.
        row["content_hash"] = hashlib.sha256(canonical_bytes(record)).hexdigest()
        if legacy.correlation_of(view) is None and explicit is None:
            # An object locator is not an operational correlation assertion.
            # Keep absence explicit even in the legacy flat CSV representation.
            row["correlation_id"] = ""
        normalized = legacy.profile_record(view, row, namespace=namespace, cluster_id=cluster_id,
                                           adapter_correlation_id=explicit, adapter_target=target)
        normalized["source_digest"]["canonicalization"] = (
            "UTF-8 JSON; object keys sorted; compact separators; ensure_ascii=false; " + POLICY)
        for link in normalized["links"]:
            if link["type"] == "operational_correlation":
                link["scope"]["id"] = "urn:eacp:experiment:github-actions-kubernetes:v1.4"
        rows.append(row)
        profile.append(normalized)
    try:
        legacy.validate_profile_records(profile)
    except Exception:
        raise HardeningError("minimized records fail Profile validation") from None
    privacy = {"policy": POLICY, "input_records": len(records), "retained_records": len(public),
               "excluded_scope_records": excluded,
               "excluded_unscoped_records": unscoped,
               "dropped_member_count": sum(drops.values()),
               "drops": [{"path": path, "reason": reason, "count": count}
                         for (path, reason), count in sorted(drops.items())],
               "raw_values_retained_in_report": False,
               "manual_publication_review_required": True}
    summary = {"adapter": "eacp.kubernetes.public-extractor/1.4.0", "profile": "eacp.profile/1.3",
               "records": len(public), "positive_control_records": len(positive),
               "adapter_explicit_exact_target_principal_http403_records": len(denials),
               "present_unjoined_no_id_records": len(negative), "oci_digest_check": digest_check,
               "source_authenticity_established": False,
               "upstream_completeness_established": False}
    return {"public_records": public, "evidence_rows": rows, "profile_records": profile,
            "privacy_report": privacy, "summary": summary}


def write_outputs(audit_log: Path, output_dir: Path, **options: Any) -> dict[str, Any]:
    if output_dir.exists():
        raise HardeningError("publication destination already exists")
    try:
        with audit_log.open(encoding="utf-8") as handle:
            records = [json.loads(line) for line in handle if line.strip()]
    except (OSError, UnicodeError, ValueError):
        raise HardeningError("cannot read valid audit JSONL") from None
    result = extract_records(records, **options)
    output_dir.parent.mkdir(parents=True, exist_ok=True)
    # Temporary output contains only minimized records and validated metadata.
    with tempfile.TemporaryDirectory(prefix=".eacp-public-", dir=output_dir.parent) as temporary:
        staged = Path(temporary) / "result"
        staged.mkdir()
        for key, filename in (("public_records", "public_filtered_audit.jsonl"),
                              ("profile_records", "profile_records.jsonl")):
            (staged / filename).write_bytes(b"".join(canonical_bytes(record) + b"\n" for record in result[key]))
        with (staged / "normalized_evidence.csv").open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=legacy.EVIDENCE_HEADERS)
            writer.writeheader()
            writer.writerows(result["evidence_rows"])
        for key, filename in (("privacy_report", "privacy_report.json"), ("summary", "audit_summary.json")):
            (staged / filename).write_bytes(canonical_bytes(result[key]) + b"\n")
        manifest = "".join(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n"
                           for path in sorted(staged.iterdir()))
        (staged / "SHA256SUMS").write_text(manifest, encoding="utf-8")
        # A second existence check avoids replacing an ordinary concurrent
        # producer's completed output; callers must control this parent path.
        if output_dir.exists():
            raise HardeningError("publication destination already exists")
        os.rename(staged, output_dir)
    return result["summary"]


def main(argv: Sequence[str] | None = None) -> int:
    parser = legacy.build_parser()
    parser.description = __doc__
    parser.add_argument("--expected-subject-digest")
    parser.add_argument("--observed-subject-digest")
    args = vars(parser.parse_args(argv))
    try:
        summary = write_outputs(**args)
    except HardeningError as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 2
    sys.stdout.write(canonical_bytes(summary).decode("utf-8") + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
