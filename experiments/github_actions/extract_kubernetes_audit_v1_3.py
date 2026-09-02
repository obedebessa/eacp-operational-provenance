#!/usr/bin/env python3
"""Extract the Kubernetes half of the EACP v1.3 cross-plane experiment.

This intentionally small extractor accepts API-server audit JSONL produced by
the isolated kind cluster.  It publishes only namespace-scoped, sanitized
records, projects the existing 13 EACP columns, and fails closed unless the
source-native positive correlation, correlation-free negative control, and a
target-bound adapter-explicit RBAC denial are all present.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Iterable, Sequence

from eacp_gha_v1_3 import EXPERIMENT_SCOPE, PROFILE_NAME, validate_profile_records


EVIDENCE_HEADERS = [
    "source_type",
    "source_id",
    "source_ts",
    "observed_ts",
    "actor",
    "service",
    "intent",
    "policy",
    "action",
    "outcome",
    "source_pointer",
    "correlation_id",
    "content_hash",
]
LOCAL_PATH_PATTERN = re.compile(
    r"/(?:Users|home|private/tmp|private/var/folders|tmp|var/folders)/[^\s\"']+"
)


class ExtractionError(RuntimeError):
    pass


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def pretty_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def sanitize(value: Any, key: str = "") -> Any:
    if isinstance(value, dict):
        cleaned: dict[str, Any] = {}
        for child_key, child_value in value.items():
            lowered = child_key.lower()
            if child_key == "sourceIPs":
                continue
            if child_key in {
                "authentication.kubernetes.io/credential-id",
                "authentication.kubernetes.io/issued-credential-id",
            }:
                continue
            if lowered in {
                "token",
                "ca.crt",
                "tls.crt",
                "certificate-authority-data",
                "client-certificate-data",
                "client-key-data",
            }:
                cleaned[child_key] = "<redacted-sensitive-value>"
                continue
            if child_key == "serviceAccountToken":
                cleaned[child_key] = "<redacted-service-account-token-projection>"
                continue
            if lowered in {"mountpath", "hostpath"} and isinstance(child_value, str):
                cleaned[child_key] = "<redacted-absolute-path>" if child_value.startswith("/") else child_value
                continue
            cleaned[child_key] = sanitize(child_value, child_key)
        return cleaned
    if isinstance(value, list):
        return [sanitize(item, key) for item in value]
    if isinstance(value, str):
        if key != "requestURI" and key.lower().endswith("path") and value.startswith("/"):
            return "<redacted-absolute-path>"
        if "-----BEGIN CERTIFICATE-----" in value:
            return "<redacted-certificate>"
        return LOCAL_PATH_PATTERN.sub("<redacted-local-path>", value)
    return value


def iter_records(path: Path) -> Iterable[dict[str, Any]]:
    try:
        with path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                try:
                    value = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ExtractionError(f"invalid audit JSON on line {line_number}: {exc}") from exc
                if not isinstance(value, dict):
                    raise ExtractionError(f"audit JSON line {line_number} is not an object")
                yield value
    except FileNotFoundError as exc:
        raise ExtractionError(f"audit log does not exist: {path}") from exc


def namespace_of(record: dict[str, Any]) -> str:
    object_ref = record.get("objectRef") if isinstance(record.get("objectRef"), dict) else {}
    namespace = object_ref.get("namespace")
    if namespace:
        return str(namespace)
    request_uri = str(record.get("requestURI") or "")
    marker = "/namespaces/"
    return request_uri.split(marker, 1)[1].split("/", 1)[0] if marker in request_uri else ""


def object_metadata(record: dict[str, Any]) -> dict[str, Any]:
    for key in ("requestObject", "responseObject"):
        value = record.get(key)
        if isinstance(value, dict) and isinstance(value.get("metadata"), dict):
            return value["metadata"]
    return {}


def effective_actor(record: dict[str, Any]) -> str:
    impersonated = record.get("impersonatedUser") if isinstance(record.get("impersonatedUser"), dict) else {}
    authenticated = record.get("user") if isinstance(record.get("user"), dict) else {}
    return str(impersonated.get("username") or authenticated.get("username") or "unknown")


def status_value(record: dict[str, Any]) -> tuple[int, str]:
    status = record.get("responseStatus") if isinstance(record.get("responseStatus"), dict) else {}
    try:
        code = int(status.get("code") or 0)
    except (TypeError, ValueError):
        code = 0
    reason = str(status.get("reason") or status.get("status") or "")
    return code, f"{code}:{reason}" if reason else str(code or "unknown")


def correlation_of(record: dict[str, Any]) -> str | None:
    metadata = object_metadata(record)
    annotations = metadata.get("annotations") if isinstance(metadata.get("annotations"), dict) else {}
    value = annotations.get("eacp.io/correlation-id")
    return str(value) if value else None


def annotations_of(record: dict[str, Any]) -> dict[str, Any]:
    metadata = object_metadata(record)
    return metadata.get("annotations") if isinstance(metadata.get("annotations"), dict) else {}


def object_name(record: dict[str, Any]) -> str:
    object_ref = record.get("objectRef") if isinstance(record.get("objectRef"), dict) else {}
    metadata = object_metadata(record)
    return str(object_ref.get("name") or metadata.get("name") or "unknown-object")


def object_target(record: dict[str, Any]) -> dict[str, str]:
    object_ref = record.get("objectRef") if isinstance(record.get("objectRef"), dict) else {}
    return {
        "api_group": str(object_ref.get("apiGroup") or ""),
        "resource": str(object_ref.get("resource") or ""),
        "namespace": namespace_of(record),
        "name": object_name(record),
    }


def correlation_binding(
    record: dict[str, Any],
    *,
    adapter_correlation_id: str | None = None,
    adapter_target: dict[str, str] | None = None,
) -> tuple[str | None, str]:
    native = correlation_of(record)
    if native:
        return native, "source_native_object_annotation"
    # Authorization can reject before decoding requestObject. Bind that 403 to
    # the chain only when its source-native target tuple exactly equals the
    # already correlated Deployment selected by the adapter.
    if (
        adapter_correlation_id
        and adapter_target
        and status_value(record)[0] == 403
        and object_target(record) == adapter_target
    ):
        return adapter_correlation_id, "adapter_explicit_exact_target"
    return None, "absent"


def normalize(
    record: dict[str, Any],
    namespace: str,
    *,
    adapter_correlation_id: str | None = None,
    adapter_target: dict[str, str] | None = None,
) -> dict[str, str]:
    object_ref = record.get("objectRef") if isinstance(record.get("objectRef"), dict) else {}
    metadata = object_metadata(record)
    labels = metadata.get("labels") if isinstance(metadata.get("labels"), dict) else {}
    resource = str(object_ref.get("resource") or "unknown-resource")
    name = object_name(record)
    service_name = str(labels.get("app.kubernetes.io/name") or name)
    audit_id = str(record.get("auditID") or hashlib.sha256(canonical_json(record).encode()).hexdigest())
    stage = str(record.get("stage") or "unknown-stage")
    source_ts = str(record.get("requestReceivedTimestamp") or record.get("stageTimestamp") or "")
    observed_ts = str(record.get("stageTimestamp") or source_ts)
    _, outcome = status_value(record)
    correlation, _ = correlation_binding(
        record,
        adapter_correlation_id=adapter_correlation_id,
        adapter_target=adapter_target,
    )
    correlation = correlation or f"k8s://{namespace}/{resource}/{name}"
    return {
        "source_type": "kubernetes.audit",
        "source_id": f"{audit_id}:{stage}",
        "source_ts": source_ts,
        "observed_ts": observed_ts,
        "actor": effective_actor(record),
        "service": f"{namespace}/{service_name}",
        "intent": "software_delivery",
        "policy": "kubernetes-rbac-admission",
        "action": str(record.get("verb") or "unknown"),
        "outcome": outcome,
        "source_pointer": f"kubernetes-audit://{audit_id}",
        "correlation_id": correlation,
        "content_hash": hashlib.sha256(canonical_json(record).encode("utf-8")).hexdigest(),
    }


def kubernetes_actor_reference(actor: str, cluster_id: str, namespace: str) -> dict[str, Any]:
    if actor.startswith("system:serviceaccount:"):
        actor_type = "service_account"
        scope = {"type": "namespace", "id": f"{cluster_id}/namespaces/{namespace}"}
    elif actor.startswith("system:"):
        actor_type = "system"
        scope = {"type": "cluster", "id": cluster_id}
    else:
        # Kubernetes usernames can come from certificates, OIDC, proxies, or
        # impersonation; do not infer a human solely from an opaque string.
        actor_type = "unknown"
        scope = {"type": "cluster", "id": cluster_id}
    return {"id": actor, "type": actor_type, "scope": scope}


def profile_links(
    record: dict[str, Any],
    cluster_id: str,
    *,
    adapter_correlation_id: str | None = None,
    adapter_target: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    annotations = annotations_of(record)
    links: list[dict[str, Any]] = []
    correlation, binding_method = correlation_binding(
        record,
        adapter_correlation_id=adapter_correlation_id,
        adapter_target=adapter_target,
    )
    if correlation:
        links.append(
            {
                "type": "operational_correlation",
                "value": str(correlation),
                "scope": dict(EXPERIMENT_SCOPE),
                "evidence_method": (
                    "source_native"
                    if binding_method == "source_native_object_annotation"
                    else "explicit"
                ),
            }
        )
    if binding_method == "adapter_explicit_exact_target":
        target = object_target(record)
        links.append(
            {
                "type": "custom",
                "custom_type": "kubernetes_resource_target",
                "value": (
                    f"kubernetes://{target['api_group']}/{target['resource']}"
                    f"/{target['namespace']}/{target['name']}"
                ),
                "scope": {"type": "cluster", "id": cluster_id},
                "evidence_method": "source_native",
            }
        )
    repository_id = annotations.get("eacp.io/github-repository-id")
    run_id = annotations.get("eacp.io/github-run-id")
    attempt = annotations.get("eacp.io/github-run-attempt")
    repository_scope = None
    if repository_id:
        repository_scope = {
            "type": "repository",
            "id": f"github://repositories/{repository_id}",
        }
    if repository_scope and run_id and attempt:
        links.append(
            {
                "type": "workflow_run",
                "value": (
                    f"github://repositories/{repository_id}/actions/runs/{run_id}/attempts/{attempt}"
                ),
                "scope": repository_scope,
                "evidence_method": "source_native",
            }
        )
    revision = annotations.get("eacp.io/github-commit-sha")
    if repository_scope and revision:
        links.append(
            {
                "type": "vcs_revision",
                "value": str(revision),
                "scope": repository_scope,
                "evidence_method": "source_native",
            }
        )
    subject_uri = annotations.get("eacp.io/subject-uri")
    subject_digest = annotations.get("eacp.io/subject-digest")
    if subject_uri and subject_digest:
        links.append(
            {
                "type": "artifact_digest",
                "value": str(subject_digest),
                "scope": {"type": "custom", "id": f"oci://{subject_uri}"},
                "evidence_method": "source_native",
            }
        )
    metadata = object_metadata(record)
    uid = metadata.get("uid")
    if uid:
        links.append(
            {
                "type": "deployment_uid",
                "value": str(uid),
                "scope": {"type": "cluster", "id": cluster_id},
                "evidence_method": "source_native",
            }
        )
    return links


def profile_record(
    record: dict[str, Any],
    row: dict[str, str],
    *,
    namespace: str,
    cluster_id: str,
    adapter_correlation_id: str | None = None,
    adapter_target: dict[str, str] | None = None,
) -> dict[str, Any]:
    authenticated = record.get("user") if isinstance(record.get("user"), dict) else {}
    authenticated_name = str(authenticated.get("username") or "unknown")
    effective_name = effective_actor(record)
    actors: dict[str, Any] = {
        "execution_principal": kubernetes_actor_reference(effective_name, cluster_id, namespace)
    }
    if effective_name != authenticated_name:
        actors["initiator"] = kubernetes_actor_reference(
            authenticated_name, cluster_id, namespace
        )
    object_ref = record.get("objectRef") if isinstance(record.get("objectRef"), dict) else {}
    code, _ = status_value(record)
    return {
        "profile": PROFILE_NAME,
        "source_type": row["source_type"],
        "source_id": row["source_id"],
        "source_ts": row["source_ts"],
        "observed_ts": row["observed_ts"],
        "actors": actors,
        "service": {
            "id": row["service"],
            "type": "kubernetes_resource",
            "scope": {
                "type": "namespace",
                "id": f"{cluster_id}/namespaces/{namespace}",
            },
        },
        "intent": row["intent"],
        "policy": row["policy"],
        "action": row["action"],
        "outcome": row["outcome"],
        "source_pointer": row["source_pointer"],
        "source_digest": {
            "algorithm": "sha256",
            "value": row["content_hash"],
            "representation": "sanitized_canonical_json",
            "canonicalization": (
                "UTF-8 JSON; object keys sorted; compact separators; ensure_ascii=false; "
                "EACP Kubernetes audit extractor v1.3"
            ),
        },
        "links": profile_links(
            record,
            cluster_id,
            adapter_correlation_id=adapter_correlation_id,
            adapter_target=adapter_target,
        ),
        "extensions": {
            "org.eacp/kubernetes_audit_adapter": {
                "resource": str(object_ref.get("resource") or "unknown-resource"),
                "namespace": namespace,
                "http_status": code,
                "source_native_correlation_present": correlation_of(record) is not None,
                "correlation_binding": correlation_binding(
                    record,
                    adapter_correlation_id=adapter_correlation_id,
                    adapter_target=adapter_target,
                )[1],
                "compatibility_projection_content_hash": row["content_hash"],
            }
        },
    }


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_outputs(
    audit_log: Path,
    output_dir: Path,
    *,
    namespace: str,
    correlation_id: str,
    denied_principal: str,
    denied_target_api_group: str,
    denied_target_resource: str,
    denied_target_name: str,
    negative_control_name: str,
    cluster_id: str,
) -> dict[str, Any]:
    if output_dir.exists():
        raise ExtractionError(f"refusing to overwrite output: {output_dir}")
    all_records = list(iter_records(audit_log))
    scoped = [
        record
        for record in all_records
        if namespace_of(record) == namespace
        and str(
            (record.get("objectRef") if isinstance(record.get("objectRef"), dict) else {}).get("subresource")
            or ""
        )
        != "token"
    ]
    if not scoped:
        raise ExtractionError(f"no audit records found for namespace {namespace!r}")
    sanitized = [sanitize(record) for record in scoped]
    denied_target = {
        "api_group": denied_target_api_group,
        "resource": denied_target_resource,
        "namespace": namespace,
        "name": denied_target_name,
    }
    rows = [
        normalize(
            record,
            namespace,
            adapter_correlation_id=correlation_id,
            adapter_target=denied_target,
        )
        for record in sanitized
    ]
    profile_records = [
        profile_record(
            record,
            row,
            namespace=namespace,
            cluster_id=cluster_id,
            adapter_correlation_id=correlation_id,
            adapter_target=denied_target,
        )
        for record, row in zip(sanitized, rows)
    ]
    validate_profile_records(profile_records)
    positive = [record for record in sanitized if correlation_of(record) == correlation_id]
    denial = [
        record
        for record in sanitized
        if object_target(record) == denied_target
        and effective_actor(record) == denied_principal
        and status_value(record)[0] == 403
    ]
    negative = [record for record in sanitized if object_name(record) == negative_control_name]
    negative_with_id = [record for record in negative if correlation_of(record)]
    if not positive:
        raise ExtractionError("positive control failed: no audit record contains the expected correlation ID")
    if not denial:
        target_403 = sum(
            object_target(record) == denied_target and status_value(record)[0] == 403
            for record in sanitized
        )
        principal_403 = sum(
            effective_actor(record) == denied_principal and status_value(record)[0] == 403
            for record in sanitized
        )
        native_correlation_403 = sum(
            correlation_of(record) == correlation_id and status_value(record)[0] == 403
            for record in sanitized
        )
        raise ExtractionError(
            "RBAC control failed: no HTTP 403 matched both expected principal and exact target; "
            f"target_403={target_403}, principal_403={principal_403}, "
            f"source_native_correlation_403={native_correlation_403}"
        )
    if not negative:
        raise ExtractionError("negative control failed: no audit record exists for the control object")
    if negative_with_id:
        raise ExtractionError("negative control failed: the control object unexpectedly contains a correlation ID")

    output_dir.mkdir(parents=True)
    filtered_path = output_dir / "public_filtered_audit.jsonl"
    filtered_path.write_text("".join(canonical_json(record) + "\n" for record in sanitized), encoding="utf-8")
    csv_path = output_dir / "normalized_evidence.csv"
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=EVIDENCE_HEADERS)
        writer.writeheader()
        writer.writerows(rows)
    profile_path = output_dir / "profile_records.jsonl"
    profile_path.write_text(
        "".join(canonical_json(record) + "\n" for record in profile_records),
        encoding="utf-8",
    )
    summary = {
        "experiment": "EACP v1.3 GitHub Actions to Kubernetes exact-link observation",
        "source_classification": "real_kubernetes_api_server_audit_metadata",
        "scope": {
            "namespace": namespace,
            "input_records": len(all_records),
            "namespace_records": len(sanitized),
            "evidence_rows": len(rows),
            "profile_records": len(profile_records),
            "profile": PROFILE_NAME,
            "cluster_id": cluster_id,
        },
        "positive_control": {
            "correlation_id": correlation_id,
            "matching_audit_records": len(positive),
            "principals": sorted({effective_actor(record) for record in positive}),
            "verbs": dict(sorted(Counter(str(record.get("verb") or "unknown") for record in positive).items())),
        },
        "rbac_denial": {
            "expected_principal": denied_principal,
            "expected_target": denied_target,
            "binding_method": "adapter_explicit_exact_target",
            "source_native_correlation_required": False,
            "source_native_correlation_records": sum(
                correlation_of(record) == correlation_id for record in denial
            ),
            "matching_http_403_records": len(denial),
            "validated": True,
        },
        "negative_control": {
            "object_name": negative_control_name,
            "audit_records": len(negative),
            "records_with_explicit_correlation_id": 0,
            "validated": True,
        },
        "integrity": {
            "unique_source_keys": len({(row["source_type"], row["source_id"]) for row in rows}),
            "distinct_content_hashes": len({row["content_hash"] for row in rows}),
        },
        "privacy": {
            "namespace_filtered": True,
            "source_ips_removed": True,
            "credential_identifiers_removed": True,
            "token_subresource_excluded": True,
            "complete_cluster_audit_log_retained": False,
            "manual_publication_review_required": True,
        },
        "claim_boundary": (
            "This validates exact identifier propagation and a deliberately denied operation in one isolated "
            "cluster. It does not establish production scalability, semantic causality, or artifact identity."
        ),
    }
    summary_path = output_dir / "audit_summary.json"
    summary_path.write_text(pretty_json(summary), encoding="utf-8")
    manifest_paths = [filtered_path, csv_path, profile_path, summary_path]
    (output_dir / "SHA256SUMS").write_text(
        "".join(f"{sha256(path)}  {path.name}\n" for path in sorted(manifest_paths)),
        encoding="utf-8",
    )
    return summary


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--audit-log", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--namespace", required=True)
    parser.add_argument("--correlation-id", required=True)
    parser.add_argument("--denied-principal", required=True)
    parser.add_argument("--denied-target-api-group", required=True)
    parser.add_argument("--denied-target-resource", required=True)
    parser.add_argument("--denied-target-name", required=True)
    parser.add_argument("--negative-control-name", required=True)
    parser.add_argument("--cluster-id", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        summary = write_outputs(
            args.audit_log,
            args.output_dir,
            namespace=args.namespace,
            correlation_id=args.correlation_id,
            denied_principal=args.denied_principal,
            denied_target_api_group=args.denied_target_api_group,
            denied_target_resource=args.denied_target_resource,
            denied_target_name=args.denied_target_name,
            negative_control_name=args.negative_control_name,
            cluster_id=args.cluster_id,
        )
    except ExtractionError as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 2
    sys.stdout.write(pretty_json(summary))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
