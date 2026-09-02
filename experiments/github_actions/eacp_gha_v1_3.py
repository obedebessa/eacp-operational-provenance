#!/usr/bin/env python3
"""Capture GitHub Actions metadata and project it into EACP v1.3 evidence.

The adapter intentionally uses only the Python standard library.  It can read
GitHub's REST API through ``gh`` (authenticated) or HTTPS (public repositories),
normalize exported API JSON without network access, verify a bundle, produce an
exact-ID cross-plane join report, and optionally annotate a Kubernetes
Deployment when an operator explicitly requests ``--apply``.

The adapter captures metadata, not workflow logs or artifact contents.  This is
both a privacy boundary and a precise claim boundary: an exact correlation ID
is observable evidence of a hand-off, not proof that two unrelated events have
the same cause or that an artifact deployed to Kubernetes is bit-identical.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Sequence


SCHEMA_VERSION = "eacp.github-actions.capture/1.3.0"
EVIDENCE_SCHEMA_VERSION = "eacp.evidence/1.3.0"
CAPTURE_SCHEMA_URL = (
    "https://raw.githubusercontent.com/obedebessa/eacp-operational-provenance/"
    "v1.3.0/experiments/github_actions/schema/github-actions-capture-v1.3.schema.json"
)
EVIDENCE_SCHEMA_URL = (
    "https://raw.githubusercontent.com/obedebessa/eacp-operational-provenance/"
    "v1.3.0/experiments/github_actions/schema/eacp-evidence-row-v1.3.schema.json"
)
ANNOTATION_KEY = "eacp.io/correlation-id"
DEFAULT_DEPLOYMENT = "eacp-demo"
DEFAULT_NAMESPACE = "eacp-k8s-eval"
SHA_PATTERN = re.compile(r"^[0-9a-fA-F]{40}(?:[0-9a-fA-F]{24})?$")
DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
CORRELATION_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,254}[A-Za-z0-9]$|^[A-Za-z0-9]$")
REPOSITORY_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
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
EXPECTED_BUNDLE_FILES = {
    "source/github_actions.json",
    "eacp/evidence.csv",
    "eacp/evidence.jsonl",
    "eacp/profile_records.jsonl",
    "kubernetes/annotation_merge_patch.json",
    "summary.json",
}
PROFILE_NAME = "eacp.profile/1.3"
EXPERIMENT_SCOPE = {
    "type": "custom",
    "id": "urn:eacp:experiment:github-actions-kubernetes:v1.3",
}


class AdapterError(RuntimeError):
    """Expected adapter, input, transport, or validation error."""


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def pretty_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def require_mapping(value: Any, description: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AdapterError(f"{description} must be a JSON object")
    return value


def require_list(value: Any, description: str) -> list[Any]:
    if not isinstance(value, list):
        raise AdapterError(f"{description} must be a JSON array")
    return value


def require_nonempty_string(value: Any, description: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise AdapterError(f"{description} must be a non-empty string")
    return value.strip()


def require_positive_int(value: Any, description: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise AdapterError(f"{description} must be a positive integer")
    return value


def require_fields(
    value: dict[str, Any],
    *,
    required: set[str],
    optional: set[str] | None = None,
    description: str,
) -> None:
    optional = optional or set()
    missing = sorted(required - set(value))
    unknown = sorted(set(value) - required - optional)
    if missing or unknown:
        raise AdapterError(f"{description} fields differ; missing={missing}, unknown={unknown}")


def optional_string(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def validate_rfc3339(value: Any, description: str, *, allow_null: bool = False) -> str | None:
    if value is None and allow_null:
        return None
    text = require_nonempty_string(value, description)
    try:
        datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise AdapterError(f"{description} is not an RFC 3339 timestamp: {text!r}") from exc
    return text


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def strip_url_secrets(value: Any) -> str | None:
    """Keep a source pointer while dropping credentials, queries, and fragments."""
    text = optional_string(value)
    if text is None:
        return None
    try:
        parsed = urllib.parse.urlsplit(text)
    except ValueError:
        return None
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None
    hostname = parsed.hostname.lower()
    port = f":{parsed.port}" if parsed.port else ""
    return urllib.parse.urlunsplit((parsed.scheme, hostname + port, parsed.path, "", ""))


def minimal_actor(value: Any) -> dict[str, Any]:
    actor = value if isinstance(value, dict) else {}
    result: dict[str, Any] = {
        "login": str(actor.get("login") or "unknown"),
        "id": actor.get("id") if isinstance(actor.get("id"), int) else None,
        "type": str(actor.get("type") or "unknown"),
    }
    html_url = strip_url_secrets(actor.get("html_url"))
    if html_url:
        result["html_url"] = html_url
    return result


def minimal_step(value: Any) -> dict[str, Any]:
    step = require_mapping(value, "job step")
    return {
        "number": int(step.get("number") or 0),
        "name": str(step.get("name") or "unnamed-step"),
        "status": str(step.get("status") or "unknown"),
        "conclusion": optional_string(step.get("conclusion")),
        "started_at": optional_string(step.get("started_at")),
        "completed_at": optional_string(step.get("completed_at")),
    }


def minimal_job(value: Any) -> dict[str, Any]:
    job = require_mapping(value, "job")
    result = {
        "id": require_positive_int(job.get("id"), "job.id"),
        "run_id": require_positive_int(job.get("run_id"), "job.run_id"),
        "run_attempt": int(job.get("run_attempt") or 1),
        "name": str(job.get("name") or "unnamed-job"),
        "workflow_name": str(job.get("workflow_name") or "unknown-workflow"),
        "status": str(job.get("status") or "unknown"),
        "conclusion": optional_string(job.get("conclusion")),
        "created_at": optional_string(job.get("created_at")),
        "started_at": optional_string(job.get("started_at")),
        "completed_at": optional_string(job.get("completed_at")),
        "html_url": strip_url_secrets(job.get("html_url")),
        # Labels describe execution class; runner IDs/names/groups are omitted.
        "labels": [str(item) for item in job.get("labels", []) if isinstance(item, str)],
        "steps": [minimal_step(item) for item in job.get("steps", []) if isinstance(item, dict)],
    }
    return result


def minimal_artifact(value: Any) -> dict[str, Any]:
    artifact = require_mapping(value, "artifact")
    workflow_run = artifact.get("workflow_run")
    workflow_run_id = None
    if isinstance(workflow_run, dict) and isinstance(workflow_run.get("id"), int):
        workflow_run_id = workflow_run["id"]
    return {
        "id": require_positive_int(artifact.get("id"), "artifact.id"),
        "name": str(artifact.get("name") or "unnamed-artifact"),
        "size_in_bytes": int(artifact.get("size_in_bytes") or 0),
        "expired": bool(artifact.get("expired", False)),
        "created_at": optional_string(artifact.get("created_at")),
        "updated_at": optional_string(artifact.get("updated_at")),
        "expires_at": optional_string(artifact.get("expires_at")),
        "archive_download_url": strip_url_secrets(artifact.get("archive_download_url")),
        "workflow_run_id": workflow_run_id,
    }


def derive_correlation_id(repository_id: int, run_id: int, attempt: int) -> str:
    return f"eacp-gha-{repository_id}-{run_id}-{attempt}"


def validate_correlation_id(value: str) -> str:
    if "\n" in value or "\r" in value or not CORRELATION_PATTERN.fullmatch(value):
        raise AdapterError(
            "correlation ID must be 1-256 characters using letters, digits, '.', '_', ':', '/', '+', or '-'"
        )
    return value


def build_source_snapshot(
    raw_run: dict[str, Any],
    raw_jobs: Sequence[Any],
    raw_artifacts: Sequence[Any],
    *,
    captured_at: str,
    acquisition: str,
    transport: str,
    authenticated: bool | None,
    service: str | None,
    correlation_id: str | None,
    deployment: str,
    namespace: str,
    subject_uri: str | None = None,
    subject_digest: str | None = None,
) -> dict[str, Any]:
    repository = require_mapping(raw_run.get("repository"), "run.repository")
    repository_id = require_positive_int(repository.get("id"), "run.repository.id")
    repository_name = require_nonempty_string(repository.get("full_name"), "run.repository.full_name")
    if not REPOSITORY_PATTERN.fullmatch(repository_name):
        raise AdapterError(f"invalid GitHub repository full_name: {repository_name!r}")
    run_id = require_positive_int(raw_run.get("id"), "run.id")
    attempt = require_positive_int(raw_run.get("run_attempt") or 1, "run.run_attempt")
    head_sha = require_nonempty_string(raw_run.get("head_sha"), "run.head_sha").lower()
    if not SHA_PATTERN.fullmatch(head_sha):
        raise AdapterError("run.head_sha must be a 40- or 64-character hexadecimal digest")
    resolved_correlation = validate_correlation_id(
        correlation_id or derive_correlation_id(repository_id, run_id, attempt)
    )
    resolved_service = require_nonempty_string(service or repository_name, "projection.service")
    if len(resolved_service) > 512 or any(character in resolved_service for character in "\r\n"):
        raise AdapterError("service must be at most 512 characters and contain no newlines")
    if bool(subject_uri) != bool(subject_digest):
        raise AdapterError("--subject-uri and --subject-digest must be provided together")
    resolved_subject: dict[str, str] | None = None
    if subject_uri and subject_digest:
        resolved_uri = require_nonempty_string(subject_uri, "projection.subject.uri")
        resolved_digest = require_nonempty_string(subject_digest, "projection.subject.digest").lower()
        if any(character in resolved_uri for character in "\r\n") or len(resolved_uri) > 1024:
            raise AdapterError("subject URI must be at most 1024 characters and contain no newlines")
        if not DIGEST_PATTERN.fullmatch(resolved_digest):
            raise AdapterError("subject digest must use sha256:<64 lowercase hexadecimal characters>")
        resolved_subject = {"uri": resolved_uri, "digest": resolved_digest}

    run = {
        "id": run_id,
        "node_id": optional_string(raw_run.get("node_id")),
        "run_number": int(raw_run.get("run_number") or 0),
        "run_attempt": attempt,
        "workflow_id": int(raw_run.get("workflow_id") or 0),
        "name": str(raw_run.get("name") or "unknown-workflow"),
        "path": optional_string(raw_run.get("path")),
        "event": str(raw_run.get("event") or "unknown"),
        "status": str(raw_run.get("status") or "unknown"),
        "conclusion": optional_string(raw_run.get("conclusion")),
        "head_branch": optional_string(raw_run.get("head_branch")),
        "head_sha": head_sha,
        "created_at": require_nonempty_string(raw_run.get("created_at"), "run.created_at"),
        "run_started_at": optional_string(raw_run.get("run_started_at")),
        "updated_at": require_nonempty_string(raw_run.get("updated_at"), "run.updated_at"),
        "html_url": strip_url_secrets(raw_run.get("html_url")),
        "api_url": strip_url_secrets(raw_run.get("url")),
        "jobs_url": strip_url_secrets(raw_run.get("jobs_url")),
        "artifacts_url": strip_url_secrets(raw_run.get("artifacts_url")),
        "actor": minimal_actor(raw_run.get("actor")),
        "triggering_actor": minimal_actor(raw_run.get("triggering_actor")),
    }
    for field in ("created_at", "run_started_at", "updated_at"):
        validate_rfc3339(run[field], f"run.{field}", allow_null=field == "run_started_at")
    if not run["html_url"]:
        raise AdapterError("run.html_url must be a valid HTTP(S) source URL")

    jobs = sorted((minimal_job(item) for item in raw_jobs), key=lambda item: item["id"])
    artifacts = sorted((minimal_artifact(item) for item in raw_artifacts), key=lambda item: item["id"])
    for job in jobs:
        if job["run_id"] != run_id:
            raise AdapterError(f"job {job['id']} belongs to run {job['run_id']}, not {run_id}")
        if job["run_attempt"] != attempt:
            raise AdapterError(
                f"job {job['id']} belongs to attempt {job['run_attempt']}, not {attempt}"
            )
        for field in ("created_at", "started_at", "completed_at"):
            validate_rfc3339(job[field], f"job {job['id']}.{field}", allow_null=True)
    for artifact in artifacts:
        linked_run = artifact.get("workflow_run_id")
        if linked_run is not None and linked_run != run_id:
            raise AdapterError(f"artifact {artifact['id']} belongs to run {linked_run}, not {run_id}")
        for field in ("created_at", "updated_at", "expires_at"):
            validate_rfc3339(artifact[field], f"artifact {artifact['id']}.{field}", allow_null=True)

    return {
        "$schema": CAPTURE_SCHEMA_URL,
        "schema_version": SCHEMA_VERSION,
        "capture": {
            "acquisition": acquisition,
            "transport": transport,
            "authenticated": authenticated,
            "captured_at": validate_rfc3339(captured_at, "capture.captured_at"),
            "sanitization_profile": "public-metadata-minimal-v1",
            "raw_api_payload_retained": False,
            "excluded": [
                "workflow logs",
                "artifact contents",
                "event payload",
                "commit messages and author emails",
                "runner identifiers and runner group names",
                "URL credentials, query parameters, and fragments",
            ],
        },
        "repository": {
            "id": repository_id,
            "full_name": repository_name,
            "private": bool(repository.get("private", False)),
            "html_url": strip_url_secrets(repository.get("html_url")),
        },
        "run": run,
        "jobs": jobs,
        "artifacts": artifacts,
        "projection": {
            "schema_version": EVIDENCE_SCHEMA_VERSION,
            "service": resolved_service,
            "intent": "software_delivery",
            "correlation_id": resolved_correlation,
            "correlation_derivation": (
                "operator-supplied" if correlation_id else "repository-id + run-id + run-attempt"
            ),
            "kubernetes_target": {
                "resource": "deployment",
                "name": require_nonempty_string(deployment, "deployment"),
                "namespace": require_nonempty_string(namespace, "namespace"),
                "annotation_key": ANNOTATION_KEY,
            },
            "subject": resolved_subject,
        },
    }


def source_record_hash(record_type: str, value: dict[str, Any]) -> str:
    payload = canonical_json({"record_type": record_type, "record": value}).encode("utf-8")
    return sha256_bytes(payload)


def load_profile_validator() -> Any:
    tool_path = Path(__file__).resolve().parents[2] / "spec/tools/eacp_profile.py"
    if not tool_path.is_file():
        raise AdapterError(f"EACP Profile 1.3 reference validator is missing: {tool_path}")
    specification = importlib.util.spec_from_file_location("eacp_profile_v1_3", tool_path)
    if specification is None or specification.loader is None:
        raise AdapterError(f"cannot load EACP Profile 1.3 validator: {tool_path}")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def validate_profile_records(records: Sequence[dict[str, Any]]) -> None:
    validator = load_profile_validator()
    errors = validator.validate_collection(records)
    if errors:
        raise AdapterError("EACP Profile 1.3 validation failed: " + "; ".join(errors))


def github_actor_reference(actor_value: Any) -> dict[str, Any] | None:
    actor = actor_value if isinstance(actor_value, dict) else {}
    login = str(actor.get("login") or "")
    actor_id = actor.get("id")
    if not login or login == "unknown":
        return None
    native_type = str(actor.get("type") or "unknown").lower()
    if native_type == "user":
        actor_type = "human"
    elif native_type in {"bot", "app"}:
        actor_type = "automation"
    else:
        actor_type = "unknown"
    scoped_id = str(actor_id) if isinstance(actor_id, int) else login
    return {
        "id": login,
        "type": actor_type,
        "scope": {"type": "account", "id": f"github://accounts/{scoped_id}"},
    }


def github_links(
    snapshot: dict[str, Any], *, include_subject: bool, record_type: str
) -> list[dict[str, Any]]:
    repository_id = snapshot["repository"]["id"]
    run = snapshot["run"]
    repository_scope = {
        "type": "repository",
        "id": f"github://repositories/{repository_id}",
    }
    workflow_run = (
        f"github://repositories/{repository_id}/actions/runs/{run['id']}"
        f"/attempts/{run['run_attempt']}"
    )
    links: list[dict[str, Any]] = [
        {
            "type": "operational_correlation",
            "value": snapshot["projection"]["correlation_id"],
            "scope": dict(EXPERIMENT_SCOPE),
            "evidence_method": "explicit",
        },
        {
            "type": "workflow_run",
            "value": workflow_run,
            "scope": repository_scope,
            "evidence_method": "source_native",
        },
        {
            "type": "vcs_revision",
            "value": run["head_sha"],
            "scope": repository_scope,
            "evidence_method": "source_native" if record_type == "run" else "explicit",
        },
    ]
    subject = snapshot["projection"].get("subject")
    if include_subject and isinstance(subject, dict):
        links.append(
            {
                "type": "artifact_digest",
                "value": subject["digest"],
                "scope": {"type": "custom", "id": f"oci://{subject['uri']}"},
                "evidence_method": "explicit",
            }
        )
    return links


def project_profile_records(
    snapshot: dict[str, Any], rows: Sequence[dict[str, str]] | None = None
) -> list[dict[str, Any]]:
    compatibility_rows = list(rows) if rows is not None else project_evidence(snapshot)
    run = snapshot["run"]
    repository_id = snapshot["repository"]["id"]
    repository_scope = {
        "type": "repository",
        "id": f"github://repositories/{repository_id}",
    }
    actors: dict[str, Any] = {}
    initiator = github_actor_reference(run.get("actor"))
    triggering = github_actor_reference(run.get("triggering_actor"))
    if initiator:
        actors["initiator"] = initiator
    if triggering:
        actors["triggering_actor"] = triggering
    actors["execution_principal"] = {
        "id": "github-actions",
        "type": "automation",
        "scope": repository_scope,
    }
    source_objects: dict[tuple[str, str], tuple[str, dict[str, Any]]] = {
        ("github.actions.run", compatibility_rows[0]["source_id"]): ("run", run)
    }
    for job in snapshot["jobs"]:
        source_id = next(
            row["source_id"]
            for row in compatibility_rows
            if row["source_type"] == "github.actions.job"
            and row["source_id"].endswith(f"/jobs/{job['id']}")
        )
        source_objects[("github.actions.job", source_id)] = ("job", job)
    for artifact in snapshot["artifacts"]:
        source_id = next(
            row["source_id"]
            for row in compatibility_rows
            if row["source_type"] == "github.actions.artifact"
            and row["source_id"].endswith(f"/artifacts/{artifact['id']}")
        )
        source_objects[("github.actions.artifact", source_id)] = ("artifact", artifact)

    records: list[dict[str, Any]] = []
    for row in compatibility_rows:
        record_type, source_object = source_objects[(row["source_type"], row["source_id"])]
        records.append(
            {
                "profile": PROFILE_NAME,
                "source_type": row["source_type"],
                "source_id": row["source_id"],
                "source_ts": row["source_ts"],
                "observed_ts": row["observed_ts"],
                "actors": json.loads(canonical_json(actors)),
                "service": {
                    "id": snapshot["repository"]["full_name"],
                    "type": "repository",
                    "scope": repository_scope,
                },
                "intent": row["intent"],
                "policy": row["policy"],
                "action": row["action"],
                "outcome": row["outcome"],
                "source_pointer": row["source_pointer"],
                "source_digest": {
                    "algorithm": "sha256",
                    "value": source_record_hash(record_type, source_object),
                    "representation": "sanitized_canonical_json",
                    "canonicalization": (
                        "UTF-8 JSON of {record_type,record}; object keys sorted; compact separators; "
                        "ensure_ascii=false; EACP GitHub Actions adapter v1.3"
                    ),
                },
                "links": github_links(
                    snapshot,
                    include_subject=row["source_type"] != "github.actions.artifact",
                    record_type=record_type,
                ),
                "extensions": {
                    "org.eacp/github_actions_adapter": {
                        "record_type": record_type,
                        "compatibility_projection_content_hash": row["content_hash"],
                        "capture_acquisition": snapshot["capture"]["acquisition"],
                    }
                },
            }
        )
    validate_profile_records(records)
    return records


def outcome(status: str, conclusion: str | None) -> str:
    return f"conclusion:{conclusion}" if conclusion else f"status:{status}"


def project_evidence(snapshot: dict[str, Any]) -> list[dict[str, str]]:
    repo = require_mapping(snapshot.get("repository"), "snapshot.repository")
    run = require_mapping(snapshot.get("run"), "snapshot.run")
    projection = require_mapping(snapshot.get("projection"), "snapshot.projection")
    repository_id = require_positive_int(repo.get("id"), "repository.id")
    run_id = require_positive_int(run.get("id"), "run.id")
    attempt = require_positive_int(run.get("run_attempt"), "run.run_attempt")
    prefix = f"github://repositories/{repository_id}/actions/runs/{run_id}/attempts/{attempt}"
    policy = f"github-actions:{run.get('path') or run.get('name') or 'unknown-workflow'}"
    actor = str(require_mapping(run.get("actor"), "run.actor").get("login") or "unknown")
    captured_at = str(
        require_mapping(snapshot.get("capture"), "snapshot.capture").get("captured_at") or ""
    )
    correlation_id = require_nonempty_string(projection.get("correlation_id"), "projection.correlation_id")
    service = require_nonempty_string(projection.get("service"), "projection.service")
    intent = require_nonempty_string(projection.get("intent"), "projection.intent")
    rows: list[dict[str, str]] = []

    rows.append(
        {
            "$schema": EVIDENCE_SCHEMA_URL,
            "source_type": "github.actions.run",
            "source_id": prefix,
            "source_ts": str(run.get("run_started_at") or run.get("created_at") or ""),
            "observed_ts": captured_at,
            "actor": actor,
            "service": service,
            "intent": intent,
            "policy": policy,
            "action": "execute_workflow",
            "outcome": outcome(str(run.get("status") or "unknown"), optional_string(run.get("conclusion"))),
            "source_pointer": str(run.get("html_url") or ""),
            "correlation_id": correlation_id,
            "content_hash": source_record_hash("run", run),
        }
    )

    for job_value in require_list(snapshot.get("jobs"), "snapshot.jobs"):
        job = require_mapping(job_value, "job")
        job_id = require_positive_int(job.get("id"), "job.id")
        rows.append(
            {
                "$schema": EVIDENCE_SCHEMA_URL,
                "source_type": "github.actions.job",
                "source_id": f"{prefix}/jobs/{job_id}",
                "source_ts": str(job.get("started_at") or job.get("created_at") or run.get("created_at") or ""),
                "observed_ts": captured_at,
                "actor": actor,
                "service": service,
                "intent": intent,
                "policy": policy,
                "action": "execute_job",
                "outcome": outcome(str(job.get("status") or "unknown"), optional_string(job.get("conclusion"))),
                "source_pointer": str(job.get("html_url") or run.get("html_url") or ""),
                "correlation_id": correlation_id,
                "content_hash": source_record_hash("job", job),
            }
        )

    for artifact_value in require_list(snapshot.get("artifacts"), "snapshot.artifacts"):
        artifact = require_mapping(artifact_value, "artifact")
        artifact_id = require_positive_int(artifact.get("id"), "artifact.id")
        rows.append(
            {
                "$schema": EVIDENCE_SCHEMA_URL,
                "source_type": "github.actions.artifact",
                "source_id": f"{prefix}/artifacts/{artifact_id}",
                "source_ts": str(artifact.get("created_at") or run.get("updated_at") or ""),
                "observed_ts": captured_at,
                "actor": actor,
                "service": service,
                "intent": intent,
                "policy": policy,
                "action": "publish_artifact",
                "outcome": "expired" if artifact.get("expired") else "available_at_capture",
                "source_pointer": str(artifact.get("archive_download_url") or run.get("html_url") or ""),
                "correlation_id": correlation_id,
                "content_hash": source_record_hash("artifact", artifact),
            }
        )

    seen: set[tuple[str, str]] = set()
    for index, row in enumerate(rows):
        missing = [field for field in EVIDENCE_HEADERS if not str(row.get(field, ""))]
        if missing:
            raise AdapterError(f"projected row {index} has empty required fields: {', '.join(missing)}")
        validate_rfc3339(row["source_ts"], f"evidence[{index}].source_ts")
        validate_rfc3339(row["observed_ts"], f"evidence[{index}].observed_ts")
        key = (row["source_type"], row["source_id"])
        if key in seen:
            raise AdapterError(f"duplicate projected source key: {key}")
        seen.add(key)
    return rows


def kubernetes_patch(snapshot: dict[str, Any]) -> dict[str, Any]:
    repo = require_mapping(snapshot["repository"], "repository")
    run = require_mapping(snapshot["run"], "run")
    projection = require_mapping(snapshot["projection"], "projection")
    annotations = {
        ANNOTATION_KEY: str(projection["correlation_id"]),
        "eacp.io/source-plane": "github-actions",
        "eacp.io/github-repository": str(repo["full_name"]),
        "eacp.io/github-repository-id": str(repo["id"]),
        "eacp.io/github-run-id": str(run["id"]),
        "eacp.io/github-run-attempt": str(run["run_attempt"]),
        "eacp.io/github-commit-sha": str(run["head_sha"]),
        "eacp.io/github-workflow": str(run["name"]),
        "eacp.io/github-source-url": str(run["html_url"]),
    }
    subject = projection.get("subject")
    if isinstance(subject, dict):
        annotations["eacp.io/subject-uri"] = str(subject["uri"])
        annotations["eacp.io/subject-digest"] = str(subject["digest"])
    return {
        "metadata": {
            "annotations": annotations
        }
    }


def source_classification(snapshot: dict[str, Any]) -> str:
    acquisition = require_mapping(snapshot.get("capture"), "capture").get("acquisition")
    if acquisition == "github-rest-api":
        return "real_github_actions_api_metadata"
    return "imported_api_metadata_authenticity_not_established_by_adapter"


def build_summary(snapshot: dict[str, Any], rows: list[dict[str, str]]) -> dict[str, Any]:
    capture = require_mapping(snapshot["capture"], "capture")
    repo = require_mapping(snapshot["repository"], "repository")
    run = require_mapping(snapshot["run"], "run")
    projection = require_mapping(snapshot["projection"], "projection")
    counts: dict[str, int] = {}
    for row in rows:
        counts[row["source_type"]] = counts.get(row["source_type"], 0) + 1
    return {
        "experiment": "EACP v1.3 GitHub Actions metadata adapter",
        "schema_version": SCHEMA_VERSION,
        "source_classification": source_classification(snapshot),
        "source": {
            "repository": repo["full_name"],
            "run_id": run["id"],
            "run_attempt": run["run_attempt"],
            "workflow": run["name"],
            "commit_sha": run["head_sha"],
            "actor": require_mapping(run["actor"], "actor")["login"],
            "source_url": run["html_url"],
            "captured_at": capture["captured_at"],
            "transport": capture["transport"],
        },
        "projection": {
            "correlation_id": projection["correlation_id"],
            "service": projection["service"],
            "evidence_rows": len(rows),
            "rows_by_source_type": dict(sorted(counts.items())),
            "all_rows_share_exact_correlation_id": all(
                row["correlation_id"] == projection["correlation_id"] for row in rows
            ),
            "unique_source_keys": len({(row["source_type"], row["source_id"]) for row in rows}),
            "subject": projection.get("subject"),
            "profile_records": len(rows),
            "profile": PROFILE_NAME,
            "typed_link_types": [
                "operational_correlation",
                "workflow_run",
                "vcs_revision",
                *( ["artifact_digest"] if projection.get("subject") else [] ),
            ],
        },
        "kubernetes_handoff": {
            "annotation_key": ANNOTATION_KEY,
            "annotation_value": projection["correlation_id"],
            "target": projection["kubernetes_target"],
            "status": "patch_generated_not_observed",
            "verification_requires": (
                "Apply the generated merge patch to the intended Deployment, capture Kubernetes "
                "object or audit evidence, then run the join command."
            ),
        },
        "privacy": {
            "raw_api_payload_retained": False,
            "workflow_logs_retained": False,
            "artifact_contents_retained": False,
            "event_payload_retained": False,
            "actor_login_retained": True,
            "repository_identity_retained": True,
            "manual_publication_review_required": True,
        },
        "claim_boundary": [
            "The adapter records GitHub REST API metadata; it does not independently authenticate GitHub's statements.",
            "The generated Kubernetes patch is a proposed hand-off until matching Kubernetes evidence is observed.",
            "Exact correlation-ID equality establishes an observable link, not semantic causality or artifact identity.",
            "Fixtures under tests/ exercise code paths only and are never empirical observations.",
        ],
    }


def write_csv(path: Path, rows: Sequence[dict[str, str]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=EVIDENCE_HEADERS, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row[field] for field in EVIDENCE_HEADERS})


def write_manifest(root: Path) -> None:
    lines = [f"{sha256_path(root / relative)}  {relative}\n" for relative in sorted(EXPECTED_BUNDLE_FILES)]
    (root / "SHA256SUMS").write_text("".join(lines), encoding="utf-8")


def write_bundle(snapshot: dict[str, Any], output_dir: Path) -> dict[str, Any]:
    if output_dir.exists():
        raise AdapterError(f"refusing to overwrite existing output: {output_dir}")
    output_dir.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=f".{output_dir.name}-", dir=output_dir.parent))
    try:
        (temporary / "source").mkdir()
        (temporary / "eacp").mkdir()
        (temporary / "kubernetes").mkdir()
        rows = project_evidence(snapshot)
        profile_records = project_profile_records(snapshot, rows)
        (temporary / "source/github_actions.json").write_text(pretty_json(snapshot), encoding="utf-8")
        write_csv(temporary / "eacp/evidence.csv", rows)
        (temporary / "eacp/evidence.jsonl").write_text(
            "".join(canonical_json(row) + "\n" for row in rows), encoding="utf-8"
        )
        (temporary / "eacp/profile_records.jsonl").write_text(
            "".join(canonical_json(record) + "\n" for record in profile_records),
            encoding="utf-8",
        )
        (temporary / "kubernetes/annotation_merge_patch.json").write_text(
            pretty_json(kubernetes_patch(snapshot)), encoding="utf-8"
        )
        summary = build_summary(snapshot, rows)
        (temporary / "summary.json").write_text(pretty_json(summary), encoding="utf-8")
        write_manifest(temporary)
        validate_bundle(temporary)
        temporary.rename(output_dir)
        return summary
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise


def read_manifest(root: Path) -> dict[str, str]:
    manifest_path = root / "SHA256SUMS"
    if not manifest_path.is_file():
        raise AdapterError("bundle is missing SHA256SUMS")
    entries: dict[str, str] = {}
    for line_number, line in enumerate(manifest_path.read_text(encoding="utf-8").splitlines(), start=1):
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        if not match:
            raise AdapterError(f"invalid SHA256SUMS line {line_number}")
        digest, relative = match.groups()
        pure = PurePosixPath(relative)
        if pure.is_absolute() or ".." in pure.parts or relative in entries:
            raise AdapterError(f"unsafe or duplicate manifest path: {relative!r}")
        entries[relative] = digest
    if set(entries) != EXPECTED_BUNDLE_FILES:
        missing = sorted(EXPECTED_BUNDLE_FILES - set(entries))
        extra = sorted(set(entries) - EXPECTED_BUNDLE_FILES)
        raise AdapterError(f"manifest file set mismatch; missing={missing}, extra={extra}")
    return entries


def load_json(path: Path, description: str = "JSON") -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise AdapterError(f"{description} file does not exist: {path}") from exc
    except json.JSONDecodeError as exc:
        raise AdapterError(f"invalid {description} in {path}: {exc}") from exc


def read_csv_rows(path: Path) -> list[dict[str, str]]:
    try:
        with path.open("r", encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            if reader.fieldnames != EVIDENCE_HEADERS:
                raise AdapterError(
                    f"unexpected CSV headers in {path}: {reader.fieldnames}; expected {EVIDENCE_HEADERS}"
                )
            return [{field: str(row[field]) for field in EVIDENCE_HEADERS} for row in reader]
    except FileNotFoundError as exc:
        raise AdapterError(f"CSV file does not exist: {path}") from exc


def validate_snapshot(snapshot: dict[str, Any]) -> None:
    require_fields(
        snapshot,
        required={
            "$schema",
            "schema_version",
            "capture",
            "repository",
            "run",
            "jobs",
            "artifacts",
            "projection",
        },
        description="source snapshot",
    )
    if snapshot.get("$schema") != CAPTURE_SCHEMA_URL:
        raise AdapterError("source snapshot $schema does not identify the v1.3 capture schema")
    if snapshot.get("schema_version") != SCHEMA_VERSION:
        raise AdapterError(f"unsupported schema_version: {snapshot.get('schema_version')!r}")
    capture = require_mapping(snapshot.get("capture"), "capture")
    require_fields(
        capture,
        required={
            "acquisition",
            "transport",
            "authenticated",
            "captured_at",
            "sanitization_profile",
            "raw_api_payload_retained",
            "excluded",
        },
        description="capture",
    )
    if capture.get("acquisition") not in {
        "github-rest-api",
        "imported-api-json",
        "imported-actions-artifact",
    }:
        raise AdapterError("capture.acquisition is unsupported")
    require_nonempty_string(capture.get("transport"), "capture.transport")
    if capture.get("authenticated") not in {True, False, None}:
        raise AdapterError("capture.authenticated must be boolean or null")
    if capture.get("sanitization_profile") != "public-metadata-minimal-v1":
        raise AdapterError("capture.sanitization_profile is unsupported")
    excluded = require_list(capture.get("excluded"), "capture.excluded")
    if not excluded or not all(isinstance(item, str) and item for item in excluded):
        raise AdapterError("capture.excluded must contain non-empty strings")
    validate_rfc3339(capture.get("captured_at"), "capture.captured_at")
    if capture.get("raw_api_payload_retained") is not False:
        raise AdapterError("raw_api_payload_retained must be false for this public-minimal profile")
    repo = require_mapping(snapshot.get("repository"), "repository")
    require_fields(
        repo,
        required={"id", "full_name", "private", "html_url"},
        description="repository",
    )
    require_positive_int(repo.get("id"), "repository.id")
    repository_name = require_nonempty_string(repo.get("full_name"), "repository.full_name")
    if not REPOSITORY_PATTERN.fullmatch(repository_name):
        raise AdapterError("repository.full_name is invalid")
    if repo.get("private") not in {True, False}:
        raise AdapterError("repository.private must be boolean")
    if repo.get("html_url") is not None and strip_url_secrets(repo.get("html_url")) != repo.get("html_url"):
        raise AdapterError("repository.html_url must be a sanitized HTTP(S) URL")
    run = require_mapping(snapshot.get("run"), "run")
    require_fields(
        run,
        required={
            "id",
            "node_id",
            "run_number",
            "run_attempt",
            "workflow_id",
            "name",
            "path",
            "event",
            "status",
            "conclusion",
            "head_branch",
            "head_sha",
            "created_at",
            "run_started_at",
            "updated_at",
            "html_url",
            "api_url",
            "jobs_url",
            "artifacts_url",
            "actor",
            "triggering_actor",
        },
        description="run",
    )
    require_positive_int(run.get("id"), "run.id")
    require_positive_int(run.get("run_attempt"), "run.run_attempt")
    sha = require_nonempty_string(run.get("head_sha"), "run.head_sha")
    if not SHA_PATTERN.fullmatch(sha):
        raise AdapterError("run.head_sha is invalid")
    validate_rfc3339(run.get("created_at"), "run.created_at")
    validate_rfc3339(run.get("updated_at"), "run.updated_at")
    validate_rfc3339(run.get("run_started_at"), "run.run_started_at", allow_null=True)
    for url_field in ("html_url", "api_url", "jobs_url", "artifacts_url"):
        url = run.get(url_field)
        if url is None and url_field == "html_url":
            raise AdapterError("run.html_url must not be null")
        if url is not None and strip_url_secrets(url) != url:
            raise AdapterError(f"run.{url_field} must be a sanitized HTTP(S) URL")
    actor_fields = {"login", "id", "type"}
    for actor_name in ("actor", "triggering_actor"):
        actor = require_mapping(run.get(actor_name), f"run.{actor_name}")
        require_fields(
            actor,
            required=actor_fields,
            optional={"html_url"},
            description=f"run.{actor_name}",
        )
        require_nonempty_string(actor.get("login"), f"run.{actor_name}.login")
        if actor.get("id") is not None and not isinstance(actor.get("id"), int):
            raise AdapterError(f"run.{actor_name}.id must be integer or null")
        if actor.get("html_url") is not None and strip_url_secrets(actor.get("html_url")) != actor.get("html_url"):
            raise AdapterError(f"run.{actor_name}.html_url must be sanitized")
    jobs = require_list(snapshot.get("jobs"), "jobs")
    for index, job_value in enumerate(jobs):
        job = require_mapping(job_value, f"jobs[{index}]")
        require_fields(
            job,
            required={
                "id",
                "run_id",
                "run_attempt",
                "name",
                "workflow_name",
                "status",
                "conclusion",
                "created_at",
                "started_at",
                "completed_at",
                "html_url",
                "labels",
                "steps",
            },
            description=f"jobs[{index}]",
        )
        require_positive_int(job.get("id"), f"jobs[{index}].id")
        if job.get("run_id") != run.get("id") or job.get("run_attempt") != run.get("run_attempt"):
            raise AdapterError(f"jobs[{index}] run identity differs from the source run")
        for timestamp in ("created_at", "started_at", "completed_at"):
            validate_rfc3339(job.get(timestamp), f"jobs[{index}].{timestamp}", allow_null=True)
        if job.get("html_url") is not None and strip_url_secrets(job.get("html_url")) != job.get("html_url"):
            raise AdapterError(f"jobs[{index}].html_url must be sanitized")
        require_list(job.get("labels"), f"jobs[{index}].labels")
        steps = require_list(job.get("steps"), f"jobs[{index}].steps")
        for step_index, step_value in enumerate(steps):
            step = require_mapping(step_value, f"jobs[{index}].steps[{step_index}]")
            require_fields(
                step,
                required={"number", "name", "status", "conclusion", "started_at", "completed_at"},
                description=f"jobs[{index}].steps[{step_index}]",
            )
            for timestamp in ("started_at", "completed_at"):
                validate_rfc3339(
                    step.get(timestamp),
                    f"jobs[{index}].steps[{step_index}].{timestamp}",
                    allow_null=True,
                )
    artifacts = require_list(snapshot.get("artifacts"), "artifacts")
    for index, artifact_value in enumerate(artifacts):
        artifact = require_mapping(artifact_value, f"artifacts[{index}]")
        require_fields(
            artifact,
            required={
                "id",
                "name",
                "size_in_bytes",
                "expired",
                "created_at",
                "updated_at",
                "expires_at",
                "archive_download_url",
                "workflow_run_id",
            },
            description=f"artifacts[{index}]",
        )
        require_positive_int(artifact.get("id"), f"artifacts[{index}].id")
        linked_run = artifact.get("workflow_run_id")
        if linked_run is not None and linked_run != run.get("id"):
            raise AdapterError(f"artifacts[{index}] run identity differs from the source run")
        for timestamp in ("created_at", "updated_at", "expires_at"):
            validate_rfc3339(
                artifact.get(timestamp), f"artifacts[{index}].{timestamp}", allow_null=True
            )
        artifact_url = artifact.get("archive_download_url")
        if artifact_url is not None and strip_url_secrets(artifact_url) != artifact_url:
            raise AdapterError(f"artifacts[{index}].archive_download_url must be sanitized")
    projection = require_mapping(snapshot.get("projection"), "projection")
    require_fields(
        projection,
        required={
            "schema_version",
            "service",
            "intent",
            "correlation_id",
            "correlation_derivation",
            "kubernetes_target",
            "subject",
        },
        description="projection",
    )
    if projection.get("schema_version") != EVIDENCE_SCHEMA_VERSION:
        raise AdapterError("projection.schema_version is unsupported")
    if projection.get("intent") != "software_delivery":
        raise AdapterError("projection.intent is unsupported")
    require_nonempty_string(projection.get("service"), "projection.service")
    if projection.get("correlation_derivation") not in {
        "repository-id + run-id + run-attempt",
        "operator-supplied",
    }:
        raise AdapterError("projection.correlation_derivation is unsupported")
    target = require_mapping(projection.get("kubernetes_target"), "projection.kubernetes_target")
    require_fields(
        target,
        required={"resource", "name", "namespace", "annotation_key"},
        description="projection.kubernetes_target",
    )
    if target.get("resource") != "deployment" or target.get("annotation_key") != ANNOTATION_KEY:
        raise AdapterError("projection Kubernetes target type or annotation key is unsupported")
    require_nonempty_string(target.get("name"), "projection.kubernetes_target.name")
    require_nonempty_string(target.get("namespace"), "projection.kubernetes_target.namespace")
    validate_correlation_id(
        require_nonempty_string(projection.get("correlation_id"), "projection.correlation_id")
    )
    subject = projection.get("subject")
    if subject is not None:
        subject_mapping = require_mapping(subject, "projection.subject")
        require_fields(
            subject_mapping,
            required={"uri", "digest"},
            description="projection.subject",
        )
        require_nonempty_string(subject_mapping.get("uri"), "projection.subject.uri")
        digest = require_nonempty_string(subject_mapping.get("digest"), "projection.subject.digest")
        if not DIGEST_PATTERN.fullmatch(digest):
            raise AdapterError("projection.subject.digest is invalid")
    project_evidence(snapshot)


def validate_bundle(root: Path) -> dict[str, Any]:
    root = root.resolve()
    if not root.is_dir():
        raise AdapterError(f"bundle directory does not exist: {root}")
    entries = read_manifest(root)
    for relative, expected_digest in entries.items():
        path = root / relative
        if not path.is_file() or path.is_symlink():
            raise AdapterError(f"manifest target is missing, not a file, or a symlink: {relative}")
        actual_digest = sha256_path(path)
        if actual_digest != expected_digest:
            raise AdapterError(
                f"checksum mismatch for {relative}: expected {expected_digest}, observed {actual_digest}"
            )
    snapshot = require_mapping(load_json(root / "source/github_actions.json"), "source snapshot")
    validate_snapshot(snapshot)
    expected_rows = project_evidence(snapshot)
    jsonl_rows: list[dict[str, Any]] = []
    for line_number, line in enumerate(
        (root / "eacp/evidence.jsonl").read_text(encoding="utf-8").splitlines(), start=1
    ):
        try:
            jsonl_rows.append(require_mapping(json.loads(line), f"JSONL row {line_number}"))
        except json.JSONDecodeError as exc:
            raise AdapterError(f"invalid JSONL row {line_number}: {exc}") from exc
    if jsonl_rows != expected_rows:
        raise AdapterError("JSONL evidence does not equal deterministic projection from the source snapshot")
    expected_profile_records = project_profile_records(snapshot, expected_rows)
    actual_profile_records: list[dict[str, Any]] = []
    for line_number, line in enumerate(
        (root / "eacp/profile_records.jsonl").read_text(encoding="utf-8").splitlines(), start=1
    ):
        try:
            actual_profile_records.append(
                require_mapping(json.loads(line), f"profile JSONL row {line_number}")
            )
        except json.JSONDecodeError as exc:
            raise AdapterError(f"invalid profile JSONL row {line_number}: {exc}") from exc
    validate_profile_records(actual_profile_records)
    if actual_profile_records != expected_profile_records:
        raise AdapterError("Profile 1.3 evidence does not equal deterministic source projection")
    csv_rows = read_csv_rows(root / "eacp/evidence.csv")
    expected_csv = [{field: row[field] for field in EVIDENCE_HEADERS} for row in expected_rows]
    if csv_rows != expected_csv:
        raise AdapterError("CSV evidence does not equal deterministic projection from the source snapshot")
    expected_patch = kubernetes_patch(snapshot)
    actual_patch = load_json(root / "kubernetes/annotation_merge_patch.json", "Kubernetes patch")
    if actual_patch != expected_patch:
        raise AdapterError("Kubernetes patch does not match the source snapshot")
    expected_summary = build_summary(snapshot, expected_rows)
    actual_summary = load_json(root / "summary.json", "summary")
    if actual_summary != expected_summary:
        raise AdapterError("summary does not match the deterministic source projection")
    return {
        "valid": True,
        "schema_version": SCHEMA_VERSION,
        "bundle": str(root),
        "verified_files": len(entries),
        "evidence_rows": len(expected_rows),
        "correlation_id": snapshot["projection"]["correlation_id"],
        "source_classification": source_classification(snapshot),
    }


class GitHubTransport:
    def __init__(self, mode: str) -> None:
        if mode not in {"auto", "gh", "public-http"}:
            raise AdapterError(f"unknown transport: {mode}")
        gh_available = shutil.which("gh") is not None
        authenticated = False
        if gh_available:
            environment = os.environ.copy()
            check = subprocess.run(
                ["gh", "auth", "status"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                env=environment,
            )
            authenticated = check.returncode == 0 or bool(environment.get("GH_TOKEN"))
        if mode == "gh" and not gh_available:
            raise AdapterError("--transport gh requested but gh is not installed")
        if mode == "gh" and not authenticated:
            raise AdapterError("--transport gh requested but gh is not authenticated and GH_TOKEN is unset")
        self.mode = "gh" if (mode == "gh" or (mode == "auto" and authenticated)) else "public-http"
        self.authenticated = self.mode == "gh"

    def get(self, endpoint: str) -> dict[str, Any]:
        if not endpoint.startswith("repos/"):
            raise AdapterError(f"refusing unexpected GitHub API endpoint: {endpoint}")
        if self.mode == "gh":
            completed = subprocess.run(
                [
                    "gh",
                    "api",
                    "--method",
                    "GET",
                    "-H",
                    "Accept: application/vnd.github+json",
                    "-H",
                    "X-GitHub-Api-Version: 2022-11-28",
                    endpoint,
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            if completed.returncode != 0:
                message = completed.stderr.strip().splitlines()[-1] if completed.stderr.strip() else "unknown error"
                raise AdapterError(f"gh api failed for {endpoint}: {message}")
            try:
                return require_mapping(json.loads(completed.stdout), f"GitHub response for {endpoint}")
            except json.JSONDecodeError as exc:
                raise AdapterError(f"gh returned invalid JSON for {endpoint}: {exc}") from exc
        request = urllib.request.Request(
            "https://api.github.com/" + endpoint,
            headers={
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "eacp-operational-provenance-v1.3",
            },
            method="GET",
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return require_mapping(json.load(response), f"GitHub response for {endpoint}")
        except urllib.error.HTTPError as exc:
            raise AdapterError(
                f"public GitHub API request failed for {endpoint} with HTTP {exc.code}; "
                "use an authenticated gh session for private repositories or higher rate limits"
            ) from exc
        except urllib.error.URLError as exc:
            raise AdapterError(f"public GitHub API request failed for {endpoint}: {exc.reason}") from exc

    def paginated(self, endpoint: str, key: str) -> list[Any]:
        values: list[Any] = []
        page = 1
        total: int | None = None
        while True:
            separator = "&" if "?" in endpoint else "?"
            response = self.get(f"{endpoint}{separator}per_page=100&page={page}")
            page_values = require_list(response.get(key), f"GitHub {key}")
            if total is None and isinstance(response.get("total_count"), int):
                total = response["total_count"]
            values.extend(page_values)
            if len(page_values) < 100 or (total is not None and len(values) >= total):
                break
            page += 1
            if page > 1000:
                raise AdapterError(f"pagination safety limit exceeded for {endpoint}")
        return values


def jobs_from_json(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    mapping = require_mapping(value, "jobs JSON")
    return require_list(mapping.get("jobs"), "jobs JSON.jobs")


def artifacts_from_json(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    mapping = require_mapping(value, "artifacts JSON")
    return require_list(mapping.get("artifacts"), "artifacts JSON.artifacts")


def private_capture_guard(snapshot: dict[str, Any], allow_private: bool) -> None:
    if snapshot["repository"]["private"] and not allow_private:
        raise AdapterError(
            "source repository is private; refusing a publication-oriented capture without --allow-private"
        )


def safe_extract_artifact(artifact_path: Path, destination: Path) -> Path:
    if artifact_path.is_dir():
        candidates = [
            path
            for path in artifact_path.rglob("github_actions.json")
            if path.is_file()
            and not path.is_symlink()
            and path.parent.name == "source"
        ]
        if len(candidates) != 1:
            raise AdapterError(
                "artifact directory must contain exactly one source/github_actions.json; "
                f"found {len(candidates)}"
            )
        return candidates[0]
    if artifact_path.suffix.lower() == ".json":
        return artifact_path
    if artifact_path.suffix.lower() != ".zip":
        raise AdapterError("artifact must be a bundle directory, source JSON, or .zip downloaded from Actions")
    with zipfile.ZipFile(artifact_path) as archive:
        candidates: list[zipfile.ZipInfo] = []
        for member in archive.infolist():
            pure = PurePosixPath(member.filename)
            if pure.is_absolute() or ".." in pure.parts:
                raise AdapterError(f"unsafe path in artifact ZIP: {member.filename!r}")
            if member.is_dir():
                continue
            if pure.as_posix().endswith("source/github_actions.json"):
                candidates.append(member)
        if len(candidates) != 1:
            raise AdapterError(
                f"artifact ZIP must contain exactly one source/github_actions.json; found {len(candidates)}"
            )
        target = destination / "github_actions.json"
        with archive.open(candidates[0]) as source, target.open("wb") as output:
            shutil.copyfileobj(source, output)
        return target


def load_snapshot_from_bundle(bundle: Path) -> dict[str, Any]:
    validate_bundle(bundle)
    return require_mapping(load_json(bundle / "source/github_actions.json"), "source snapshot")


def kubernetes_join_rows(csv_path: Path, correlation_id: str) -> tuple[int, list[dict[str, str]]]:
    try:
        with csv_path.open("r", encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            headers = set(reader.fieldnames or [])
            required = {"source_type", "source_id", "source_ts", "actor", "correlation_id", "source_pointer"}
            if not required.issubset(headers):
                raise AdapterError(
                    f"Kubernetes evidence CSV lacks headers: {sorted(required - headers)}"
                )
            matched = [dict(row) for row in reader if row.get("correlation_id") == correlation_id]
    except FileNotFoundError as exc:
        raise AdapterError(f"Kubernetes evidence CSV does not exist: {csv_path}") from exc
    kubernetes = [row for row in matched if row.get("source_type", "").startswith("kubernetes.")]
    return len(matched), kubernetes


def join_report(
    snapshot: dict[str, Any],
    *,
    kubernetes_csv: Path | None,
    kubernetes_object: Path | None,
    negative_control_object: Path | None = None,
    kubernetes_pods: Path | None = None,
    kubernetes_audit_summary: Path | None = None,
) -> dict[str, Any]:
    correlation_id = str(snapshot["projection"]["correlation_id"])
    github_rows = project_evidence(snapshot)
    csv_exact_matches = 0
    kubernetes_rows: list[dict[str, str]] = []
    if kubernetes_csv:
        csv_exact_matches, kubernetes_rows = kubernetes_join_rows(kubernetes_csv, correlation_id)

    object_match = False
    subject_match = False
    workload_image_match = False
    object_identity: dict[str, Any] | None = None
    if kubernetes_object:
        value = require_mapping(load_json(kubernetes_object, "Kubernetes object"), "Kubernetes object")
        metadata = require_mapping(value.get("metadata"), "Kubernetes object.metadata")
        annotations = metadata.get("annotations") if isinstance(metadata.get("annotations"), dict) else {}
        observed = annotations.get(ANNOTATION_KEY)
        object_match = observed == correlation_id
        expected_subject = snapshot["projection"].get("subject")
        observed_subject_digest = annotations.get("eacp.io/subject-digest")
        observed_subject_uri = annotations.get("eacp.io/subject-uri")
        if isinstance(expected_subject, dict):
            subject_match = (
                observed_subject_digest == expected_subject.get("digest")
                and observed_subject_uri == expected_subject.get("uri")
            )
            expected_image = f"{expected_subject['uri']}@{expected_subject['digest']}"
            spec = value.get("spec") if isinstance(value.get("spec"), dict) else {}
            template = spec.get("template") if isinstance(spec.get("template"), dict) else {}
            pod_spec = template.get("spec") if isinstance(template.get("spec"), dict) else {}
            containers = pod_spec.get("containers") if isinstance(pod_spec.get("containers"), list) else []
            workload_image_match = any(
                isinstance(container, dict) and container.get("image") == expected_image
                for container in containers
            )
        object_identity = {
            "api_version": value.get("apiVersion"),
            "kind": value.get("kind"),
            "namespace": metadata.get("namespace"),
            "name": metadata.get("name"),
            "observed_correlation_id": observed,
            "exact_match": object_match,
            "observed_subject_uri": observed_subject_uri,
            "observed_subject_digest": observed_subject_digest,
            "subject_annotations_exact_match": subject_match,
            "workload_image_exact_match": workload_image_match,
        }
    negative_control: dict[str, Any] | None = None
    if negative_control_object:
        value = require_mapping(
            load_json(negative_control_object, "negative-control Kubernetes object"),
            "negative-control Kubernetes object",
        )
        metadata = require_mapping(value.get("metadata"), "negative-control metadata")
        annotations = metadata.get("annotations") if isinstance(metadata.get("annotations"), dict) else {}
        negative_control = {
            "namespace": metadata.get("namespace"),
            "name": metadata.get("name"),
            "correlation_annotation_absent": ANNOTATION_KEY not in annotations,
            "observed_correlation_id": annotations.get(ANNOTATION_KEY),
        }
    pod_observation: dict[str, Any] | None = None
    if kubernetes_pods:
        value = require_mapping(load_json(kubernetes_pods, "Kubernetes Pod list"), "Kubernetes Pod list")
        items = require_list(value.get("items"), "Kubernetes Pod list.items")
        spec_images: list[str] = []
        runtime_image_ids: list[str] = []
        pod_correlation_ids: list[str | None] = []
        for item_value in items:
            item = require_mapping(item_value, "Kubernetes Pod")
            metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
            annotations = metadata.get("annotations") if isinstance(metadata.get("annotations"), dict) else {}
            pod_correlation_ids.append(annotations.get(ANNOTATION_KEY))
            spec = item.get("spec") if isinstance(item.get("spec"), dict) else {}
            for container in spec.get("containers") if isinstance(spec.get("containers"), list) else []:
                if isinstance(container, dict) and isinstance(container.get("image"), str):
                    spec_images.append(container["image"])
            status = item.get("status") if isinstance(item.get("status"), dict) else {}
            statuses = (
                status.get("containerStatuses")
                if isinstance(status.get("containerStatuses"), list)
                else []
            )
            for container_status in statuses:
                if isinstance(container_status, dict) and isinstance(container_status.get("imageID"), str):
                    runtime_image_ids.append(container_status["imageID"])
        expected_subject = snapshot["projection"].get("subject")
        expected_image = None
        expected_digest = None
        if isinstance(expected_subject, dict):
            expected_image = f"{expected_subject['uri']}@{expected_subject['digest']}"
            expected_digest = expected_subject["digest"]
        runtime_exact = bool(expected_digest) and any(
            image_id == expected_digest
            or image_id.endswith("@" + expected_digest)
            or image_id.endswith("/" + expected_digest)
            for image_id in runtime_image_ids
        )
        pod_observation = {
            "pod_count": len(items),
            "all_pods_have_exact_correlation_id": bool(items)
            and all(value == correlation_id for value in pod_correlation_ids),
            "spec_images": sorted(set(spec_images)),
            "pod_spec_subject_exact_match": bool(expected_image) and expected_image in spec_images,
            "runtime_image_ids": sorted(set(runtime_image_ids)),
            "runtime_image_id_exact_subject_digest_match": runtime_exact,
            "runtime_digest_interpretation": (
                "exact subject digest observed in runtime imageID"
                if runtime_exact
                else "runtime imageID may be a platform-manifest or runtime-normalized digest; reported without treating it as an exact match"
            ),
        }
    observed = bool(kubernetes_rows) or object_match
    denied_rows = [
        row for row in kubernetes_rows
        if str(row.get("outcome", "")).startswith("403")
        or "forbidden" in str(row.get("outcome", "")).lower()
    ]
    rbac_binding: dict[str, Any] | None = None
    if kubernetes_audit_summary:
        audit_summary = require_mapping(
            load_json(kubernetes_audit_summary, "Kubernetes audit summary"),
            "Kubernetes audit summary",
        )
        denial_summary = require_mapping(
            audit_summary.get("rbac_denial"), "Kubernetes audit summary.rbac_denial"
        )
        expected_target = require_mapping(
            denial_summary.get("expected_target"),
            "Kubernetes audit summary.rbac_denial.expected_target",
        )
        if denial_summary.get("binding_method") != "adapter_explicit_exact_target":
            raise AdapterError("Kubernetes target-bound RBAC denial uses an unsupported binding method")
        matching_denials = denial_summary.get("matching_http_403_records")
        if not isinstance(matching_denials, int) or matching_denials < 1:
            raise AdapterError("Kubernetes audit summary has no target-bound HTTP 403")
        if object_identity:
            api_version = str(object_identity.get("api_version") or "")
            observed_target = {
                "api_group": api_version.split("/", 1)[0] if "/" in api_version else "",
                "resource": str(object_identity.get("kind") or "").lower() + "s",
                "namespace": object_identity.get("namespace"),
                "name": object_identity.get("name"),
            }
            if expected_target != observed_target:
                raise AdapterError(
                    "Target-bound RBAC denial does not equal the source-native correlated Kubernetes object target"
                )
        rbac_binding = {
            "binding_method": "adapter_explicit_exact_target",
            "target": expected_target,
            "matching_http_403_records": matching_denials,
            "source_native_correlation_records": int(
                denial_summary.get("source_native_correlation_records") or 0
            ),
            "source_native_correlation_required": False,
        }
    if observed and subject_match and workload_image_match:
        status = "observed_cross_plane_link_with_subject_digest"
    elif observed:
        status = "observed_cross_plane_link"
    else:
        status = "no_matching_kubernetes_evidence_observed"
    return {
        "schema_version": "eacp.cross-plane-join/1.3.0",
        "join_rule": (
            "exact equality on eacp.io/correlation-id / EACP correlation_id for the positive chain; "
            "RBAC denial is adapter-explicit via exact Kubernetes target equality"
        ),
        "correlation_id": correlation_id,
        "status": status,
        "github_actions": {
            "repository": snapshot["repository"]["full_name"],
            "run_id": snapshot["run"]["id"],
            "run_attempt": snapshot["run"]["run_attempt"],
            "commit_sha": snapshot["run"]["head_sha"],
            "evidence_rows": len(github_rows),
            "source_url": snapshot["run"]["html_url"],
        },
        "kubernetes": {
            "csv_supplied": kubernetes_csv is not None,
            "csv_rows_with_exact_id": csv_exact_matches,
            "kubernetes_source_rows_with_exact_id": len(kubernetes_rows),
            "source_ids": [row["source_id"] for row in kubernetes_rows],
            "principals": sorted({row.get("actor", "unknown") for row in kubernetes_rows}),
            "rbac_denied_rows_in_projection": len(denied_rows),
            "rbac_denial_binding": rbac_binding,
            "object_supplied": kubernetes_object is not None,
            "object": object_identity,
            "negative_control": negative_control,
            "pods": pod_observation,
        },
        "claim_boundary": (
            "Exact identifier equality demonstrates an observable cross-plane link. It does not, by itself, "
            "prove causal correctness, authorization, or bit-for-bit artifact identity."
        ),
    }


def output_json(value: Any, path: Path | None) -> None:
    rendered = pretty_json(value)
    if path is None:
        sys.stdout.write(rendered)
        return
    if path.exists():
        raise AdapterError(f"refusing to overwrite output: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(rendered, encoding="utf-8")


def add_projection_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--service", help="EACP service identifier; defaults to owner/repository")
    parser.add_argument(
        "--correlation-id",
        help="explicit hand-off identifier; default is deterministically derived from repository/run/attempt",
    )
    parser.add_argument("--deployment", default=DEFAULT_DEPLOYMENT)
    parser.add_argument("--namespace", default=DEFAULT_NAMESPACE)
    parser.add_argument("--subject-uri", help="immutable subject name, for example oci://registry/name")
    parser.add_argument("--subject-digest", help="immutable digest in sha256:<64 hex> form")
    parser.add_argument("--captured-at", help="RFC 3339 capture time; defaults to current UTC time")
    parser.add_argument(
        "--allow-private",
        action="store_true",
        help="acknowledge that a private-repository metadata bundle requires manual publication review",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="GitHub Actions to EACP v1.3 adapter and cross-plane validation tool"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    capture = subparsers.add_parser("capture", help="read one real GitHub Actions run through REST API")
    capture.add_argument("--repo", required=True, help="owner/repository")
    capture.add_argument("--run-id", type=int, required=True)
    capture.add_argument("--output-dir", type=Path, required=True)
    capture.add_argument("--transport", choices=("auto", "gh", "public-http"), default="auto")
    add_projection_arguments(capture)

    import_api = subparsers.add_parser(
        "import-api", help="normalize previously exported GitHub run/jobs/artifacts API JSON"
    )
    import_api.add_argument("--run-json", type=Path, required=True)
    import_api.add_argument("--jobs-json", type=Path, required=True)
    import_api.add_argument("--artifacts-json", type=Path, required=True)
    import_api.add_argument("--output-dir", type=Path, required=True)
    add_projection_arguments(import_api)

    import_artifact = subparsers.add_parser(
        "import-artifact", help="regenerate a validated bundle from an Actions artifact directory/ZIP/source JSON"
    )
    import_artifact.add_argument("--artifact", type=Path, required=True)
    import_artifact.add_argument("--output-dir", type=Path, required=True)
    import_artifact.add_argument("--allow-private", action="store_true")
    import_artifact.add_argument("--captured-at", help="replace capture time and mark this as an artifact import")

    verify = subparsers.add_parser("verify", help="verify checksums and deterministic projection")
    verify.add_argument("--bundle", type=Path, required=True)

    join = subparsers.add_parser("join", help="test an exact cross-plane join against Kubernetes evidence")
    join.add_argument("--bundle", type=Path, required=True)
    join.add_argument("--kubernetes-evidence-csv", type=Path)
    join.add_argument("--kubernetes-object-json", type=Path)
    join.add_argument("--negative-control-object-json", type=Path)
    join.add_argument("--kubernetes-pods-json", type=Path)
    join.add_argument("--kubernetes-audit-summary-json", type=Path)
    join.add_argument("--output", type=Path)

    annotate = subparsers.add_parser(
        "annotate", help="plan or explicitly apply the bundle correlation to a Kubernetes Deployment"
    )
    annotate.add_argument("--bundle", type=Path, required=True)
    annotate.add_argument("--deployment")
    annotate.add_argument("--namespace")
    annotate.add_argument("--context")
    annotate.add_argument("--kubectl", default="kubectl")
    annotate.add_argument("--apply", action="store_true", help="perform the patch; omission is non-mutating plan mode")
    annotate.add_argument("--snapshot-output", type=Path)
    return parser


def command_capture(args: argparse.Namespace) -> dict[str, Any]:
    if not REPOSITORY_PATTERN.fullmatch(args.repo):
        raise AdapterError("--repo must use owner/repository syntax")
    if args.run_id < 1:
        raise AdapterError("--run-id must be positive")
    transport = GitHubTransport(args.transport)
    encoded_repo = "/".join(urllib.parse.quote(part, safe="") for part in args.repo.split("/"))
    base = f"repos/{encoded_repo}/actions/runs/{args.run_id}"
    raw_run = transport.get(base)
    raw_jobs = transport.paginated(base + "/jobs", "jobs")
    raw_artifacts = transport.paginated(base + "/artifacts", "artifacts")
    snapshot = build_source_snapshot(
        raw_run,
        raw_jobs,
        raw_artifacts,
        captured_at=args.captured_at or utc_now(),
        acquisition="github-rest-api",
        transport=transport.mode,
        authenticated=transport.authenticated,
        service=args.service,
        correlation_id=args.correlation_id,
        deployment=args.deployment,
        namespace=args.namespace,
        subject_uri=args.subject_uri,
        subject_digest=args.subject_digest,
    )
    if snapshot["repository"]["full_name"].lower() != args.repo.lower():
        raise AdapterError(
            f"GitHub response repository {snapshot['repository']['full_name']!r} does not match requested {args.repo!r}"
        )
    if snapshot["run"]["id"] != args.run_id:
        raise AdapterError("GitHub response run ID does not match requested run")
    private_capture_guard(snapshot, args.allow_private)
    return write_bundle(snapshot, args.output_dir)


def command_import_api(args: argparse.Namespace) -> dict[str, Any]:
    raw_run = require_mapping(load_json(args.run_json, "run JSON"), "run JSON")
    raw_jobs = jobs_from_json(load_json(args.jobs_json, "jobs JSON"))
    raw_artifacts = artifacts_from_json(load_json(args.artifacts_json, "artifacts JSON"))
    snapshot = build_source_snapshot(
        raw_run,
        raw_jobs,
        raw_artifacts,
        captured_at=args.captured_at or utc_now(),
        acquisition="imported-api-json",
        transport="offline-import",
        authenticated=None,
        service=args.service,
        correlation_id=args.correlation_id,
        deployment=args.deployment,
        namespace=args.namespace,
        subject_uri=args.subject_uri,
        subject_digest=args.subject_digest,
    )
    private_capture_guard(snapshot, args.allow_private)
    return write_bundle(snapshot, args.output_dir)


def command_import_artifact(args: argparse.Namespace) -> dict[str, Any]:
    if not args.artifact.exists():
        raise AdapterError(f"artifact does not exist: {args.artifact}")
    with tempfile.TemporaryDirectory(prefix="eacp-gha-artifact-") as temporary_name:
        source_path = safe_extract_artifact(args.artifact, Path(temporary_name))
        snapshot = require_mapping(load_json(source_path, "artifact source JSON"), "artifact source JSON")
        validate_snapshot(snapshot)
        snapshot = json.loads(canonical_json(snapshot))
        snapshot["capture"]["acquisition"] = "imported-actions-artifact"
        snapshot["capture"]["transport"] = "offline-artifact-import"
        snapshot["capture"]["authenticated"] = None
        snapshot["capture"]["captured_at"] = validate_rfc3339(
            args.captured_at or utc_now(), "capture.captured_at"
        )
        private_capture_guard(snapshot, args.allow_private)
        return write_bundle(snapshot, args.output_dir)


def command_annotate(args: argparse.Namespace) -> dict[str, Any]:
    snapshot = load_snapshot_from_bundle(args.bundle)
    target = require_mapping(snapshot["projection"]["kubernetes_target"], "kubernetes target")
    deployment = args.deployment or target["name"]
    namespace = args.namespace or target["namespace"]
    patch_path = args.bundle / "kubernetes/annotation_merge_patch.json"
    command = [
        args.kubectl,
        "patch",
        "deployment",
        str(deployment),
        "--namespace",
        str(namespace),
        "--type=merge",
        f"--patch-file={patch_path.resolve()}",
        "-o",
        "json",
    ]
    if args.context:
        command[1:1] = ["--context", args.context]
    plan = {
        "mode": "apply" if args.apply else "plan",
        "mutation_performed": False,
        "target": {"resource": "deployment", "name": deployment, "namespace": namespace},
        "correlation_id": snapshot["projection"]["correlation_id"],
        "argv": command,
    }
    if not args.apply:
        if args.snapshot_output:
            raise AdapterError("--snapshot-output is valid only together with --apply")
        return plan
    if shutil.which(args.kubectl) is None:
        raise AdapterError(f"kubectl executable not found: {args.kubectl}")
    completed = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
    if completed.returncode != 0:
        message = completed.stderr.strip().splitlines()[-1] if completed.stderr.strip() else "unknown error"
        raise AdapterError(f"kubectl patch failed: {message}")
    try:
        result = require_mapping(json.loads(completed.stdout), "kubectl output")
    except json.JSONDecodeError as exc:
        raise AdapterError(f"kubectl returned invalid JSON: {exc}") from exc
    annotations = require_mapping(
        require_mapping(result.get("metadata"), "patched object metadata").get("annotations"),
        "patched object annotations",
    )
    if annotations.get(ANNOTATION_KEY) != snapshot["projection"]["correlation_id"]:
        raise AdapterError("patched object did not return the expected correlation annotation")
    if args.snapshot_output:
        output_json(result, args.snapshot_output)
    plan["mutation_performed"] = True
    plan["observed_object"] = {
        "uid": result.get("metadata", {}).get("uid"),
        "resource_version": result.get("metadata", {}).get("resourceVersion"),
        "exact_annotation_match": True,
    }
    return plan


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "capture":
            result = command_capture(args)
            output_json(result, None)
        elif args.command == "import-api":
            result = command_import_api(args)
            output_json(result, None)
        elif args.command == "import-artifact":
            result = command_import_artifact(args)
            output_json(result, None)
        elif args.command == "verify":
            output_json(validate_bundle(args.bundle), None)
        elif args.command == "join":
            if not args.kubernetes_evidence_csv and not args.kubernetes_object_json:
                raise AdapterError("join requires --kubernetes-evidence-csv and/or --kubernetes-object-json")
            snapshot = load_snapshot_from_bundle(args.bundle)
            report = join_report(
                snapshot,
                kubernetes_csv=args.kubernetes_evidence_csv,
                kubernetes_object=args.kubernetes_object_json,
                negative_control_object=args.negative_control_object_json,
                kubernetes_pods=args.kubernetes_pods_json,
                kubernetes_audit_summary=args.kubernetes_audit_summary_json,
            )
            output_json(report, args.output)
        elif args.command == "annotate":
            output_json(command_annotate(args), None)
        else:  # pragma: no cover - argparse enforces the subcommand
            parser.error("unknown command")
    except AdapterError as exc:
        parser.exit(2, f"error: {exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
