#!/usr/bin/env python3
"""Replay one frozen Kubernetes audit corpus through OTel and EACP.

The OpenTelemetry arm is a fixed Collector Contrib container configured as a
filelog JSON parser followed by the file exporter. The EACP arm is a fresh
Python process that normalizes the same bytes and persists the canonical
projection to an indexed, append-only SQLite database. The orchestrator runs
the arms in alternating order and validates their projections outside the
timed intervals.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import platform
import re
import shutil
import sqlite3
import statistics
import subprocess
import sys
import tempfile
import time
import uuid
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Sequence


IMAGE = (
    "ghcr.io/open-telemetry/opentelemetry-collector-releases/"
    "opentelemetry-collector-contrib:0.158.0"
)
NAMESPACE = "eacp-k8s-eval"
PROJECTION_FIELDS = (
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
)

EACP_SCHEMA = """
CREATE TABLE evidence (
  row_order INTEGER PRIMARY KEY,
  source_type TEXT NOT NULL,
  source_id TEXT NOT NULL,
  source_ts TEXT NOT NULL,
  observed_ts TEXT NOT NULL,
  actor TEXT NOT NULL,
  service TEXT NOT NULL,
  intent TEXT NOT NULL,
  policy TEXT NOT NULL,
  action TEXT NOT NULL,
  outcome TEXT NOT NULL,
  source_pointer TEXT NOT NULL,
  correlation_id TEXT NOT NULL,
  content_hash TEXT NOT NULL,
  UNIQUE(source_type, source_id)
);
CREATE INDEX ev_service_time ON evidence(service, source_ts);
CREATE INDEX ev_correlation_time ON evidence(correlation_id, source_ts);
CREATE INDEX ev_action_time ON evidence(action, source_ts);
CREATE TRIGGER evidence_no_update
BEFORE UPDATE ON evidence BEGIN
  SELECT RAISE(ABORT, 'evidence rows are append-only');
END;
CREATE TRIGGER evidence_no_delete
BEFORE DELETE ON evidence BEGIN
  SELECT RAISE(ABORT, 'evidence rows are append-only');
END;
"""

LOCAL_PATH_PATTERN = re.compile(
    r"/(?:Users|home|private/tmp|private/var/folders|tmp|var/folders)/[^\s\"']+"
)
SENSITIVE_KEYS = {
    "authorization",
    "accesstoken",
    "refreshtoken",
    "clientsecret",
    "privatekey",
    "password",
    "passwd",
    "kubeconfig",
}


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                value = json.loads(stripped)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid JSON on input line {line_number}: {exc}") from exc
            if not isinstance(value, dict):
                raise ValueError(f"input line {line_number} is not a JSON object")
            records.append(value)
    if not records:
        raise ValueError("input corpus is empty")
    return records


def read_reference_projection(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        if tuple(reader.fieldnames or ()) != PROJECTION_FIELDS:
            raise ValueError(
                "reference CSV fields do not match the canonical projection: "
                f"{reader.fieldnames!r}"
            )
        rows = [{field: str(row[field]) for field in PROJECTION_FIELDS} for row in reader]
    if not rows:
        raise ValueError("reference canonical projection is empty")
    return rows


def walk_json(value: Any, keys: tuple[str, ...] = ()) -> Iterable[tuple[tuple[str, ...], Any]]:
    if isinstance(value, dict):
        for key, child in value.items():
            child_keys = keys + (str(key),)
            yield child_keys, child
            yield from walk_json(child, child_keys)
    elif isinstance(value, list):
        for child in value:
            yield from walk_json(child, keys)


def audit_public_safety(records: Sequence[dict[str, Any]]) -> dict[str, Any]:
    findings: list[str] = []
    for index, record in enumerate(records, start=1):
        resource = str((record.get("objectRef") or {}).get("resource") or "").lower()
        uri = str(record.get("requestURI") or "").lower()
        if resource in {"secret", "secrets"} or "/secrets" in uri:
            findings.append(f"record {index}: Secret resource")
        for keys, value in walk_json(record):
            key = keys[-1] if keys else ""
            if key == "sourceIPs":
                findings.append(f"record {index}: sourceIPs present")
            normalized_key = re.sub(r"[^a-z0-9]", "", key.lower())
            if (
                normalized_key in SENSITIVE_KEYS
                or normalized_key.endswith("issuedcredentialid")
                or normalized_key.endswith("credentialid")
            ):
                findings.append(f"record {index}: sensitive key {key!r}")
            if isinstance(value, str) and LOCAL_PATH_PATTERN.search(value):
                findings.append(f"record {index}: local filesystem path")
            if isinstance(value, str) and re.search(
                r"-----BEGIN (?:[A-Z ]+ )?(?:CERTIFICATE|PRIVATE KEY)-----", value
            ):
                findings.append(f"record {index}: PEM certificate or private key")
    if findings:
        preview = "; ".join(findings[:10])
        raise ValueError(f"input failed public-safety validation: {preview}")
    return {
        "records_scanned": len(records),
        "audit_sourceIPs_fields_absent": True,
        "secret_resources_absent": True,
        "sensitive_key_patterns_absent": True,
        "pem_certificates_and_private_keys_absent": True,
        "local_filesystem_paths_absent": True,
    }


def object_metadata(record: dict[str, Any]) -> dict[str, Any]:
    for candidate_name in ("requestObject", "responseObject"):
        candidate = record.get(candidate_name)
        if not isinstance(candidate, dict):
            continue
        metadata = candidate.get("metadata")
        if isinstance(metadata, dict):
            return metadata
    return {}


def normalize(record: dict[str, Any], namespace: str = NAMESPACE) -> dict[str, str]:
    object_ref = record.get("objectRef") or {}
    metadata = object_metadata(record)
    labels = metadata.get("labels") if isinstance(metadata.get("labels"), dict) else {}
    annotations = (
        metadata.get("annotations") if isinstance(metadata.get("annotations"), dict) else {}
    )

    resource = str(object_ref.get("resource") or "unknown-resource")
    name = str(object_ref.get("name") or metadata.get("name") or resource)
    workload_name = str(labels.get("app.kubernetes.io/name") or name)
    audit_id = str(
        record.get("auditID")
        or hashlib.sha256(canonical_json(record).encode("utf-8")).hexdigest()
    )
    stage = str(record.get("stage") or "unknown-stage")
    source_id = f"{audit_id}:{stage}"
    source_ts = str(record.get("requestReceivedTimestamp") or record.get("stageTimestamp") or "")
    observed_ts = str(record.get("stageTimestamp") or source_ts)
    actor = str(
        (record.get("impersonatedUser") or {}).get("username")
        or (record.get("user") or {}).get("username")
        or "unknown"
    )
    action = str(record.get("verb") or "unknown")
    status = record.get("responseStatus") or {}
    code = str(status.get("code") or "unknown")
    reason = str(status.get("reason") or status.get("status") or "")
    outcome = f"{code}:{reason}" if reason else code
    explicit_correlation = str(annotations.get("eacp.io/correlation-id") or "")
    correlation_id = explicit_correlation or (
        f"k8s://{namespace}/{resource}/{name}" if name else audit_id
    )
    serialized = canonical_json(record)

    return {
        "source_type": "kubernetes.audit",
        "source_id": source_id,
        "source_ts": source_ts,
        "observed_ts": observed_ts,
        "actor": actor,
        "service": f"{namespace}/{workload_name}",
        "intent": "operational_provenance",
        "policy": "kubernetes-rbac-admission",
        "action": action,
        "outcome": outcome,
        "source_pointer": f"kubernetes-audit://{audit_id}",
        "correlation_id": correlation_id,
        "content_hash": hashlib.sha256(serialized.encode("utf-8")).hexdigest(),
    }


def create_eacp_database(input_path: Path, database_path: Path) -> None:
    records = read_jsonl(input_path)
    rows = [normalize(record) for record in records]
    connection = sqlite3.connect(database_path)
    try:
        connection.execute("PRAGMA journal_mode=DELETE")
        connection.execute("PRAGMA synchronous=FULL")
        connection.executescript(EACP_SCHEMA)
        with connection:
            connection.executemany(
                """
                INSERT INTO evidence(
                  row_order, source_type, source_id, source_ts, observed_ts,
                  actor, service, intent, policy, action, outcome,
                  source_pointer, correlation_id, content_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (index, *(row[field] for field in PROJECTION_FIELDS))
                    for index, row in enumerate(rows, start=1)
                ],
            )
    finally:
        connection.close()


def read_eacp_projection(database_path: Path) -> list[dict[str, str]]:
    connection = sqlite3.connect(database_path)
    try:
        rows = connection.execute(
            f"SELECT {', '.join(PROJECTION_FIELDS)} FROM evidence ORDER BY row_order"
        ).fetchall()
    finally:
        connection.close()
    return [dict(zip(PROJECTION_FIELDS, row)) for row in rows]


def decode_any_value(value: Any) -> Any:
    if not isinstance(value, dict):
        return value
    scalar_names = (
        "stringValue",
        "boolValue",
        "intValue",
        "doubleValue",
        "bytesValue",
    )
    for name in scalar_names:
        if name in value:
            scalar = value[name]
            if name == "intValue" and isinstance(scalar, str):
                try:
                    return int(scalar)
                except ValueError:
                    return scalar
            return scalar
    if "arrayValue" in value:
        values = (value.get("arrayValue") or {}).get("values") or []
        return [decode_any_value(item) for item in values]
    if "kvlistValue" in value:
        entries = (value.get("kvlistValue") or {}).get("values") or []
        return {
            str(entry.get("key")): decode_any_value(entry.get("value"))
            for entry in entries
            if isinstance(entry, dict) and "key" in entry
        }
    return {key: decode_any_value(child) for key, child in value.items()}


def iter_json_values(text: str) -> Iterable[Any]:
    decoder = json.JSONDecoder()
    position = 0
    while position < len(text):
        while position < len(text) and text[position].isspace():
            position += 1
        if position >= len(text):
            return
        value, position = decoder.raw_decode(text, position)
        yield value


def read_collector_records(output_path: Path) -> list[dict[str, Any]]:
    if not output_path.is_file() or output_path.stat().st_size == 0:
        return []
    try:
        payloads = list(iter_json_values(output_path.read_text(encoding="utf-8")))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return []
    records: list[dict[str, Any]] = []
    for payload in payloads:
        if not isinstance(payload, dict):
            continue
        for resource_logs in payload.get("resourceLogs") or []:
            for scope_logs in resource_logs.get("scopeLogs") or []:
                for log_record in scope_logs.get("logRecords") or []:
                    body = decode_any_value(log_record.get("body"))
                    if isinstance(body, str):
                        try:
                            body = json.loads(body)
                        except json.JSONDecodeError:
                            pass
                    if isinstance(body, dict):
                        records.append(body)
    return records


def projection_digest(rows: Sequence[dict[str, str]]) -> str:
    canonical_rows = sorted(canonical_json(row) for row in rows)
    payload = "\n".join(canonical_rows) + ("\n" if canonical_rows else "")
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def field_accuracy(
    expected: Sequence[dict[str, str]], observed: Sequence[dict[str, str]]
) -> dict[str, Any]:
    expected_by_id = {row["source_id"]: row for row in expected}
    observed_by_id = {row["source_id"]: row for row in observed}
    common = sorted(set(expected_by_id) & set(observed_by_id))
    correct = 0
    compared = len(common) * len(PROJECTION_FIELDS)
    per_field: dict[str, float] = {}
    for field in PROJECTION_FIELDS:
        field_correct = sum(
            expected_by_id[source_id][field] == observed_by_id[source_id][field]
            for source_id in common
        )
        correct += field_correct
        per_field[field] = field_correct / len(common) if common else 0.0
    return {
        "matched_source_ids": len(common),
        "expected_source_ids": len(expected_by_id),
        "observed_source_ids": len(observed_by_id),
        "correct_field_values": correct,
        "compared_field_values": compared,
        "overall": correct / compared if compared else 0.0,
        "per_field": per_field,
    }


def percentile(values: Sequence[float], probability: float) -> float:
    ordered = sorted(values)
    if not ordered:
        return 0.0
    position = (len(ordered) - 1) * probability
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    fraction = position - lower
    return ordered[lower] * (1.0 - fraction) + ordered[upper] * fraction


def describe(values: Sequence[float]) -> dict[str, float]:
    return {
        "minimum": min(values),
        "q1": percentile(values, 0.25),
        "median": statistics.median(values),
        "q3": percentile(values, 0.75),
        "maximum": max(values),
    }


def command_output(command: Sequence[str]) -> str:
    completed = subprocess.run(
        command,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    return completed.stdout.strip()


def inspect_image() -> dict[str, str]:
    try:
        raw = command_output(["docker", "image", "inspect", IMAGE])
    except subprocess.CalledProcessError:
        command_output(["docker", "pull", IMAGE])
        raw = command_output(["docker", "image", "inspect", IMAGE])
    inspection = json.loads(raw)[0]
    repo_digests = inspection.get("RepoDigests") or []
    resolved_digest = next(
        (item.split("@", 1)[1] for item in repo_digests if "@sha256:" in item),
        "",
    )
    if not resolved_digest:
        raise RuntimeError("Docker did not report a resolved repository digest")
    version = command_output(["docker", "run", "--rm", IMAGE, "--version"])
    return {
        "tag": IMAGE,
        "resolved_digest": resolved_digest,
        "image_id": str(inspection.get("Id") or ""),
        "collector_version": version,
    }


def run_eacp_trial(
    script_path: Path, input_path: Path, database_path: Path
) -> tuple[float, list[dict[str, str]]]:
    started = time.perf_counter_ns()
    subprocess.run(
        [
            sys.executable,
            str(script_path),
            "eacp-worker",
            "--input",
            str(input_path),
            "--database",
            str(database_path),
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )
    elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000
    return elapsed_ms, read_eacp_projection(database_path)


def run_otel_trial(
    config_path: Path,
    input_path: Path,
    output_dir: Path,
    expected_count: int,
    timeout_seconds: float,
    trial: int,
) -> tuple[float, list[dict[str, Any]], str]:
    output_dir.mkdir(parents=True)
    os.chmod(output_dir, 0o777)
    output_path = output_dir / "collector-output.jsonl"
    container_name = f"eacp-otel-{os.getpid()}-{trial}-{uuid.uuid4().hex[:8]}"
    command = [
        "docker",
        "run",
        "--detach",
        "--name",
        container_name,
        "--volume",
        f"{input_path.parent.resolve()}:/input:ro",
        "--volume",
        f"{config_path.resolve()}:/config/collector-config.yaml:ro",
        "--volume",
        f"{output_dir.resolve()}:/output",
        IMAGE,
        "--config=/config/collector-config.yaml",
    ]
    started = time.perf_counter_ns()
    try:
        subprocess.run(
            command,
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
        deadline = time.monotonic() + timeout_seconds
        records: list[dict[str, Any]] = []
        while time.monotonic() < deadline:
            records = read_collector_records(output_path)
            if len(records) >= expected_count:
                break
            time.sleep(0.025)
        elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000
        logs = command_output(["docker", "logs", container_name])
        if len(records) != expected_count:
            raise RuntimeError(
                f"Collector trial {trial} exported {len(records)} of "
                f"{expected_count} records; logs: {logs[-2000:]}"
            )
        return elapsed_ms, records, logs
    finally:
        subprocess.run(
            ["docker", "stop", "--time", "1", container_name],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        subprocess.run(
            ["docker", "rm", "--force", container_name],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )


def checksums_for(directory: Path) -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    for path in sorted(directory.iterdir()):
        if path.is_file() and path.name != "SHA256SUMS":
            rows.append((sha256_file(path), path.name))
    return rows


def orchestrate(args: argparse.Namespace) -> int:
    if shutil.which("docker") is None:
        raise SystemExit("docker is required")
    if args.trials < 1:
        raise SystemExit("--trials must be positive")
    if args.output_dir.exists():
        raise SystemExit(f"refusing to overwrite existing output: {args.output_dir}")
    if args.input.name != "public_filtered_audit.jsonl":
        raise SystemExit(
            "the input must be the sanitized Kubernetes artifact named "
            "public_filtered_audit.jsonl"
        )

    records = read_jsonl(args.input)
    safety = audit_public_safety(records)
    direct_projection = [normalize(record) for record in records]
    reference_path = args.reference_csv or args.input.with_name("normalized_evidence.csv")
    if not reference_path.is_file():
        raise SystemExit(
            "a canonical normalized_evidence.csv is required; pass --reference-csv "
            "or place it beside the input JSONL"
        )
    expected_projection = read_reference_projection(reference_path)
    direct_digest = projection_digest(direct_projection)
    expected_digest = projection_digest(expected_projection)
    if len(direct_projection) != len(expected_projection) or direct_digest != expected_digest:
        raise SystemExit(
            "the independent comparison normalizer does not match the Kubernetes "
            "canonical reference projection"
        )
    source_ids = [row["source_id"] for row in expected_projection]
    duplicate_source_ids = len(source_ids) - len(set(source_ids))
    if duplicate_source_ids:
        raise SystemExit(
            f"canonical projection contains {duplicate_source_ids} duplicate source IDs"
        )

    config_path = Path(__file__).resolve().with_name("collector-config.yaml")
    if not config_path.is_file():
        raise SystemExit(f"missing Collector configuration: {config_path.name}")
    image = inspect_image()
    args.output_dir.mkdir(parents=True)
    work_dir = args.output_dir / "work"
    work_dir.mkdir()

    trial_rows: list[dict[str, Any]] = []
    eacp_projections: list[list[dict[str, str]]] = []
    otel_projections: list[list[dict[str, str]]] = []
    try:
        for trial in range(1, args.trials + 1):
            order = ("eacp", "opentelemetry") if trial % 2 else ("opentelemetry", "eacp")
            for position, pipeline in enumerate(order, start=1):
                if pipeline == "eacp":
                    db_path = work_dir / f"eacp-trial-{trial:02d}.sqlite"
                    elapsed_ms, projection = run_eacp_trial(
                        Path(__file__).resolve(), args.input.resolve(), db_path
                    )
                    output_bytes = db_path.stat().st_size
                    digest = projection_digest(projection)
                    eacp_projections.append(projection)
                    exported_records = len(projection)
                else:
                    output_dir = work_dir / f"otel-trial-{trial:02d}"
                    elapsed_ms, exported, logs = run_otel_trial(
                        config_path,
                        args.input.resolve(),
                        output_dir,
                        len(records),
                        args.timeout_seconds,
                        trial,
                    )
                    if logs:
                        raise RuntimeError(
                            f"Collector emitted unexpected error-level logs in trial {trial}: {logs}"
                        )
                    projection = [normalize(record) for record in exported]
                    output_path = output_dir / "collector-output.jsonl"
                    output_bytes = output_path.stat().st_size
                    digest = projection_digest(projection)
                    otel_projections.append(projection)
                    exported_records = len(exported)
                if exported_records != len(records) or digest != expected_digest:
                    raise RuntimeError(
                        f"validation failed for {pipeline} trial {trial}: "
                        f"records={exported_records}, digest={digest}"
                    )
                trial_rows.append(
                    {
                        "trial": trial,
                        "order_position": position,
                        "pipeline": pipeline,
                        "wall_time_ms": elapsed_ms,
                        "events": exported_records,
                        "microseconds_per_event": elapsed_ms * 1000 / exported_records,
                        "amortized_completion_rate_events_per_second": exported_records / (elapsed_ms / 1000),
                        "output_bytes": output_bytes,
                        "bytes_per_event": output_bytes / exported_records,
                        "projection_sha256": digest,
                        "projection_matches_expected": True,
                    }
                )
                print(
                    f"trial {trial:02d} position {position}: {pipeline} "
                    f"{elapsed_ms:.3f} ms, {exported_records} events"
                )
    finally:
        if not args.keep_work:
            shutil.rmtree(work_dir, ignore_errors=True)

    field_check = field_accuracy(expected_projection, otel_projections[0])
    input_sha256 = sha256_file(args.input)
    by_pipeline = {
        pipeline: [row for row in trial_rows if row["pipeline"] == pipeline]
        for pipeline in ("eacp", "opentelemetry")
    }
    descriptive: dict[str, Any] = {}
    for pipeline, rows in by_pipeline.items():
        descriptive[pipeline] = {
            "wall_time_ms": describe([float(row["wall_time_ms"]) for row in rows]),
            "microseconds_per_event": describe(
                [float(row["microseconds_per_event"]) for row in rows]
            ),
            "amortized_completion_rate_events_per_second": describe(
                [float(row["amortized_completion_rate_events_per_second"]) for row in rows]
            ),
            "output_bytes": describe([float(row["output_bytes"]) for row in rows]),
            "bytes_per_event": describe(
                [float(row["bytes_per_event"]) for row in rows]
            ),
        }

    environment = {
        "run_finished_utc": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "host_os": platform.system(),
        "host_release": platform.release(),
        "machine": platform.machine(),
        "logical_cpus": os.cpu_count(),
        "python": platform.python_version(),
        "sqlite": sqlite3.sqlite_version,
        "docker_client": command_output(
            ["docker", "version", "--format", "{{.Client.Version}}"]
        ),
        "docker_server": command_output(
            ["docker", "version", "--format", "{{.Server.Version}}"]
        ),
        "collector": image,
    }
    summary = {
        "experiment": (
            "Laboratory comparison of EACP SQLite ingestion and an "
            "OpenTelemetry Collector reference pipeline"
        ),
        "input": {
            "artifact_name": args.input.name,
            "sha256": input_sha256,
            "bytes": args.input.stat().st_size,
            "events": len(records),
            "reference_projection_artifact_name": reference_path.name,
            "reference_projection_sha256": sha256_file(reference_path),
            "canonical_projection_sha256": expected_digest,
            "duplicate_source_ids": duplicate_source_ids,
            "public_safety_validation": safety,
        },
        "method": {
            "sequential_trials_per_pipeline": args.trials,
            "order": "alternating; odd trials EACP first, even trials OpenTelemetry first",
            "timing_boundary_eacp": (
                "fresh Python process start through committed indexed SQLite database"
            ),
            "timing_boundary_opentelemetry": (
                "fresh Docker container creation through host-side reading and "
                "JSON decoding of the complete file-exporter payload"
            ),
            "validation_outside_timed_intervals": (
                "the EACP database rows and the raw audit bodies preserved in "
                "the Collector export are mapped by the shared external validator "
                "to the same canonical 13-field projection"
            ),
        },
        "solutions": {
            "eacp": {
                "implementation": "Python standard library plus SQLite",
                "storage": "indexed append-only evidence table",
            },
            "opentelemetry": {
                **image,
                "pipeline": "filelog JSON parser -> batch processor -> file exporter",
                "configuration": "collector-config.yaml",
                "collector_natively_maps_eacp_13_field_projection": False,
                "comparison_role": (
                    "retain each raw Kubernetes audit line as the exported log body "
                    "for post-export validation; parsed attributes are not used by "
                    "the EACP validator"
                ),
                "file_exporter_indexed_or_queryable": False,
            },
        },
        "validation": {
            "expected_events": len(records),
            "all_eacp_trials_retained_every_event": all(
                len(projection) == len(records) for projection in eacp_projections
            ),
            "all_opentelemetry_trials_retained_every_event": all(
                len(projection) == len(records) for projection in otel_projections
            ),
            "all_projection_digests_equal": all(
                projection_digest(projection) == expected_digest
                for projection in eacp_projections + otel_projections
            ),
            "external_post_export_validator_matches_reference_projection": (
                direct_digest == expected_digest
            ),
            "post_export_canonical_projection_preservation": {
                "mapping_performed_by": (
                    "shared external validator after Collector export; not by "
                    "the Collector configuration"
                ),
                "collector_native_semantic_normalization_claimed": False,
                "field_value_equality": field_check,
            },
        },
        "descriptive_results": descriptive,
        "environment": environment,
        "limitations": [
            "This is one compact frozen audit corpus from a single-node local kind cluster, not a production workload.",
            "Timing boundaries are asymmetric: the Collector interval includes Docker startup, batching, polling, and host-side reading and JSON decoding of the complete export; EACP projection reading occurs later during validation. Values are descriptive observed times to validated output and do not establish implementation superiority.",
            "The OpenTelemetry file exporter produces unindexed OTLP/JSON, whereas EACP produces indexed SQLite; storage-byte values describe unlike artifacts and are not a compression ranking.",
            "No query-latency comparison is made between SQLite and the Collector file output.",
            "The Collector is evaluated as a vendor-neutral ingest/parse/export reference pipeline, not as a complete provenance query system.",
            "The 13-field equality result tests whether the Collector pipeline preserved enough raw JSON content for an external post-export normalizer; it is not a claim of Collector-native EACP semantic mapping.",
            "Ten sequential paired replays on one host are summarized with median and quartiles; they are not independent-population samples and no inferential test is claimed.",
            "CPU and peak-memory utilization were not measured in this compact experiment.",
        ],
    }

    trials_path = args.output_dir / "trials.csv"
    with trials_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(trial_rows[0]))
        writer.writeheader()
        writer.writerows(trial_rows)
    summary_path = args.output_dir / "summary.json"
    summary_path.write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    environment_path = args.output_dir / "environment.json"
    environment_path.write_text(
        json.dumps(environment, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    checksums = checksums_for(args.output_dir)
    (args.output_dir / "SHA256SUMS").write_text(
        "".join(f"{digest}  {name}\n" for digest, name in checksums),
        encoding="utf-8",
    )
    print(json.dumps(summary["descriptive_results"], indent=2, sort_keys=True))
    print(f"Results written to {args.output_dir.name}")
    return 0


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    worker = subparsers.add_parser("eacp-worker", help=argparse.SUPPRESS)
    worker.add_argument("--input", type=Path, required=True)
    worker.add_argument("--database", type=Path, required=True)

    run = subparsers.add_parser("run")
    run.add_argument("--input", type=Path, required=True)
    run.add_argument("--reference-csv", type=Path)
    run.add_argument("--output-dir", type=Path, required=True)
    run.add_argument("--trials", type=int, default=10)
    run.add_argument("--timeout-seconds", type=float, default=30.0)
    run.add_argument("--keep-work", action="store_true")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    if args.command == "eacp-worker":
        create_eacp_database(args.input, args.database)
        return 0
    return orchestrate(args)


if __name__ == "__main__":
    raise SystemExit(main())
