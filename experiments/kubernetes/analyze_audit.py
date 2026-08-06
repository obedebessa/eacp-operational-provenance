#!/usr/bin/env python3
"""Normalize real Kubernetes audit records into the EACP evidence schema.

The script uses only Python's standard library. It preserves a namespace-
filtered JSONL dataset, creates both a raw SQLite store and an indexed,
append-only EACP store, and records descriptive and microbenchmark results.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import platform
import random
import re
import sqlite3
import statistics
import tempfile
import time
from collections import Counter
from pathlib import Path
from typing import Any, Iterable


EACP_SCHEMA = """
CREATE TABLE evidence (
  evidence_id INTEGER PRIMARY KEY,
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

RAW_SCHEMA = """
CREATE TABLE raw_audit (
  row_id INTEGER PRIMARY KEY,
  audit_id TEXT NOT NULL,
  event_json TEXT NOT NULL
);
CREATE INDEX raw_audit_id ON raw_audit(audit_id);
"""


def percentile(values: list[float], probability: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    position = (len(ordered) - 1) * probability
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    fraction = position - lower
    return ordered[lower] * (1.0 - fraction) + ordered[upper] * fraction


def canonical_json(record: dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


LOCAL_PATH_PATTERN = re.compile(
    r"/(?:Users|home|private/tmp|private/var/folders|tmp|var/folders)/[^\s\"']+"
)


def sanitize_for_public(value: Any, key: str = "") -> Any:
    """Remove client IPs and host/container filesystem paths from public data."""
    if isinstance(value, dict):
        sanitized: dict[str, Any] = {}
        for child_key, child_value in value.items():
            if child_key == "sourceIPs":
                continue
            if child_key in {
                "authentication.kubernetes.io/credential-id",
                "authentication.kubernetes.io/issued-credential-id",
            }:
                continue
            if child_key.lower() in {"ca.crt", "tls.crt", "certificate-authority-data"}:
                continue
            if child_key == "serviceAccountToken":
                sanitized[child_key] = "<redacted-service-account-token-projection>"
                continue
            if child_key.lower() in {"token", "client-certificate-data", "client-key-data"}:
                sanitized[child_key] = "<redacted-sensitive-value>"
                continue
            if child_key.lower() in {"mountpath", "hostpath"} and isinstance(child_value, str):
                sanitized[child_key] = "<redacted-absolute-path>" if child_value.startswith("/") else child_value
                continue
            sanitized[child_key] = sanitize_for_public(child_value, child_key)
        return sanitized
    if isinstance(value, list):
        return [sanitize_for_public(item, key) for item in value]
    if isinstance(value, str):
        # requestURI is an API identifier rather than a filesystem path and is
        # required to interpret an audit record, so it is intentionally kept.
        if key != "requestURI" and key.lower().endswith("path") and value.startswith("/"):
            return "<redacted-absolute-path>"
        if "-----BEGIN CERTIFICATE-----" in value:
            return "<redacted-certificate>"
        return LOCAL_PATH_PATTERN.sub("<redacted-local-path>", value)
    return value


def effective_actor(record: dict[str, Any]) -> str:
    """Return the identity whose authorization was evaluated."""
    impersonated = record.get("impersonatedUser") or {}
    authenticated = record.get("user") or {}
    return str(impersonated.get("username") or authenticated.get("username") or "unknown")


def iter_audit_records(path: Path) -> Iterable[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                value = json.loads(stripped)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid JSON on audit-log line {line_number}: {exc}") from exc
            if isinstance(value, dict):
                yield value


def record_namespace(record: dict[str, Any]) -> str:
    object_ref = record.get("objectRef") or {}
    namespace = object_ref.get("namespace")
    if namespace:
        return str(namespace)
    request_uri = str(record.get("requestURI") or "")
    marker = "/namespaces/"
    if marker in request_uri:
        return request_uri.split(marker, 1)[1].split("/", 1)[0]
    return ""


def object_metadata(record: dict[str, Any]) -> dict[str, Any]:
    for candidate_name in ("requestObject", "responseObject"):
        candidate = record.get(candidate_name)
        if not isinstance(candidate, dict):
            continue
        metadata = candidate.get("metadata")
        if isinstance(metadata, dict):
            return metadata
    return {}


def normalize(record: dict[str, Any], namespace: str) -> tuple[str, ...]:
    object_ref = record.get("objectRef") or {}
    metadata = object_metadata(record)
    labels = metadata.get("labels") if isinstance(metadata.get("labels"), dict) else {}
    annotations = metadata.get("annotations") if isinstance(metadata.get("annotations"), dict) else {}

    resource = str(object_ref.get("resource") or "unknown-resource")
    name = str(object_ref.get("name") or metadata.get("name") or resource)
    workload_name = str(labels.get("app.kubernetes.io/name") or name)
    service = f"{namespace}/{workload_name}"

    audit_id = str(record.get("auditID") or hashlib.sha256(canonical_json(record).encode()).hexdigest())
    stage = str(record.get("stage") or "unknown-stage")
    source_id = f"{audit_id}:{stage}"
    source_ts = str(record.get("requestReceivedTimestamp") or record.get("stageTimestamp") or "")
    observed_ts = str(record.get("stageTimestamp") or source_ts)
    actor = effective_actor(record)
    action = str(record.get("verb") or "unknown")
    status = record.get("responseStatus") or {}
    code = str(status.get("code") or "unknown")
    reason = str(status.get("reason") or status.get("status") or "")
    outcome = f"{code}:{reason}" if reason else code
    explicit_correlation = str(annotations.get("eacp.io/correlation-id") or "")
    correlation_id = explicit_correlation or (f"k8s://{namespace}/{resource}/{name}" if name else audit_id)
    serialized = canonical_json(record)
    content_hash = hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    return (
        "kubernetes.audit",
        source_id,
        source_ts,
        observed_ts,
        actor,
        service,
        "operational_provenance",
        "kubernetes-rbac-admission",
        action,
        outcome,
        f"kubernetes-audit://{audit_id}",
        correlation_id,
        content_hash,
    )


def open_db(path: Path, schema: str) -> sqlite3.Connection:
    connection = sqlite3.connect(path)
    connection.execute("PRAGMA journal_mode=DELETE")
    connection.execute("PRAGMA synchronous=FULL")
    connection.executescript(schema)
    return connection


def insert_raw(path: Path, records: list[dict[str, Any]]) -> float:
    connection = open_db(path, RAW_SCHEMA)
    rows = [
        (str(record.get("auditID") or ""), canonical_json(record))
        for record in records
    ]
    started = time.perf_counter_ns()
    with connection:
        connection.executemany(
            "INSERT INTO raw_audit(audit_id, event_json) VALUES (?, ?)", rows
        )
    elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000
    connection.close()
    return elapsed_ms


def insert_eacp(path: Path, rows: list[tuple[str, ...]]) -> float:
    connection = open_db(path, EACP_SCHEMA)
    started = time.perf_counter_ns()
    with connection:
        connection.executemany(
            """
            INSERT INTO evidence(
              source_type, source_id, source_ts, observed_ts, actor, service,
              intent, policy, action, outcome, source_pointer, correlation_id,
              content_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            rows,
        )
    elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000
    connection.close()
    return elapsed_ms


def benchmark_queries(
    database: Path,
    column: str,
    values: list[str],
    repetitions: int,
    seed: int,
) -> dict[str, Any]:
    if not values:
        return {"repetitions": 0, "median_ms": 0.0, "p95_ms": 0.0, "mean_rows": 0.0}
    connection = sqlite3.connect(database)
    query = (
        f"SELECT source_ts, actor, service, action, outcome, correlation_id "
        f"FROM evidence WHERE {column} = ? ORDER BY source_ts"
    )
    rng = random.Random(seed)
    timings: list[float] = []
    row_counts: list[int] = []
    for _ in range(repetitions):
        value = rng.choice(values)
        started = time.perf_counter_ns()
        rows = connection.execute(query, (value,)).fetchall()
        timings.append((time.perf_counter_ns() - started) / 1_000_000)
        row_counts.append(len(rows))
    plan = [list(row) for row in connection.execute(f"EXPLAIN QUERY PLAN {query}", (values[0],))]
    connection.close()
    return {
        "repetitions": repetitions,
        "median_ms": statistics.median(timings),
        "p95_ms": percentile(timings, 0.95),
        "mean_rows": statistics.fmean(row_counts),
        "query_plan": plan,
    }


def verify_append_only(database: Path) -> dict[str, bool]:
    connection = sqlite3.connect(database)
    update_blocked = False
    delete_blocked = False
    try:
        connection.execute("UPDATE evidence SET outcome = outcome WHERE evidence_id = 1")
    except sqlite3.IntegrityError:
        update_blocked = True
    try:
        connection.execute("DELETE FROM evidence WHERE evidence_id = 1")
    except sqlite3.IntegrityError:
        delete_blocked = True
    connection.rollback()
    connection.close()
    return {"update_blocked": update_blocked, "delete_blocked": delete_blocked}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--audit-log", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--namespace", default="eacp-k8s-eval")
    parser.add_argument("--trials", type=int, default=10)
    parser.add_argument("--queries", type=int, default=300)
    args = parser.parse_args()

    if args.trials < 1 or args.queries < 1:
        parser.error("--trials and --queries must be positive")
    if not args.audit_log.is_file():
        parser.error(f"audit log does not exist: {args.audit_log}")

    args.output_dir.mkdir(parents=True, exist_ok=True)
    parsing_started = time.perf_counter_ns()
    all_records = list(iter_audit_records(args.audit_log))
    filtered_private = [
        record for record in all_records
        if record_namespace(record) == args.namespace
        and str((record.get("objectRef") or {}).get("subresource") or "") != "token"
    ]
    filtered = [sanitize_for_public(record) for record in filtered_private]
    normalized = [normalize(record, args.namespace) for record in filtered]
    parsing_ms = (time.perf_counter_ns() - parsing_started) / 1_000_000
    if not filtered:
        raise SystemExit(f"no audit events found for namespace {args.namespace!r}")

    filtered_jsonl = args.output_dir / "public_filtered_audit.jsonl"
    with filtered_jsonl.open("w", encoding="utf-8") as handle:
        for record in filtered:
            handle.write(canonical_json(record) + "\n")

    normalized_csv = args.output_dir / "normalized_evidence.csv"
    headers = [
        "source_type", "source_id", "source_ts", "observed_ts", "actor",
        "service", "intent", "policy", "action", "outcome",
        "source_pointer", "correlation_id", "content_hash",
    ]
    with normalized_csv.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(headers)
        writer.writerows(normalized)

    raw_timings: list[float] = []
    eacp_timings: list[float] = []
    with tempfile.TemporaryDirectory(prefix="eacp-k8s-benchmark-") as temporary:
        temporary_path = Path(temporary)
        for trial in range(args.trials):
            raw_timings.append(insert_raw(temporary_path / f"raw-{trial}.sqlite", filtered))
            eacp_timings.append(insert_eacp(temporary_path / f"eacp-{trial}.sqlite", normalized))

    raw_db = args.output_dir / "kubernetes_audit_raw.sqlite"
    eacp_db = args.output_dir / "kubernetes_eacp.sqlite"
    for path in (raw_db, eacp_db):
        if path.exists():
            raise SystemExit(f"refusing to overwrite existing result: {path}")
    insert_raw(raw_db, filtered)
    insert_eacp(eacp_db, normalized)

    connection = sqlite3.connect(eacp_db)
    eacp_count = connection.execute("SELECT COUNT(*) FROM evidence").fetchone()[0]
    distinct_hashes = connection.execute("SELECT COUNT(DISTINCT content_hash) FROM evidence").fetchone()[0]
    service_values = [row[0] for row in connection.execute("SELECT DISTINCT service FROM evidence")]
    correlation_values = [row[0] for row in connection.execute("SELECT DISTINCT correlation_id FROM evidence")]
    connection.close()

    verb_counts = Counter(str(record.get("verb") or "unknown") for record in filtered)
    resource_counts = Counter(str((record.get("objectRef") or {}).get("resource") or "unknown") for record in filtered)
    actor_counts = Counter(effective_actor(record) for record in filtered)
    status_counts = Counter(str((record.get("responseStatus") or {}).get("code") or "unknown") for record in filtered)
    kubectl_events = sum(1 for record in filtered if str(record.get("userAgent") or "").startswith("kubectl/"))
    denied_actor = f"system:serviceaccount:{args.namespace}:eacp-observer"
    denied_records = [
        record for record in filtered
        if effective_actor(record) == denied_actor
        and int((record.get("responseStatus") or {}).get("code") or 0) == 403
    ]
    explicit_correlation_records = sum(
        1 for row in normalized if row[11].startswith("eacp-round-")
    )

    summary = {
        "experiment": "EACP ingestion of real Kubernetes API-server audit records",
        "scope": {
            "namespace": args.namespace,
            "total_audit_records": len(all_records),
            "namespace_audit_records": len(filtered),
            "kubectl_initiated_records": kubectl_events,
            "unique_audit_ids": len({str(record.get('auditID') or '') for record in filtered}),
        },
        "distribution": {
            "verbs": dict(sorted(verb_counts.items())),
            "resources": dict(sorted(resource_counts.items())),
            "actors": dict(sorted(actor_counts.items())),
            "http_status_codes": dict(sorted(status_counts.items())),
        },
        "rbac_denials": {
            "expected_actor": denied_actor,
            "count": len(denied_records),
            "verbs": dict(sorted(Counter(str(record.get("verb") or "unknown") for record in denied_records).items())),
            "resources": dict(sorted(Counter(str((record.get("objectRef") or {}).get("resource") or "unknown") for record in denied_records).items())),
            "all_status_403": all(int((record.get("responseStatus") or {}).get("code") or 0) == 403 for record in denied_records),
        },
        "normalization": {
            "elapsed_ms": parsing_ms,
            "microseconds_per_namespace_event": parsing_ms * 1000 / len(filtered),
            "normalized_rows": len(normalized),
            "rows_with_explicit_workload_correlation": explicit_correlation_records,
        },
        "persistence_trials": {
            "count": args.trials,
            "raw_sqlite_median_ms": statistics.median(raw_timings),
            "raw_sqlite_p95_ms": percentile(raw_timings, 0.95),
            "eacp_sqlite_median_ms": statistics.median(eacp_timings),
            "eacp_sqlite_p95_ms": percentile(eacp_timings, 0.95),
            "eacp_median_microseconds_per_event": statistics.median(eacp_timings) * 1000 / len(filtered),
        },
        "query_microbenchmark": {
            "service": benchmark_queries(eacp_db, "service", service_values, args.queries, 20260805),
            "correlation": benchmark_queries(eacp_db, "correlation_id", correlation_values, args.queries, 20260806),
        },
        "integrity": {
            "row_count_matches_filtered_input": eacp_count == len(filtered),
            "stored_rows": eacp_count,
            "distinct_content_hashes": distinct_hashes,
            "append_only_triggers": verify_append_only(eacp_db),
        },
        "artifact_sizes_bytes": {
            "local_qa_complete_audit_log": args.audit_log.stat().st_size,
            "public_filtered_audit_jsonl": filtered_jsonl.stat().st_size,
            "normalized_evidence_csv": normalized_csv.stat().st_size,
            "raw_sqlite": raw_db.stat().st_size,
            "eacp_sqlite": eacp_db.stat().st_size,
        },
        "runtime": {
            "python": platform.python_version(),
            "sqlite": sqlite3.sqlite_version,
            "platform": platform.platform(),
            "machine": platform.machine(),
            "logical_cpus": os.cpu_count(),
        },
        "privacy": {
            "public_dataset_is_namespace_filtered": True,
            "audit_sourceIPs_fields_removed": True,
            "absolute_filesystem_paths_redacted": True,
            "certificates_redacted": True,
            "credential_identifiers_removed": True,
            "service_account_token_projections_redacted": True,
            "token_subresource_records_excluded": True,
            "complete_audit_log_is_local_qa_only": True,
        },
        "limitations": [
            "Single-node local kind cluster; results do not estimate production-scale throughput or availability.",
            "One namespace and a compact CRUD-oriented workload; managed-cloud control planes may behave differently.",
            "The persistence and query measurements are local microbenchmarks over one captured audit dataset.",
            "Kubernetes audit records cover the API plane only; telemetry, identity-provider, incident, and recovery sources remain outside this experiment.",
            "RequestResponse logging was restricted to non-secret resources; the complete audit log should still be reviewed before public release.",
        ],
    }
    output = args.output_dir / "summary.json"
    output.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
