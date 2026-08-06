#!/usr/bin/env python3
"""Reproducible pilot benchmark for the Evidence-Aware Control Plane (EACP).

The benchmark creates six heterogeneous, indexed SQLite source stores and a
separate append-only EACP evidence index.  It measures the extra cost of
normalizing and storing evidence metadata and compares warm-cache state and
correlation reconstruction queries against an indexed, tool-fragmented
baseline.  The workload is synthetic and deterministic; it does not represent
production traffic or a Kubernetes cluster.

Only Python's standard library is required.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import platform
import random
import resource
import sqlite3
import statistics
import subprocess
import sys
import tempfile
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Sequence


SOURCE_TYPES = (
    "deployment",
    "identity",
    "policy",
    "telemetry",
    "incident",
    "recovery",
)

SOURCE_TO_COMMON = {
    "deployment": {
        "actor": "principal",
        "service": "app",
        "intent": "release_integrity",
        "policy": "pipeline",
        "action": "change_type",
        "outcome": "status",
        "pointer": "record_uri",
        "correlation": "correlation",
        "timestamp": "event_time",
    },
    "identity": {
        "actor": "subject",
        "service": "resource_service",
        "intent": "least_privilege",
        "policy": "entitlement",
        "action": "operation",
        "outcome": "decision",
        "pointer": "log_ref",
        "correlation": "request_id",
        "timestamp": "ts",
    },
    "policy": {
        "actor": "caller",
        "service": "workload",
        "intent": "policy_conformance",
        "policy": "rule_id",
        "action": "verb",
        "outcome": "result",
        "pointer": "evidence_url",
        "correlation": "trace_key",
        "timestamp": "observed_at",
    },
    "telemetry": {
        "actor": "reporter",
        "service": "target",
        "intent": "service_availability",
        "policy": "objective",
        "action": "signal",
        "outcome": "state",
        "pointer": "query_ref",
        "correlation": "incident_key",
        "timestamp": "alert_time",
    },
    "incident": {
        "actor": "responder",
        "service": "affected_service",
        "intent": "incident_response",
        "policy": "objective",
        "action": "action",
        "outcome": "status",
        "pointer": "ticket_ref",
        "correlation": "incident_id",
        "timestamp": "changed_at",
    },
    "recovery": {
        "actor": "operator",
        "service": "system",
        "intent": "recoverability",
        "policy": "recovery_target",
        "action": "procedure",
        "outcome": "outcome",
        "pointer": "artifact_ref",
        "correlation": "ticket_id",
        "timestamp": "completed_at",
    },
}


RAW_SCHEMA = """
CREATE TABLE deployments (
  source_id INTEGER PRIMARY KEY, event_time TEXT NOT NULL, principal TEXT NOT NULL,
  app TEXT NOT NULL, pipeline TEXT NOT NULL, change_type TEXT NOT NULL,
  status TEXT NOT NULL, record_uri TEXT NOT NULL, correlation TEXT NOT NULL
);
CREATE INDEX dep_service_time ON deployments(app, event_time);
CREATE INDEX dep_correlation ON deployments(correlation, event_time);

CREATE TABLE identity_events (
  source_id INTEGER PRIMARY KEY, ts TEXT NOT NULL, subject TEXT NOT NULL,
  resource_service TEXT NOT NULL, entitlement TEXT NOT NULL, operation TEXT NOT NULL,
  decision TEXT NOT NULL, log_ref TEXT NOT NULL, request_id TEXT NOT NULL
);
CREATE INDEX iam_service_time ON identity_events(resource_service, ts);
CREATE INDEX iam_correlation ON identity_events(request_id, ts);

CREATE TABLE policy_decisions (
  source_id INTEGER PRIMARY KEY, observed_at TEXT NOT NULL, caller TEXT NOT NULL,
  workload TEXT NOT NULL, rule_id TEXT NOT NULL, verb TEXT NOT NULL,
  result TEXT NOT NULL, evidence_url TEXT NOT NULL, trace_key TEXT NOT NULL
);
CREATE INDEX pol_service_time ON policy_decisions(workload, observed_at);
CREATE INDEX pol_correlation ON policy_decisions(trace_key, observed_at);

CREATE TABLE telemetry_alerts (
  source_id INTEGER PRIMARY KEY, alert_time TEXT NOT NULL, reporter TEXT NOT NULL,
  target TEXT NOT NULL, objective TEXT NOT NULL, signal TEXT NOT NULL,
  state TEXT NOT NULL, query_ref TEXT NOT NULL, incident_key TEXT NOT NULL
);
CREATE INDEX tel_service_time ON telemetry_alerts(target, alert_time);
CREATE INDEX tel_correlation ON telemetry_alerts(incident_key, alert_time);

CREATE TABLE incidents (
  source_id INTEGER PRIMARY KEY, changed_at TEXT NOT NULL, responder TEXT NOT NULL,
  affected_service TEXT NOT NULL, objective TEXT NOT NULL, action TEXT NOT NULL,
  status TEXT NOT NULL, ticket_ref TEXT NOT NULL, incident_id TEXT NOT NULL
);
CREATE INDEX inc_service_time ON incidents(affected_service, changed_at);
CREATE INDEX inc_correlation ON incidents(incident_id, changed_at);

CREATE TABLE recovery_events (
  source_id INTEGER PRIMARY KEY, completed_at TEXT NOT NULL, operator TEXT NOT NULL,
  system TEXT NOT NULL, recovery_target TEXT NOT NULL, procedure TEXT NOT NULL,
  outcome TEXT NOT NULL, artifact_ref TEXT NOT NULL, ticket_id TEXT NOT NULL
);
CREATE INDEX rec_service_time ON recovery_events(system, completed_at);
CREATE INDEX rec_correlation ON recovery_events(ticket_id, completed_at);
"""


EACP_SCHEMA = """
CREATE TABLE evidence (
  evidence_id INTEGER PRIMARY KEY,
  source_type TEXT NOT NULL,
  source_id INTEGER NOT NULL,
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
CREATE INDEX ev_correlation ON evidence(correlation_id, source_ts);
CREATE INDEX ev_source_time ON evidence(source_type, source_ts);

CREATE TRIGGER evidence_no_update
BEFORE UPDATE ON evidence BEGIN
  SELECT RAISE(ABORT, 'evidence rows are append-only');
END;
CREATE TRIGGER evidence_no_delete
BEFORE DELETE ON evidence BEGIN
  SELECT RAISE(ABORT, 'evidence rows are append-only');
END;
"""


BASELINE_SERVICE_QUERY = """
SELECT event_time, principal, app, 'release_integrity', pipeline, change_type,
       status, record_uri, correlation, 'deployment'
  FROM deployments WHERE app = ?
UNION ALL
SELECT ts, subject, resource_service, 'least_privilege', entitlement, operation,
       decision, log_ref, request_id, 'identity'
  FROM identity_events WHERE resource_service = ?
UNION ALL
SELECT observed_at, caller, workload, 'policy_conformance', rule_id, verb,
       result, evidence_url, trace_key, 'policy'
  FROM policy_decisions WHERE workload = ?
UNION ALL
SELECT alert_time, reporter, target, 'service_availability', objective, signal,
       state, query_ref, incident_key, 'telemetry'
  FROM telemetry_alerts WHERE target = ?
UNION ALL
SELECT changed_at, responder, affected_service, 'incident_response', objective,
       action, status, ticket_ref, incident_id, 'incident'
  FROM incidents WHERE affected_service = ?
UNION ALL
SELECT completed_at, operator, system, 'recoverability', recovery_target,
       procedure, outcome, artifact_ref, ticket_id, 'recovery'
  FROM recovery_events WHERE system = ?
ORDER BY 1, 10
"""


BASELINE_CORRELATION_QUERY = """
SELECT event_time, principal, app, 'release_integrity', pipeline, change_type,
       status, record_uri, correlation, 'deployment'
  FROM deployments WHERE correlation = ?
UNION ALL
SELECT ts, subject, resource_service, 'least_privilege', entitlement, operation,
       decision, log_ref, request_id, 'identity'
  FROM identity_events WHERE request_id = ?
UNION ALL
SELECT observed_at, caller, workload, 'policy_conformance', rule_id, verb,
       result, evidence_url, trace_key, 'policy'
  FROM policy_decisions WHERE trace_key = ?
UNION ALL
SELECT alert_time, reporter, target, 'service_availability', objective, signal,
       state, query_ref, incident_key, 'telemetry'
  FROM telemetry_alerts WHERE incident_key = ?
UNION ALL
SELECT changed_at, responder, affected_service, 'incident_response', objective,
       action, status, ticket_ref, incident_id, 'incident'
  FROM incidents WHERE incident_id = ?
UNION ALL
SELECT completed_at, operator, system, 'recoverability', recovery_target,
       procedure, outcome, artifact_ref, ticket_id, 'recovery'
  FROM recovery_events WHERE ticket_id = ?
ORDER BY 1, 10
"""


EACP_SERVICE_QUERY = """
SELECT source_ts, actor, service, intent, policy, action, outcome,
       source_pointer, correlation_id, source_type
  FROM evidence WHERE service = ?
ORDER BY source_ts, source_type
"""


EACP_CORRELATION_QUERY = """
SELECT source_ts, actor, service, intent, policy, action, outcome,
       source_pointer, correlation_id, source_type
  FROM evidence WHERE correlation_id = ?
ORDER BY source_ts, source_type
"""


BASELINE_FULL_QUERY = """
SELECT event_time, principal, app, 'release_integrity', pipeline, change_type,
       status, record_uri, correlation, 'deployment' FROM deployments
UNION ALL
SELECT ts, subject, resource_service, 'least_privilege', entitlement, operation,
       decision, log_ref, request_id, 'identity' FROM identity_events
UNION ALL
SELECT observed_at, caller, workload, 'policy_conformance', rule_id, verb,
       result, evidence_url, trace_key, 'policy' FROM policy_decisions
UNION ALL
SELECT alert_time, reporter, target, 'service_availability', objective, signal,
       state, query_ref, incident_key, 'telemetry' FROM telemetry_alerts
UNION ALL
SELECT changed_at, responder, affected_service, 'incident_response', objective,
       action, status, ticket_ref, incident_id, 'incident' FROM incidents
UNION ALL
SELECT completed_at, operator, system, 'recoverability', recovery_target,
       procedure, outcome, artifact_ref, ticket_id, 'recovery' FROM recovery_events
ORDER BY 1, 10
"""


EACP_FULL_QUERY = """
SELECT source_ts, actor, service, intent, policy, action, outcome,
       source_pointer, correlation_id, source_type
  FROM evidence ORDER BY source_ts, source_type
"""


def percentile(values: Sequence[float], p: float) -> float:
    """Linear-interpolated percentile compatible with small stdlib installs."""
    if not values:
        raise ValueError("cannot calculate percentile of an empty sequence")
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    rank = (len(ordered) - 1) * p
    lo = int(rank)
    hi = min(lo + 1, len(ordered) - 1)
    fraction = rank - lo
    return ordered[lo] * (1.0 - fraction) + ordered[hi] * fraction


def utc_string(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def make_event(index: int, service_count: int, seed: int) -> dict[str, Any]:
    """Create one deterministic heterogeneous event.

    Every six consecutive events form a cross-plane chain with one correlation
    identifier and service.  A hash-based permutation prevents service order
    from being tied to insertion order while remaining deterministic.
    """
    chain = index // len(SOURCE_TYPES)
    source_type = SOURCE_TYPES[index % len(SOURCE_TYPES)]
    # 161 is coprime with the default service count (200), so each consecutive
    # block of 200 chains visits every service exactly once.
    service_number = ((chain * 161) + seed) % service_count
    service = f"svc-{service_number:04d}"
    correlation = f"corr-{seed:04d}-{chain:08d}"
    moment = datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(milliseconds=index * 250)
    timestamp = utc_string(moment)
    source_id = index + 1
    rare_failure = (chain + seed) % 23 == 0
    rare_denial = (chain + seed) % 31 == 0

    common = {"source_type": source_type, "source_id": source_id}
    if source_type == "deployment":
        common.update(
            event_time=timestamp,
            principal=f"pipeline-bot-{chain % 7}",
            app=service,
            pipeline=f"release-{chain % 12}",
            change_type="rollout",
            status="failed" if rare_failure else "succeeded",
            record_uri=f"ci://runs/{source_id}",
            correlation=correlation,
        )
    elif source_type == "identity":
        common.update(
            ts=timestamp,
            subject=f"operator-{chain % 17}",
            resource_service=service,
            entitlement=f"role-{chain % 9}",
            operation="role_binding_review",
            decision="denied" if rare_denial else "allowed",
            log_ref=f"iam://events/{source_id}",
            request_id=correlation,
        )
    elif source_type == "policy":
        common.update(
            observed_at=timestamp,
            caller=f"admission-{chain % 3}",
            workload=service,
            rule_id=f"policy-{chain % 15}",
            verb="evaluate",
            result="deny" if rare_denial else "pass",
            evidence_url=f"policy://decisions/{source_id}",
            trace_key=correlation,
        )
    elif source_type == "telemetry":
        common.update(
            alert_time=timestamp,
            reporter=f"monitor-{chain % 5}",
            target=service,
            objective="availability-99.9",
            signal="health_transition",
            state="degraded" if rare_failure else "healthy",
            query_ref=f"otel://queries/{source_id}",
            incident_key=correlation,
        )
    elif source_type == "incident":
        common.update(
            changed_at=timestamp,
            responder=f"oncall-{chain % 11}",
            affected_service=service,
            objective="restore_service",
            action="open_or_update",
            status="investigating" if rare_failure else "closed-no-impact",
            ticket_ref=f"ticket://incidents/{source_id}",
            incident_id=correlation,
        )
    elif source_type == "recovery":
        common.update(
            completed_at=timestamp,
            operator=f"recovery-bot-{chain % 4}",
            system=service,
            recovery_target="rto-60m",
            procedure="verify_or_rollback",
            outcome="rolled-back" if rare_failure else "verified",
            artifact_ref=f"backup://checks/{source_id}",
            ticket_id=correlation,
        )
    return common


def generate_events(event_count: int, service_count: int, seed: int) -> Iterable[dict[str, Any]]:
    for index in range(event_count):
        yield make_event(index, service_count, seed)


def normalized_row(event: dict[str, Any], observed_ts: str) -> tuple[Any, ...]:
    mapping = SOURCE_TO_COMMON[event["source_type"]]
    row_without_hash = (
        event["source_type"],
        event["source_id"],
        event[mapping["timestamp"]],
        observed_ts,
        event[mapping["actor"]],
        event[mapping["service"]],
        mapping["intent"],
        event[mapping["policy"]],
        event[mapping["action"]],
        event[mapping["outcome"]],
        event[mapping["pointer"]],
        event[mapping["correlation"]],
    )
    canonical = json.dumps(row_without_hash, separators=(",", ":"), ensure_ascii=True)
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return row_without_hash + (digest,)


def configure(connection: sqlite3.Connection) -> None:
    connection.execute("PRAGMA journal_mode=DELETE")
    connection.execute("PRAGMA synchronous=FULL")
    connection.execute("PRAGMA temp_store=MEMORY")
    connection.execute("PRAGMA cache_size=-65536")
    connection.execute("PRAGMA foreign_keys=ON")


def insert_raw(connection: sqlite3.Connection, events: Sequence[dict[str, Any]]) -> None:
    grouped: dict[str, list[tuple[Any, ...]]] = defaultdict(list)
    for event in events:
        source_type = event["source_type"]
        if source_type == "deployment":
            grouped[source_type].append(tuple(event[k] for k in (
                "source_id", "event_time", "principal", "app", "pipeline", "change_type",
                "status", "record_uri", "correlation")))
        elif source_type == "identity":
            grouped[source_type].append(tuple(event[k] for k in (
                "source_id", "ts", "subject", "resource_service", "entitlement", "operation",
                "decision", "log_ref", "request_id")))
        elif source_type == "policy":
            grouped[source_type].append(tuple(event[k] for k in (
                "source_id", "observed_at", "caller", "workload", "rule_id", "verb",
                "result", "evidence_url", "trace_key")))
        elif source_type == "telemetry":
            grouped[source_type].append(tuple(event[k] for k in (
                "source_id", "alert_time", "reporter", "target", "objective", "signal",
                "state", "query_ref", "incident_key")))
        elif source_type == "incident":
            grouped[source_type].append(tuple(event[k] for k in (
                "source_id", "changed_at", "responder", "affected_service", "objective", "action",
                "status", "ticket_ref", "incident_id")))
        elif source_type == "recovery":
            grouped[source_type].append(tuple(event[k] for k in (
                "source_id", "completed_at", "operator", "system", "recovery_target", "procedure",
                "outcome", "artifact_ref", "ticket_id")))

    table_by_source = {
        "deployment": "deployments",
        "identity": "identity_events",
        "policy": "policy_decisions",
        "telemetry": "telemetry_alerts",
        "incident": "incidents",
        "recovery": "recovery_events",
    }
    with connection:
        for source_type, rows in grouped.items():
            connection.executemany(
                f"INSERT INTO {table_by_source[source_type]} VALUES (?,?,?,?,?,?,?,?,?)",
                rows,
            )


def insert_eacp(connection: sqlite3.Connection, events: Sequence[dict[str, Any]]) -> float:
    """Normalize and insert all evidence; return wall-clock seconds."""
    insert_sql = """
      INSERT INTO evidence (
        source_type, source_id, source_ts, observed_ts, actor, service, intent,
        policy, action, outcome, source_pointer, correlation_id, content_hash
      ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
    """
    start = time.perf_counter()
    with connection:
        for offset in range(0, len(events), 1000):
            batch = events[offset:offset + 1000]
            # In this deterministic synthetic workload, collection is modeled
            # as immediate.  Production source-to-observer latency is outside
            # the scope of this microbenchmark.
            rows = [
                normalized_row(
                    event,
                    event[SOURCE_TO_COMMON[event["source_type"]]["timestamp"]],
                )
                for event in batch
            ]
            connection.executemany(insert_sql, rows)
    return time.perf_counter() - start


def timed_fetch(connection: sqlite3.Connection, sql: str, params: Sequence[Any]) -> tuple[float, list[tuple[Any, ...]]]:
    start = time.perf_counter_ns()
    rows = connection.execute(sql, params).fetchall()
    elapsed_ms = (time.perf_counter_ns() - start) / 1_000_000
    return elapsed_ms, rows


def benchmark_query_pair(
    baseline: sqlite3.Connection,
    eacp: sqlite3.Connection,
    baseline_sql: str,
    eacp_sql: str,
    keys: Sequence[str],
    seed: int,
) -> tuple[list[float], list[float], int, list[int]]:
    del seed  # retained in the signature so callers document the trial seed
    baseline_times: list[float] = []
    eacp_times: list[float] = []
    verified_rows = 0
    row_counts: list[int] = []

    for position, key in enumerate(keys):
        baseline_params = (key,) * 6
        if position % 2 == 0:
            baseline_ms, baseline_rows = timed_fetch(baseline, baseline_sql, baseline_params)
            eacp_ms, eacp_rows = timed_fetch(eacp, eacp_sql, (key,))
        else:
            eacp_ms, eacp_rows = timed_fetch(eacp, eacp_sql, (key,))
            baseline_ms, baseline_rows = timed_fetch(baseline, baseline_sql, baseline_params)
        baseline_times.append(baseline_ms)
        eacp_times.append(eacp_ms)

        if baseline_rows != eacp_rows:
            raise AssertionError(f"baseline and EACP reconstruction differ for {key}")
        verified_rows += len(eacp_rows)
        row_counts.append(len(eacp_rows))
    return baseline_times, eacp_times, verified_rows, row_counts


def projection_digest(connection: sqlite3.Connection, sql: str) -> tuple[str, int]:
    digest = hashlib.sha256()
    count = 0
    for row in connection.execute(sql):
        digest.update(json.dumps(row, separators=(",", ":"), ensure_ascii=True).encode("utf-8"))
        digest.update(b"\n")
        count += 1
    return digest.hexdigest(), count


def explain(connection: sqlite3.Connection, sql: str, params: Sequence[Any]) -> list[str]:
    return [str(row[3]) for row in connection.execute("EXPLAIN QUERY PLAN " + sql, params)]


def db_size(connection: sqlite3.Connection, path: Path) -> int:
    connection.execute("ANALYZE")
    connection.execute("VACUUM")
    return path.stat().st_size


def run_trial(
    event_count: int,
    trial: int,
    service_count: int,
    query_samples: int,
    workdir: Path,
    keep_databases: bool,
) -> dict[str, Any]:
    # Workloads are nested by trial: the 10k and 50k datasets are prefixes of
    # the corresponding 100k dataset for the same seed.
    seed = 9137 + trial * 101
    events = list(generate_events(event_count, service_count, seed))
    baseline_path = workdir / f"baseline_{event_count}_{trial}.sqlite"
    eacp_path = workdir / f"eacp_{event_count}_{trial}.sqlite"

    baseline = sqlite3.connect(baseline_path)
    eacp = sqlite3.connect(eacp_path)
    configure(baseline)
    configure(eacp)
    baseline.executescript(RAW_SCHEMA)
    eacp.executescript(EACP_SCHEMA)
    insert_raw(baseline, events)
    ingest_seconds = insert_eacp(eacp, events)

    baseline_bytes = db_size(baseline, baseline_path)
    eacp_bytes = db_size(eacp, eacp_path)

    baseline_digest, baseline_projection_rows = projection_digest(baseline, BASELINE_FULL_QUERY)
    eacp_digest, eacp_projection_rows = projection_digest(eacp, EACP_FULL_QUERY)
    if baseline_projection_rows != event_count or eacp_projection_rows != event_count:
        raise AssertionError("full projection row count differs from the generated event count")
    if baseline_digest != eacp_digest:
        raise AssertionError("full fragmented and EACP projection digests differ")

    # Warm both caches with representative indexed queries.
    for service_index in range(service_count):
        key = f"svc-{service_index:04d}"
        baseline.execute(BASELINE_SERVICE_QUERY, (key,) * 6).fetchall()
        eacp.execute(EACP_SERVICE_QUERY, (key,)).fetchall()

    rng = random.Random(seed + 77)
    service_keys = [f"svc-{rng.randrange(service_count):04d}" for _ in range(query_samples)]
    chain_count = (event_count + len(SOURCE_TYPES) - 1) // len(SOURCE_TYPES)
    correlation_keys = [f"corr-{seed:04d}-{rng.randrange(chain_count):08d}" for _ in range(query_samples)]

    base_service, eacp_service, verified_service, service_row_counts = benchmark_query_pair(
        baseline, eacp, BASELINE_SERVICE_QUERY, EACP_SERVICE_QUERY,
        service_keys, seed + 1,
    )
    base_corr, eacp_corr, verified_corr, correlation_row_counts = benchmark_query_pair(
        baseline, eacp, BASELINE_CORRELATION_QUERY, EACP_CORRELATION_QUERY,
        correlation_keys, seed + 2,
    )

    result = {
        "event_count": event_count,
        "trial": trial,
        "seed": seed,
        "service_count": service_count,
        "query_samples": query_samples,
        "ingest_seconds": ingest_seconds,
        "ingest_us_per_event": ingest_seconds * 1_000_000 / event_count,
        "ingest_events_per_second": event_count / ingest_seconds,
        "baseline_db_bytes": baseline_bytes,
        "eacp_db_bytes": eacp_bytes,
        "baseline_bytes_per_event": baseline_bytes / event_count,
        "eacp_bytes_per_event": eacp_bytes / event_count,
        "eacp_to_baseline_storage_percent": eacp_bytes * 100.0 / baseline_bytes,
        "service_baseline_p50_ms": percentile(base_service, 0.50),
        "service_baseline_p95_ms": percentile(base_service, 0.95),
        "service_eacp_p50_ms": percentile(eacp_service, 0.50),
        "service_eacp_p95_ms": percentile(eacp_service, 0.95),
        "service_p95_speedup": percentile(base_service, 0.95) / percentile(eacp_service, 0.95),
        "correlation_baseline_p50_ms": percentile(base_corr, 0.50),
        "correlation_baseline_p95_ms": percentile(base_corr, 0.95),
        "correlation_eacp_p50_ms": percentile(eacp_corr, 0.50),
        "correlation_eacp_p95_ms": percentile(eacp_corr, 0.95),
        "correlation_p95_speedup": percentile(base_corr, 0.95) / percentile(eacp_corr, 0.95),
        "verified_rows": verified_service + verified_corr,
        "service_rows_per_query_mean": statistics.mean(service_row_counts),
        "correlation_rows_per_query_mean": statistics.mean(correlation_row_counts),
        "full_projection_rows": baseline_projection_rows,
        "full_projection_sha256": baseline_digest,
        "_query_plans": {
            "baseline_service": explain(baseline, BASELINE_SERVICE_QUERY, (service_keys[0],) * 6),
            "eacp_service": explain(eacp, EACP_SERVICE_QUERY, (service_keys[0],)),
            "baseline_correlation": explain(baseline, BASELINE_CORRELATION_QUERY, (correlation_keys[0],) * 6),
            "eacp_correlation": explain(eacp, EACP_CORRELATION_QUERY, (correlation_keys[0],)),
        },
    }

    baseline.close()
    eacp.close()
    if not keep_databases:
        baseline_path.unlink(missing_ok=True)
        eacp_path.unlink(missing_ok=True)
    return result


def summarize(rows: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[int(row["event_count"])].append(row)

    metrics = [
        "ingest_us_per_event",
        "ingest_events_per_second",
        "baseline_bytes_per_event",
        "eacp_bytes_per_event",
        "eacp_to_baseline_storage_percent",
        "service_baseline_p95_ms",
        "service_eacp_p95_ms",
        "service_p95_speedup",
        "correlation_baseline_p95_ms",
        "correlation_eacp_p95_ms",
        "correlation_p95_speedup",
        "service_rows_per_query_mean",
        "correlation_rows_per_query_mean",
    ]
    summary: list[dict[str, Any]] = []
    for event_count in sorted(grouped):
        item: dict[str, Any] = {
            "event_count": event_count,
            "trials": len(grouped[event_count]),
        }
        for metric in metrics:
            values = [float(row[metric]) for row in grouped[event_count]]
            item[f"{metric}_median"] = statistics.median(values)
            item[f"{metric}_q1"] = percentile(values, 0.25)
            item[f"{metric}_q3"] = percentile(values, 0.75)
            item[f"{metric}_min"] = min(values)
            item[f"{metric}_max"] = max(values)
        summary.append(item)
    return summary


def write_csv(path: Path, rows: Sequence[dict[str, Any]]) -> None:
    if not rows:
        return
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def environment_record(argv: Sequence[str]) -> dict[str, Any]:
    def sysctl_value(name: str) -> str | None:
        try:
            return subprocess.check_output(
                ["sysctl", "-n", name], text=True, stderr=subprocess.DEVNULL
            ).strip()
        except (FileNotFoundError, subprocess.CalledProcessError):
            return None

    return {
        "generated_at_utc": utc_string(datetime.now(timezone.utc)),
        "command": [sys.executable, *argv],
        "python": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "sqlite": sqlite3.sqlite_version,
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "cpu_count": os.cpu_count(),
        "cpu_brand": sysctl_value("machdep.cpu.brand_string"),
        "memory_bytes": sysctl_value("hw.memsize"),
        "max_rss_platform_units": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
    }


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sizes", nargs="+", type=int, default=[10_000, 50_000, 100_000])
    parser.add_argument("--trials", type=int, default=10)
    parser.add_argument("--services", type=int, default=200)
    parser.add_argument("--query-samples", type=int, default=300)
    parser.add_argument("--output", type=Path, default=Path(__file__).resolve().parent / "results")
    parser.add_argument("--keep-databases", action="store_true")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    actual_argv = list(sys.argv[1:] if argv is None else argv)
    args = parse_args(actual_argv)
    args.output.mkdir(parents=True, exist_ok=True)
    workdir = args.output / "work"
    workdir.mkdir(parents=True, exist_ok=True)

    trial_rows: list[dict[str, Any]] = []
    query_plans: dict[str, Any] | None = None
    for event_count in args.sizes:
        for trial in range(1, args.trials + 1):
            result = run_trial(
                event_count=event_count,
                trial=trial,
                service_count=args.services,
                query_samples=args.query_samples,
                workdir=workdir,
                keep_databases=args.keep_databases,
            )
            if query_plans is None:
                query_plans = result.pop("_query_plans")
            else:
                result.pop("_query_plans")
            trial_rows.append(result)
            print(
                f"size={event_count} trial={trial}/{args.trials} "
                f"ingest={result['ingest_events_per_second']:.0f} ev/s "
                f"service_p95={result['service_eacp_p95_ms']:.3f} ms "
                f"corr_p95={result['correlation_eacp_p95_ms']:.3f} ms",
                flush=True,
            )

    summary_rows = summarize(trial_rows)
    write_csv(args.output / "trial_results.csv", trial_rows)
    write_csv(args.output / "summary_results.csv", summary_rows)
    (args.output / "environment.json").write_text(
        json.dumps(environment_record(actual_argv), indent=2) + "\n",
        encoding="utf-8",
    )
    (args.output / "summary_results.json").write_text(
        json.dumps(summary_rows, indent=2) + "\n",
        encoding="utf-8",
    )
    (args.output / "query_plans.json").write_text(
        json.dumps(query_plans, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"results={args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
