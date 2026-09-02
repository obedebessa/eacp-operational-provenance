#!/usr/bin/env python3
"""Paired index-ablation experiment for the EACP SQLite benchmark.

The experiment imports the published benchmark implementation directly.  It
uses its event generator, normalization and hashing path, SQLite connection
configuration, evidence table schema, queries, and seed schedule.  Treatments
remove only the service and/or correlation lookup indexes from that schema.

Only Python's standard library is required.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import importlib.util
import json
import os
import platform
import random
import resource
import sqlite3
import statistics
import subprocess
import sys
import time
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence


EXPERIMENT_DIR = Path(__file__).resolve().parent
REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
BENCHMARK_PATH = REPOSITORY_ROOT / "benchmark" / "sqlite" / "eacp_benchmark.py"
EXPERIMENT_SOURCE_PATH = Path(__file__).resolve()
RESULT_SCHEMA_VERSION = "1.0"


def _load_original_benchmark() -> Any:
    """Load the benchmark by path so no copied generator or schema can drift."""

    spec = importlib.util.spec_from_file_location(
        "eacp_published_sqlite_benchmark", BENCHMARK_PATH
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import benchmark from {BENCHMARK_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ORIGINAL = _load_original_benchmark()


SERVICE_INDEX_SQL = (
    "CREATE INDEX ev_service_time ON evidence(service, source_ts);"
)
CORRELATION_INDEX_SQL = (
    "CREATE INDEX ev_correlation ON evidence(correlation_id, source_ts);"
)
SOURCE_INDEX_SQL = (
    "CREATE INDEX ev_source_time ON evidence(source_type, source_ts);"
)


@dataclass(frozen=True)
class Variant:
    name: str
    service_index: bool
    correlation_index: bool


VARIANTS = (
    Variant("full_indexes", True, True),
    Variant("no_service_index", False, True),
    Variant("no_correlation_index", True, False),
    Variant("no_lookup_indexes", False, False),
)
VARIANT_BY_NAME = {variant.name: variant for variant in VARIANTS}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def row_digest(rows: Sequence[tuple[Any, ...]]) -> str:
    digest = hashlib.sha256()
    for row in rows:
        digest.update(
            json.dumps(row, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        )
        digest.update(b"\n")
    return digest.hexdigest()


def schema_for_variant(variant: Variant) -> str:
    """Return the exact original EACP schema minus treatment indexes."""

    schema = ORIGINAL.EACP_SCHEMA
    for statement in (SERVICE_INDEX_SQL, CORRELATION_INDEX_SQL, SOURCE_INDEX_SQL):
        if schema.count(statement) != 1:
            raise AssertionError(
                "published benchmark schema changed; expected exactly one occurrence "
                f"of {statement!r}"
            )
    if not variant.service_index:
        schema = schema.replace(SERVICE_INDEX_SQL, "")
    if not variant.correlation_index:
        schema = schema.replace(CORRELATION_INDEX_SQL, "")
    return schema


def user_index_names(connection: sqlite3.Connection) -> list[str]:
    return sorted(
        str(row[1])
        for row in connection.execute("PRAGMA index_list('evidence')")
        if not str(row[1]).startswith("sqlite_autoindex_")
    )


def dbstat_bytes(connection: sqlite3.Connection) -> dict[str, int] | None:
    """Return per-object bytes when SQLite exposes the optional dbstat table."""

    try:
        return {
            str(name): int(size)
            for name, size in connection.execute(
                "SELECT name, SUM(pgsize) FROM dbstat GROUP BY name ORDER BY name"
            )
        }
    except sqlite3.OperationalError:
        return None


def balanced_order(offset: int) -> list[Variant]:
    start = offset % len(VARIANTS)
    return list(VARIANTS[start:] + VARIANTS[:start])


def exact_query_keys(
    event_count: int,
    service_count: int,
    query_samples: int,
    seed: int,
) -> tuple[list[str], list[str]]:
    """Use the same key-generation sequence as the published benchmark."""

    rng = random.Random(seed + 77)
    service_keys = [
        f"svc-{rng.randrange(service_count):04d}" for _ in range(query_samples)
    ]
    chain_count = (
        event_count + len(ORIGINAL.SOURCE_TYPES) - 1
    ) // len(ORIGINAL.SOURCE_TYPES)
    correlation_keys = [
        f"corr-{seed:04d}-{rng.randrange(chain_count):08d}"
        for _ in range(query_samples)
    ]
    return service_keys, correlation_keys


def _expected_indexes(variant: Variant) -> list[str]:
    names = ["ev_source_time"]
    if variant.service_index:
        names.append("ev_service_time")
    if variant.correlation_index:
        names.append("ev_correlation")
    return sorted(names)


def create_database(
    path: Path,
    events: Sequence[dict[str, Any]],
    variant: Variant,
) -> tuple[sqlite3.Connection, dict[str, Any]]:
    path.unlink(missing_ok=True)
    connection = sqlite3.connect(path)
    ORIGINAL.configure(connection)
    connection.executescript(schema_for_variant(variant))

    ingest_seconds = ORIGINAL.insert_eacp(connection, events)
    database_bytes = ORIGINAL.db_size(connection, path)
    integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
    if integrity != "ok":
        raise AssertionError(f"SQLite integrity check failed for {variant.name}: {integrity}")

    indexes = user_index_names(connection)
    if indexes != _expected_indexes(variant):
        raise AssertionError(
            f"unexpected indexes for {variant.name}: {indexes}; "
            f"expected {_expected_indexes(variant)}"
        )

    projection_sha256, projection_rows = ORIGINAL.projection_digest(
        connection, ORIGINAL.EACP_FULL_QUERY
    )
    page_size = int(connection.execute("PRAGMA page_size").fetchone()[0])
    page_count = int(connection.execute("PRAGMA page_count").fetchone()[0])
    if page_size * page_count != database_bytes:
        raise AssertionError("SQLite page accounting differs from database file size")

    object_bytes = dbstat_bytes(connection)
    autoindex_bytes = None
    retained_source_index_bytes = None
    ablated_lookup_index_bytes = None
    if object_bytes is not None:
        autoindex_bytes = object_bytes.get("sqlite_autoindex_evidence_1", 0)
        retained_source_index_bytes = object_bytes.get("ev_source_time", 0)
        ablated_lookup_index_bytes = sum(
            object_bytes.get(name, 0)
            for name in ("ev_service_time", "ev_correlation")
        )

    metadata = {
        "ingest_seconds": ingest_seconds,
        "ingest_us_per_event": ingest_seconds * 1_000_000 / len(events),
        "ingest_events_per_second": len(events) / ingest_seconds,
        "database_bytes": database_bytes,
        "database_bytes_per_event": database_bytes / len(events),
        "page_size_bytes": page_size,
        "page_count": page_count,
        "dbstat_available": int(object_bytes is not None),
        "dbstat_table_bytes": (
            None if object_bytes is None else object_bytes.get("evidence", 0)
        ),
        "dbstat_unique_autoindex_bytes": autoindex_bytes,
        "dbstat_retained_source_index_bytes": retained_source_index_bytes,
        "dbstat_lookup_index_bytes": ablated_lookup_index_bytes,
        "projection_rows": projection_rows,
        "projection_sha256": projection_sha256,
        "integrity_check": integrity,
        "user_indexes": indexes,
    }
    return connection, metadata


def warm_connections(
    connections: Mapping[str, sqlite3.Connection],
    service_keys: Sequence[str],
    correlation_keys: Sequence[str],
    trial: int,
) -> None:
    """Run every measured key once before timed warm-cache measurements."""

    query_specs = (
        (ORIGINAL.EACP_SERVICE_QUERY, service_keys),
        (ORIGINAL.EACP_CORRELATION_QUERY, correlation_keys),
    )
    for query_number, (sql, keys) in enumerate(query_specs):
        for position, key in enumerate(keys):
            for variant in balanced_order(trial + query_number + position):
                connections[variant.name].execute(sql, (key,)).fetchall()


def measure_warm_queries(
    connections: Mapping[str, sqlite3.Connection],
    event_count: int,
    trial: int,
    seed: int,
    service_keys: Sequence[str],
    correlation_keys: Sequence[str],
) -> tuple[list[dict[str, Any]], dict[str, dict[str, list[float]]], int]:
    """Measure paired queries and require row-for-row equality."""

    measurements: list[dict[str, Any]] = []
    timings = {
        variant.name: {"service": [], "correlation": []}
        for variant in VARIANTS
    }
    verified_rows = 0
    query_specs = (
        ("service", ORIGINAL.EACP_SERVICE_QUERY, service_keys),
        ("correlation", ORIGINAL.EACP_CORRELATION_QUERY, correlation_keys),
    )

    for query_number, (query_type, sql, keys) in enumerate(query_specs):
        for position, key in enumerate(keys):
            rows_by_variant: dict[str, list[tuple[Any, ...]]] = {}
            elapsed_by_variant: dict[str, float] = {}
            for variant in balanced_order(trial + query_number + position):
                elapsed_ms, rows = ORIGINAL.timed_fetch(
                    connections[variant.name], sql, (key,)
                )
                elapsed_by_variant[variant.name] = elapsed_ms
                rows_by_variant[variant.name] = rows
                timings[variant.name][query_type].append(elapsed_ms)

            reference_rows = rows_by_variant["full_indexes"]
            for variant in VARIANTS:
                if rows_by_variant[variant.name] != reference_rows:
                    raise AssertionError(
                        f"query output differs for {query_type} key {key} "
                        f"in {variant.name}"
                    )
            verified_rows += len(reference_rows)
            measurements.append(
                {
                    "event_count": event_count,
                    "trial": trial,
                    "seed": seed,
                    "query_type": query_type,
                    "sample_position": position,
                    "query_key": key,
                    "row_count": len(reference_rows),
                    "row_sha256": row_digest(reference_rows),
                    **{
                        f"{variant.name}_ms": elapsed_by_variant[variant.name]
                        for variant in VARIANTS
                    },
                }
            )
    return measurements, timings, verified_rows


def fresh_connection_fetch(
    path: Path,
    sql: str,
    key: str,
) -> tuple[float, list[tuple[Any, ...]]]:
    """Time connect plus the first query using a new SQLite page cache.

    The operating-system page cache is deliberately not claimed to be cold.
    """

    start = time.perf_counter_ns()
    connection = sqlite3.connect(path)
    try:
        rows = connection.execute(sql, (key,)).fetchall()
    finally:
        connection.close()
    elapsed_ms = (time.perf_counter_ns() - start) / 1_000_000
    return elapsed_ms, rows


def measure_cold_open_queries(
    paths: Mapping[str, Path],
    event_count: int,
    trial: int,
    seed: int,
    service_keys: Sequence[str],
    correlation_keys: Sequence[str],
    sample_count: int,
) -> tuple[list[dict[str, Any]], dict[str, dict[str, list[float]]], int]:
    """Measure paired new-connection first queries (OS cache uncontrolled)."""

    measurements: list[dict[str, Any]] = []
    timings = {
        variant.name: {"service": [], "correlation": []}
        for variant in VARIANTS
    }
    verified_rows = 0
    query_specs = (
        ("service", ORIGINAL.EACP_SERVICE_QUERY, service_keys[:sample_count]),
        (
            "correlation",
            ORIGINAL.EACP_CORRELATION_QUERY,
            correlation_keys[:sample_count],
        ),
    )

    for query_number, (query_type, sql, keys) in enumerate(query_specs):
        for position, key in enumerate(keys):
            rows_by_variant: dict[str, list[tuple[Any, ...]]] = {}
            elapsed_by_variant: dict[str, float] = {}
            for variant in balanced_order(trial + query_number + position):
                elapsed_ms, rows = fresh_connection_fetch(
                    paths[variant.name], sql, key
                )
                elapsed_by_variant[variant.name] = elapsed_ms
                rows_by_variant[variant.name] = rows
                timings[variant.name][query_type].append(elapsed_ms)

            reference_rows = rows_by_variant["full_indexes"]
            for variant in VARIANTS:
                if rows_by_variant[variant.name] != reference_rows:
                    raise AssertionError(
                        f"cold-open output differs for {query_type} key {key} "
                        f"in {variant.name}"
                    )
            verified_rows += len(reference_rows)
            measurements.append(
                {
                    "event_count": event_count,
                    "trial": trial,
                    "seed": seed,
                    "query_type": query_type,
                    "sample_position": position,
                    "query_key": key,
                    "row_count": len(reference_rows),
                    "row_sha256": row_digest(reference_rows),
                    **{
                        f"{variant.name}_connect_plus_first_query_ms": (
                            elapsed_by_variant[variant.name]
                        )
                        for variant in VARIANTS
                    },
                }
            )
    return measurements, timings, verified_rows


def query_plan_record(
    connection: sqlite3.Connection,
    variant: Variant,
    event_count: int,
    trial: int,
    seed: int,
    service_key: str,
    correlation_key: str,
) -> dict[str, Any]:
    service_plan = ORIGINAL.explain(
        connection, ORIGINAL.EACP_SERVICE_QUERY, (service_key,)
    )
    correlation_plan = ORIGINAL.explain(
        connection, ORIGINAL.EACP_CORRELATION_QUERY, (correlation_key,)
    )
    return {
        "event_count": event_count,
        "trial": trial,
        "seed": seed,
        "variant": variant.name,
        "user_indexes": user_index_names(connection),
        "service_key": service_key,
        "service_plan": service_plan,
        "service_uses_target_index": int(
            any("ev_service_time" in item for item in service_plan)
        ),
        "correlation_key": correlation_key,
        "correlation_plan": correlation_plan,
        "correlation_uses_target_index": int(
            any("ev_correlation" in item for item in correlation_plan)
        ),
    }


def run_trial(
    event_count: int,
    size_position: int,
    trial: int,
    service_count: int,
    query_samples: int,
    cold_open_samples: int,
    workdir: Path,
    keep_databases: bool,
) -> tuple[
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
]:
    """Run one paired trial and return trial, warm, cold-open, and plan rows."""

    seed = 9137 + trial * 101
    events = list(ORIGINAL.generate_events(event_count, service_count, seed))
    service_keys, correlation_keys = exact_query_keys(
        event_count, service_count, query_samples, seed
    )

    connections: dict[str, sqlite3.Connection] = {}
    paths: dict[str, Path] = {}
    build_metadata: dict[str, dict[str, Any]] = {}
    build_order = balanced_order((trial - 1) + size_position)
    for position, variant in enumerate(build_order):
        path = workdir / f"{variant.name}_{event_count}_{trial}.sqlite"
        paths[variant.name] = path
        connection, metadata = create_database(path, events, variant)
        connections[variant.name] = connection
        metadata["build_order"] = position + 1
        build_metadata[variant.name] = metadata

    projection_pairs = {
        (
            int(metadata["projection_rows"]),
            str(metadata["projection_sha256"]),
        )
        for metadata in build_metadata.values()
    }
    if len(projection_pairs) != 1:
        raise AssertionError("full canonical projections differ across index variants")
    projection_rows, _projection_sha256 = next(iter(projection_pairs))
    if projection_rows != event_count:
        raise AssertionError("full canonical projection row count is incomplete")

    plan_rows = [
        query_plan_record(
            connections[variant.name],
            variant,
            event_count,
            trial,
            seed,
            service_keys[0],
            correlation_keys[0],
        )
        for variant in VARIANTS
    ]

    warm_connections(connections, service_keys, correlation_keys, trial)
    warm_rows, warm_timings, verified_warm_rows = measure_warm_queries(
        connections,
        event_count,
        trial,
        seed,
        service_keys,
        correlation_keys,
    )

    for connection in connections.values():
        connection.close()

    cold_rows, cold_timings, verified_cold_rows = measure_cold_open_queries(
        paths,
        event_count,
        trial,
        seed,
        service_keys,
        correlation_keys,
        cold_open_samples,
    )

    full_metadata = build_metadata["full_indexes"]
    full_warm_service_p95 = ORIGINAL.percentile(
        warm_timings["full_indexes"]["service"], 0.95
    )
    full_warm_correlation_p95 = ORIGINAL.percentile(
        warm_timings["full_indexes"]["correlation"], 0.95
    )
    full_cold_service_p95 = ORIGINAL.percentile(
        cold_timings["full_indexes"]["service"], 0.95
    )
    full_cold_correlation_p95 = ORIGINAL.percentile(
        cold_timings["full_indexes"]["correlation"], 0.95
    )

    trial_rows: list[dict[str, Any]] = []
    for variant in VARIANTS:
        metadata = build_metadata[variant.name]
        warm_service_p50 = ORIGINAL.percentile(
            warm_timings[variant.name]["service"], 0.50
        )
        warm_service_p95 = ORIGINAL.percentile(
            warm_timings[variant.name]["service"], 0.95
        )
        warm_correlation_p50 = ORIGINAL.percentile(
            warm_timings[variant.name]["correlation"], 0.50
        )
        warm_correlation_p95 = ORIGINAL.percentile(
            warm_timings[variant.name]["correlation"], 0.95
        )
        cold_service_p95 = ORIGINAL.percentile(
            cold_timings[variant.name]["service"], 0.95
        )
        cold_correlation_p95 = ORIGINAL.percentile(
            cold_timings[variant.name]["correlation"], 0.95
        )
        trial_rows.append(
            {
                "event_count": event_count,
                "trial": trial,
                "seed": seed,
                "variant": variant.name,
                "build_order": metadata["build_order"],
                "service_index": int(variant.service_index),
                "correlation_index": int(variant.correlation_index),
                "service_count": service_count,
                "query_samples": query_samples,
                "cold_open_samples": cold_open_samples,
                "ingest_seconds": metadata["ingest_seconds"],
                "ingest_us_per_event": metadata["ingest_us_per_event"],
                "ingest_events_per_second": metadata["ingest_events_per_second"],
                "ingest_time_ratio_to_full": (
                    metadata["ingest_seconds"] / full_metadata["ingest_seconds"]
                ),
                "ingest_time_reduction_vs_full_percent": (
                    (1.0 - metadata["ingest_seconds"] / full_metadata["ingest_seconds"])
                    * 100.0
                ),
                "database_bytes": metadata["database_bytes"],
                "database_bytes_per_event": metadata["database_bytes_per_event"],
                "database_size_ratio_to_full": (
                    metadata["database_bytes"] / full_metadata["database_bytes"]
                ),
                "database_bytes_reduction_vs_full_percent": (
                    (1.0 - metadata["database_bytes"] / full_metadata["database_bytes"])
                    * 100.0
                ),
                "dbstat_available": metadata["dbstat_available"],
                "dbstat_table_bytes": metadata["dbstat_table_bytes"],
                "dbstat_unique_autoindex_bytes": metadata[
                    "dbstat_unique_autoindex_bytes"
                ],
                "dbstat_retained_source_index_bytes": metadata[
                    "dbstat_retained_source_index_bytes"
                ],
                "dbstat_lookup_index_bytes": metadata["dbstat_lookup_index_bytes"],
                "warm_service_p50_ms": warm_service_p50,
                "warm_service_p95_ms": warm_service_p95,
                "warm_service_p95_ratio_to_full": (
                    warm_service_p95 / full_warm_service_p95
                ),
                "warm_correlation_p50_ms": warm_correlation_p50,
                "warm_correlation_p95_ms": warm_correlation_p95,
                "warm_correlation_p95_ratio_to_full": (
                    warm_correlation_p95 / full_warm_correlation_p95
                ),
                "cold_open_service_p95_ms": cold_service_p95,
                "cold_open_service_p95_ratio_to_full": (
                    cold_service_p95 / full_cold_service_p95
                ),
                "cold_open_correlation_p95_ms": cold_correlation_p95,
                "cold_open_correlation_p95_ratio_to_full": (
                    cold_correlation_p95 / full_cold_correlation_p95
                ),
                "verified_warm_queries": query_samples * 2,
                "verified_warm_rows": verified_warm_rows,
                "verified_cold_open_queries": cold_open_samples * 2,
                "verified_cold_open_rows": verified_cold_rows,
                "full_projection_rows": metadata["projection_rows"],
                "full_projection_sha256": metadata["projection_sha256"],
                "all_outputs_equivalent": 1,
                "integrity_check": metadata["integrity_check"],
                "user_indexes": ";".join(metadata["user_indexes"]),
            }
        )

    if not keep_databases:
        for path in paths.values():
            path.unlink(missing_ok=True)
    return trial_rows, warm_rows, cold_rows, plan_rows


SUMMARY_METRICS = (
    "ingest_us_per_event",
    "ingest_events_per_second",
    "ingest_time_ratio_to_full",
    "ingest_time_reduction_vs_full_percent",
    "database_bytes",
    "database_bytes_per_event",
    "database_size_ratio_to_full",
    "database_bytes_reduction_vs_full_percent",
    "dbstat_table_bytes",
    "dbstat_unique_autoindex_bytes",
    "dbstat_retained_source_index_bytes",
    "dbstat_lookup_index_bytes",
    "warm_service_p50_ms",
    "warm_service_p95_ms",
    "warm_service_p95_ratio_to_full",
    "warm_correlation_p50_ms",
    "warm_correlation_p95_ms",
    "warm_correlation_p95_ratio_to_full",
    "cold_open_service_p95_ms",
    "cold_open_service_p95_ratio_to_full",
    "cold_open_correlation_p95_ms",
    "cold_open_correlation_p95_ratio_to_full",
)


def summarize(trial_rows: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    """Summarize trial-level values descriptively; trial is the unit."""

    grouped: dict[tuple[int, str], list[dict[str, Any]]] = defaultdict(list)
    for row in trial_rows:
        grouped[(int(row["event_count"]), str(row["variant"]))].append(row)

    summary_rows: list[dict[str, Any]] = []
    for event_count in sorted({key[0] for key in grouped}):
        for variant in VARIANTS:
            rows = grouped[(event_count, variant.name)]
            item: dict[str, Any] = {
                "event_count": event_count,
                "variant": variant.name,
                "trials": len(rows),
                "service_index": int(variant.service_index),
                "correlation_index": int(variant.correlation_index),
                "all_outputs_equivalent": int(
                    all(int(row["all_outputs_equivalent"]) == 1 for row in rows)
                ),
            }
            for metric in SUMMARY_METRICS:
                values = [
                    float(row[metric])
                    for row in rows
                    if row[metric] is not None
                ]
                if not values:
                    for suffix in ("median", "q1", "q3", "min", "max"):
                        item[f"{metric}_{suffix}"] = None
                    continue
                item[f"{metric}_median"] = statistics.median(values)
                item[f"{metric}_q1"] = ORIGINAL.percentile(values, 0.25)
                item[f"{metric}_q3"] = ORIGINAL.percentile(values, 0.75)
                item[f"{metric}_min"] = min(values)
                item[f"{metric}_max"] = max(values)
            summary_rows.append(item)
    return summary_rows


def write_csv(path: Path, rows: Sequence[dict[str, Any]]) -> None:
    if not rows:
        raise ValueError(f"refusing to write empty result file: {path.name}")
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def utc_string(value: datetime) -> str:
    return (
        value.astimezone(timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def sysctl_value(name: str) -> str | None:
    try:
        return subprocess.check_output(
            ["sysctl", "-n", name], text=True, stderr=subprocess.DEVNULL
        ).strip()
    except (FileNotFoundError, subprocess.CalledProcessError):
        return None


def environment_record(command: Sequence[str]) -> dict[str, Any]:
    sqlite_connection = sqlite3.connect(":memory:")
    try:
        compile_options = sorted(
            str(row[0])
            for row in sqlite_connection.execute("PRAGMA compile_options")
        )
    finally:
        sqlite_connection.close()
    return {
        "generated_at_utc": utc_string(datetime.now(timezone.utc)),
        "portable_reproduction_command": list(command),
        "python": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "sqlite": sqlite3.sqlite_version,
        "sqlite_compile_options": compile_options,
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "cpu_count": os.cpu_count(),
        "cpu_brand": sysctl_value("machdep.cpu.brand_string"),
        "memory_bytes": sysctl_value("hw.memsize"),
        "max_rss_platform_units": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        "timer": "time.perf_counter_ns",
        "experiment_source_sha256": sha256_file(EXPERIMENT_SOURCE_PATH),
        "benchmark_source_sha256": sha256_file(BENCHMARK_PATH),
        "cold_open_definition": (
            "sqlite3.connect plus first execute/fetch/close; each sample uses a new "
            "SQLite connection and therefore a new SQLite page cache"
        ),
        "operating_system_page_cache_controlled": False,
    }


def method_record(
    sizes: Sequence[int],
    trials: int,
    service_count: int,
    query_samples: int,
    cold_open_samples: int,
) -> dict[str, Any]:
    seeds = [9137 + trial * 101 for trial in range(1, trials + 1)]
    return {
        "result_schema_version": RESULT_SCHEMA_VERSION,
        "research_question": (
            "How much of EACP SQLite lookup performance, ingestion cost, and "
            "database size is attributable to the service and correlation indexes?"
        ),
        "benchmark_source": "benchmark/sqlite/eacp_benchmark.py",
        "benchmark_source_sha256": sha256_file(BENCHMARK_PATH),
        "experiment_source": "experiments/index_ablation/index_ablation.py",
        "experiment_source_sha256": sha256_file(EXPERIMENT_SOURCE_PATH),
        "reuse": [
            "SOURCE_TYPES",
            "EACP_SCHEMA",
            "EACP_SERVICE_QUERY",
            "EACP_CORRELATION_QUERY",
            "EACP_FULL_QUERY",
            "generate_events",
            "configure",
            "insert_eacp",
            "timed_fetch",
            "projection_digest",
            "explain",
            "db_size",
            "percentile",
        ],
        "treatment": (
            "Remove only the exact CREATE INDEX statements for ev_service_time "
            "and/or ev_correlation. The table, UNIQUE constraint, append-only "
            "triggers, and ev_source_time index remain unchanged."
        ),
        "variants": [
            {
                "name": variant.name,
                "service_index": variant.service_index,
                "correlation_index": variant.correlation_index,
            }
            for variant in VARIANTS
        ],
        "event_counts": list(sizes),
        "trials_per_event_count": trials,
        "seeds": seeds,
        "service_count": service_count,
        "warm_query_samples_per_type_per_trial": query_samples,
        "cold_open_samples_per_type_per_trial": cold_open_samples,
        "pairing": (
            "Within each event-count/seed trial, all variants receive the same "
            "generated events and the same ordered service and correlation keys."
        ),
        "order_control": (
            "Database build order and per-query variant execution order are "
            "deterministically rotated across trials and sample positions."
        ),
        "warm_cache_protocol": (
            "Every timed key is fetched once on every variant immediately before "
            "the timed warm-cache pass."
        ),
        "cold_open_protocol": (
            "Each sample times sqlite3.connect plus the first query and close on a "
            "new connection. This resets SQLite's connection-local page cache but "
            "does not flush or claim control of the operating-system page cache."
        ),
        "database_size_protocol": "ANALYZE, VACUUM, then file size in bytes.",
        "equivalence_protocol": (
            "Abort unless every variant has the same complete canonical projection "
            "row count and SHA-256, and every timed warm and cold-open query is "
            "row-for-row identical to full_indexes."
        ),
        "analysis_unit": "one event-count/seed trial",
        "statistics": (
            "Within-trial p50/p95 use linear interpolation across query samples. "
            "Across-trial summaries report median, Q1, Q3, minimum, and maximum. "
            "No population, independence, normality, or statistical-significance "
            "claim is made."
        ),
    }


RESULT_FILENAMES = (
    "cold_open_measurements.csv",
    "environment.json",
    "method.json",
    "query_measurements.csv",
    "query_plans.json",
    "summary_results.csv",
    "summary_results.json",
    "trial_results.csv",
    "trial_results.json",
)


def write_checksums(output: Path) -> None:
    lines = [
        f"{sha256_file(output / name)}  {name}"
        for name in RESULT_FILENAMES
    ]
    (output / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")


def verify_checksums(output: Path) -> list[str]:
    checksum_path = output / "SHA256SUMS"
    errors: list[str] = []
    if not checksum_path.is_file():
        return ["missing SHA256SUMS"]
    listed: set[str] = set()
    for line_number, line in enumerate(
        checksum_path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        parts = line.split(maxsplit=1)
        if len(parts) != 2:
            errors.append(f"malformed SHA256SUMS line {line_number}")
            continue
        expected, name = parts
        name = name.strip()
        listed.add(name)
        target = output / name
        if not target.is_file():
            errors.append(f"missing checksummed file: {name}")
        elif sha256_file(target) != expected:
            errors.append(f"checksum mismatch: {name}")
    expected_names = set(RESULT_FILENAMES)
    if listed != expected_names:
        errors.append(
            "checksum inventory differs: "
            f"missing={sorted(expected_names - listed)}, "
            f"extra={sorted(listed - expected_names)}"
        )
    method_path = output / "method.json"
    if method_path.is_file():
        try:
            method = json.loads(method_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            errors.append(f"cannot parse method.json: {error}")
        else:
            source_checks = (
                (
                    "experiment_source_sha256",
                    EXPERIMENT_SOURCE_PATH,
                ),
                ("benchmark_source_sha256", BENCHMARK_PATH),
            )
            for field, source_path in source_checks:
                if method.get(field) != sha256_file(source_path):
                    errors.append(f"source checksum mismatch: {field}")
    return errors


def portable_command(args: argparse.Namespace) -> list[str]:
    return [
        "python3",
        "experiments/index_ablation/index_ablation.py",
        "--sizes",
        *(str(value) for value in args.sizes),
        "--trials",
        str(args.trials),
        "--services",
        str(args.services),
        "--query-samples",
        str(args.query_samples),
        "--cold-open-samples",
        str(args.cold_open_samples),
        "--output",
        "experiments/index_ablation/results/reference",
    ]


def run_campaign(args: argparse.Namespace) -> None:
    output = args.output
    output.mkdir(parents=True, exist_ok=True)
    workdir = output / "work"
    workdir.mkdir(parents=True, exist_ok=True)

    trial_rows: list[dict[str, Any]] = []
    warm_rows: list[dict[str, Any]] = []
    cold_rows: list[dict[str, Any]] = []
    plan_rows: list[dict[str, Any]] = []
    for size_position, event_count in enumerate(args.sizes):
        for trial in range(1, args.trials + 1):
            current_trial, current_warm, current_cold, current_plans = run_trial(
                event_count=event_count,
                size_position=size_position,
                trial=trial,
                service_count=args.services,
                query_samples=args.query_samples,
                cold_open_samples=args.cold_open_samples,
                workdir=workdir,
                keep_databases=args.keep_databases,
            )
            trial_rows.extend(current_trial)
            warm_rows.extend(current_warm)
            cold_rows.extend(current_cold)
            if trial == 1:
                plan_rows.extend(current_plans)
            full = next(
                row for row in current_trial if row["variant"] == "full_indexes"
            )
            none = next(
                row
                for row in current_trial
                if row["variant"] == "no_lookup_indexes"
            )
            print(
                f"size={event_count} trial={trial}/{args.trials} "
                f"full_service_p95={full['warm_service_p95_ms']:.3f}ms "
                f"no_indexes_service_p95={none['warm_service_p95_ms']:.3f}ms "
                f"full_corr_p95={full['warm_correlation_p95_ms']:.3f}ms "
                f"no_indexes_corr_p95={none['warm_correlation_p95_ms']:.3f}ms",
                flush=True,
            )

    summary_rows = summarize(trial_rows)
    write_csv(output / "trial_results.csv", trial_rows)
    write_csv(output / "query_measurements.csv", warm_rows)
    write_csv(output / "cold_open_measurements.csv", cold_rows)
    write_csv(output / "summary_results.csv", summary_rows)
    (output / "trial_results.json").write_text(
        json.dumps(trial_rows, indent=2) + "\n", encoding="utf-8"
    )
    (output / "summary_results.json").write_text(
        json.dumps(
            {
                "result_schema_version": RESULT_SCHEMA_VERSION,
                "analysis_unit": "one event-count/seed trial",
                "inferential_statistics": False,
                "rows": summary_rows,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    (output / "query_plans.json").write_text(
        json.dumps(
            {
                "result_schema_version": RESULT_SCHEMA_VERSION,
                "capture_rule": "first trial at each event count",
                "plans": plan_rows,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    (output / "method.json").write_text(
        json.dumps(
            method_record(
                args.sizes,
                args.trials,
                args.services,
                args.query_samples,
                args.cold_open_samples,
            ),
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    (output / "environment.json").write_text(
        json.dumps(environment_record(portable_command(args)), indent=2) + "\n",
        encoding="utf-8",
    )
    write_checksums(output)
    if not args.keep_databases:
        try:
            workdir.rmdir()
        except OSError:
            pass
    print(f"results={output}")


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--sizes", nargs="+", type=int, default=[10_000, 50_000, 100_000]
    )
    parser.add_argument("--trials", type=int, default=10)
    parser.add_argument("--services", type=int, default=200)
    parser.add_argument("--query-samples", type=int, default=300)
    parser.add_argument("--cold-open-samples", type=int, default=20)
    parser.add_argument(
        "--output", type=Path, default=EXPERIMENT_DIR / "results" / "latest"
    )
    parser.add_argument("--keep-databases", action="store_true")
    parser.add_argument(
        "--verify",
        type=Path,
        help="verify an existing result directory instead of running",
    )
    args = parser.parse_args(argv)
    if any(size <= 0 for size in args.sizes):
        parser.error("--sizes values must be positive")
    if args.trials <= 0 or args.services <= 0 or args.query_samples <= 0:
        parser.error("--trials, --services, and --query-samples must be positive")
    if not 1 <= args.cold_open_samples <= args.query_samples:
        parser.error("--cold-open-samples must be between 1 and --query-samples")
    if len(set(args.sizes)) != len(args.sizes):
        parser.error("--sizes values must be unique")
    return args


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(list(sys.argv[1:] if argv is None else argv))
    if args.verify is not None:
        errors = verify_checksums(args.verify)
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        if errors:
            return 1
        print(f"Checksums verified: {args.verify}")
        return 0
    run_campaign(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
