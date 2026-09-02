#!/usr/bin/env python3
"""Deterministic adversarial correlation-robustness experiment for EACP.

This experiment is deliberately separate from the v1.2 SQLite benchmark.  It
uses synthetic ground truth to measure reconstruction quality after correlation
metadata or delivery order is perturbed.  It does not infer missing identifiers
and it does not modify the published v1.2 schema.

Only the Python standard library is required.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import platform
import statistics
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from itertools import combinations
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


SOURCE_TYPES = (
    "deployment",
    "identity",
    "policy",
    "telemetry",
    "incident",
    "recovery",
)

# This follows the seed schedule used by the v1.2 benchmark, extended to 30
# independent trials per condition.
DEFAULT_SEEDS = tuple(9137 + trial * 101 for trial in range(1, 31))
DEFAULT_SOURCE_OFFSETS_MS = (0, 250, 500, 750, 1000, 1250)
DEFAULT_NATURAL_OBSERVATION_DELAY_MS = 25
RESULT_SCHEMA_VERSION = "1.0"


@dataclass(frozen=True)
class Event:
    """One observed record plus evaluation-only ground truth.

    Reconstructors may inspect the operational fields but must never inspect
    ``truth_chain_id``, ``truth_source_ms``, ``canonical_event_id``, or
    ``observation_kind``.  Tests enforce this separation behaviorally.
    """

    event_id: str
    source_id: str
    payload_hash: str
    truth_chain_id: str
    truth_source_ms: int
    canonical_event_id: str
    observation_kind: str
    service: str
    source_type: str
    source_ms: int
    arrival_ms: int
    correlation_id: str | None


@dataclass(frozen=True)
class Reconstruction:
    """Groups emitted by one reconstruction policy and observable warnings."""

    groups: Mapping[str, tuple[Event, ...]]
    ambiguity_flags: frozenset[str]
    ambiguity_candidates: Mapping[str, tuple[Event, ...]]
    abstained_event_ids: frozenset[str]
    deduplicated_event_ids: frozenset[str]
    source_conflict_flags: frozenset[str]


def stable_integer(seed: int, *parts: object) -> int:
    """Return a cross-process deterministic integer for selection and jitter."""

    material = "\x1f".join((str(seed), *(str(part) for part in parts)))
    return int.from_bytes(hashlib.sha256(material.encode("utf-8")).digest(), "big")


def stable_fraction(seed: int, *parts: object) -> float:
    return stable_integer(seed, *parts) / float(1 << 256)


def percentile(values: Sequence[float], probability: float) -> float | None:
    """Linear-interpolated percentile, or ``None`` for an empty sample."""

    if not values:
        return None
    ordered = sorted(values)
    if len(ordered) == 1:
        return float(ordered[0])
    rank = (len(ordered) - 1) * probability
    lower = int(rank)
    upper = min(lower + 1, len(ordered) - 1)
    fraction = rank - lower
    return float(ordered[lower] * (1.0 - fraction) + ordered[upper] * fraction)


def choose_exact(
    items: Iterable[Any],
    count: int,
    seed: int,
    label: str,
    key,
) -> list[Any]:
    """Select exactly ``count`` items using a stable hash ranking."""

    ranked = sorted(
        items,
        key=lambda item: (stable_integer(seed, label, key(item)), str(key(item))),
    )
    return ranked[: max(0, min(count, len(ranked)))]


def generate_events(
    chain_count: int,
    service_count: int,
    seed: int,
    overlap_fraction: float,
) -> list[Event]:
    """Generate six-plane chains with controlled same-service overlap.

    Each service receives at most one chain per round.  Consecutive rounds form
    pairs.  A deterministic fraction of the second chains starts 800 ms after
    the first, while a complete six-plane chain spans 1,250 ms.  The remaining
    second chains start 10 seconds later.  This mixture makes a temporal-only
    comparator informative: many episodes are separable, but overlap creates a
    genuine precision/recall trade-off.
    """

    events: list[Event] = []
    for chain_index in range(chain_count):
        service_index = chain_index % service_count
        round_index = chain_index // service_count
        pair_cycle = round_index // 2
        service_phase_ms = service_index * 3
        if round_index % 2 == 0:
            pair_offset_ms = 0
        else:
            overlaps = stable_fraction(
                seed, "schedule-overlap", service_index, pair_cycle
            ) < overlap_fraction
            pair_offset_ms = 800 if overlaps else 10_000
        chain_start_ms = pair_cycle * 20_000 + pair_offset_ms + service_phase_ms
        service = f"svc-{service_index:04d}"
        truth_chain_id = f"truth-{seed:06d}-{chain_index:06d}"
        correlation_id = f"corr-{seed:06d}-{chain_index:06d}"

        for source_index, source_type in enumerate(SOURCE_TYPES):
            source_ms = chain_start_ms + DEFAULT_SOURCE_OFFSETS_MS[source_index]
            event_id = f"event-{seed:06d}-{chain_index:06d}-{source_index}"
            source_id = f"{source_type}-{seed:06d}-{chain_index:06d}"
            payload_material = (
                f"{source_id}|{service}|{source_ms}|{correlation_id}|synthetic"
            )
            payload_hash = hashlib.sha256(payload_material.encode("utf-8")).hexdigest()
            events.append(
                Event(
                    event_id=event_id,
                    source_id=source_id,
                    payload_hash=payload_hash,
                    truth_chain_id=truth_chain_id,
                    truth_source_ms=source_ms,
                    canonical_event_id=event_id,
                    observation_kind="canonical",
                    service=service,
                    source_type=source_type,
                    source_ms=source_ms,
                    arrival_ms=source_ms + DEFAULT_NATURAL_OBSERVATION_DELAY_MS,
                    correlation_id=correlation_id,
                )
            )
    return sorted(events, key=lambda event: (event.source_ms, event.event_id))


def scenario_specs(
    missing_rates: Sequence[float],
    collision_rates: Sequence[float],
) -> list[dict[str, Any]]:
    """Return the complete, ordered fault-injection matrix."""

    specs: list[dict[str, Any]] = [
        {
            "name": "control",
            "kind": "control",
            "description": "Complete identifiers and natural 25 ms observation delay.",
        }
    ]
    for rate in missing_rates:
        percent = int(round(rate * 100))
        specs.append(
            {
                "name": f"missing_random_{percent}pct",
                "kind": "missing_random",
                "rate": rate,
                "description": f"Remove the correlation ID from exactly {percent}% of events.",
            }
        )
    for rate in missing_rates:
        percent = int(round(rate * 100))
        specs.append(
            {
                "name": f"wrong_id_same_service_{percent}pct",
                "kind": "wrong_id",
                "rate": rate,
                "description": (
                    f"Replace the correlation ID on exactly {percent}% of events with "
                    "an ID from a different truth chain of the same service."
                ),
            }
        )
    for source_type in SOURCE_TYPES:
        specs.append(
            {
                "name": f"missing_plane_{source_type}",
                "kind": "missing_plane",
                "source_type": source_type,
                "description": f"Remove every correlation ID emitted by the {source_type} plane.",
            }
        )
    for rate in collision_rates:
        percent = int(round(rate * 100))
        specs.append(
            {
                "name": f"collision_same_service_{percent}pct",
                "kind": "collision_same_service",
                "rate": rate,
                "description": (
                    f"Reuse identifiers for {percent}% as many disjoint same-service "
                    "victim/donor pairs as there are truth chains."
                ),
            }
        )
    specs.append(
        {
            "name": "collision_cross_service_5pct",
            "kind": "collision_cross_service",
            "rate": 0.05,
            "description": (
                "Reuse identifiers for 5% as many disjoint cross-service victim/donor "
                "pairs as there are truth chains."
            ),
        }
    )
    specs.extend(
        [
            {
                "name": "duplicate_exact_10pct",
                "kind": "duplicate_exact",
                "rate": 0.10,
                "description": (
                    "Replay an exact second observation for exactly 10% of canonical events."
                ),
            },
            {
                "name": "duplicate_source_conflict_5pct",
                "kind": "duplicate_source_conflict",
                "rate": 0.05,
                "description": (
                    "Add a second observation with the same source type and source ID but "
                    "a conflicting payload hash for exactly 5% of canonical events."
                ),
            },
            {
                "name": "clock_skew_random_10pct_5s",
                "kind": "clock_skew",
                "rate": 0.10,
                "skew_ms": 5_000,
                "description": (
                    "Shift the logged source timestamp of exactly 10% of events by "
                    "deterministic +5 or -5 second skew without changing arrival time."
                ),
            },
            {
                "name": "late_arrival_10pct_30s",
                "kind": "late_arrival",
                "rate": 0.10,
                "delay_ms": 30_000,
                "description": "Delay exactly 10% of events by 30 seconds.",
            },
            {
                "name": "out_of_order_jitter_3s",
                "kind": "out_of_order_jitter",
                "jitter_ms": 3_000,
                "description": "Add deterministic independent 0--3 second transport jitter.",
            },
            {
                "name": "compound_adversarial",
                "kind": "compound",
                "missing_rate": 0.10,
                "collision_rate": 0.05,
                "late_rate": 0.10,
                "delay_ms": 30_000,
                "jitter_ms": 3_000,
                "description": (
                    "Combine 10% missing IDs, 5% same-service ID reuse, 10% 30-second "
                    "late arrivals, and 0--3 second jitter."
                ),
            },
        ]
    )
    return specs


def _replace_selected_missing(
    events: Sequence[Event], rate: float, seed: int, label: str
) -> tuple[list[Event], int]:
    count = int(round(len(events) * rate))
    selected = {
        event.event_id
        for event in choose_exact(events, count, seed, label, lambda event: event.event_id)
    }
    return [
        replace(event, correlation_id=None) if event.event_id in selected else event
        for event in events
    ], len(selected)


def _replace_wrong_ids(
    events: Sequence[Event], rate: float, seed: int, label: str
) -> tuple[list[Event], int]:
    """Substitute IDs from other chains of the same service."""

    count = int(round(len(events) * rate))
    selected = {
        event.event_id
        for event in choose_exact(events, count, seed, label, lambda event: event.event_id)
    }
    chain_metadata = _chain_metadata(events)
    correlations_by_service: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for chain_id, (service, correlation_id) in chain_metadata.items():
        correlations_by_service[service].append((chain_id, correlation_id))
    for service in correlations_by_service:
        correlations_by_service[service].sort()

    replaced: list[Event] = []
    for event in events:
        if event.event_id not in selected:
            replaced.append(event)
            continue
        donors = [
            correlation_id
            for chain_id, correlation_id in correlations_by_service[event.service]
            if chain_id != event.truth_chain_id
        ]
        if not donors:
            raise ValueError("wrong-ID injection requires at least two chains per service")
        donor_index = stable_integer(seed, label, "donor", event.event_id) % len(donors)
        replaced.append(replace(event, correlation_id=donors[donor_index]))
    return replaced, len(selected)


def _add_exact_duplicates(
    events: Sequence[Event], rate: float, seed: int, label: str
) -> tuple[list[Event], int]:
    count = int(round(len(events) * rate))
    selected = choose_exact(events, count, seed, label, lambda event: event.event_id)
    duplicates = [
        replace(
            event,
            event_id=f"{event.event_id}-duplicate-exact",
            observation_kind="exact_duplicate",
        )
        for event in selected
    ]
    return [*events, *duplicates], len(duplicates)


def _add_conflicting_duplicates(
    events: Sequence[Event], rate: float, seed: int, label: str
) -> tuple[list[Event], int]:
    count = int(round(len(events) * rate))
    selected = choose_exact(events, count, seed, label, lambda event: event.event_id)
    conflicts = [
        replace(
            event,
            event_id=f"{event.event_id}-duplicate-conflict",
            payload_hash=hashlib.sha256(
                f"{event.payload_hash}|injected-conflict".encode("utf-8")
            ).hexdigest(),
            observation_kind="conflicting_duplicate",
        )
        for event in selected
    ]
    return [*events, *conflicts], len(conflicts)


def _replace_clock_skew(
    events: Sequence[Event],
    rate: float,
    skew_ms: int,
    seed: int,
    label: str,
) -> tuple[list[Event], int]:
    count = int(round(len(events) * rate))
    selected = {
        event.event_id
        for event in choose_exact(events, count, seed, label, lambda event: event.event_id)
    }
    replaced: list[Event] = []
    for event in events:
        if event.event_id not in selected:
            replaced.append(event)
            continue
        direction = 1 if stable_integer(seed, label, "direction", event.event_id) % 2 else -1
        replaced.append(replace(event, source_ms=event.source_ms + direction * skew_ms))
    return replaced, len(selected)


def _chain_metadata(events: Sequence[Event]) -> dict[str, tuple[str, str]]:
    metadata: dict[str, tuple[str, str]] = {}
    for event in events:
        if event.truth_chain_id not in metadata:
            if event.correlation_id is None:
                raise ValueError("collision injection must precede missing-ID injection")
            metadata[event.truth_chain_id] = (event.service, event.correlation_id)
    return metadata


def _collision_pairs(
    events: Sequence[Event],
    rate: float,
    seed: int,
    label: str,
    same_service: bool,
) -> list[tuple[str, str]]:
    metadata = _chain_metadata(events)
    target = int(round(len(metadata) * rate))
    candidates: list[tuple[str, str]] = []

    if same_service:
        by_service: dict[str, list[str]] = defaultdict(list)
        for chain_id, (service, _correlation_id) in metadata.items():
            by_service[service].append(chain_id)
        for service, chain_ids in sorted(by_service.items()):
            ordered = sorted(
                chain_ids,
                key=lambda chain_id: (
                    stable_integer(seed, label, service, chain_id),
                    chain_id,
                ),
            )
            candidates.extend(zip(ordered[0::2], ordered[1::2]))
    else:
        ordered = sorted(
            metadata,
            key=lambda chain_id: (stable_integer(seed, label, chain_id), chain_id),
        )
        unused = list(ordered)
        while unused:
            donor = unused.pop(0)
            donor_service = metadata[donor][0]
            victim_index = next(
                (
                    index
                    for index, candidate in enumerate(unused)
                    if metadata[candidate][0] != donor_service
                ),
                None,
            )
            if victim_index is None:
                break
            victim = unused.pop(victim_index)
            candidates.append((donor, victim))

    selected = choose_exact(
        candidates,
        target,
        seed,
        f"{label}-pairs",
        lambda pair: f"{pair[0]}::{pair[1]}",
    )
    if len(selected) != target:
        raise ValueError(
            f"scenario requested {target} collision pairs but only {len(selected)} were available"
        )
    return selected


def _replace_collisions(
    events: Sequence[Event],
    rate: float,
    seed: int,
    label: str,
    same_service: bool,
) -> tuple[list[Event], int]:
    metadata = _chain_metadata(events)
    pairs = _collision_pairs(events, rate, seed, label, same_service)
    replacement = {victim: metadata[donor][1] for donor, victim in pairs}
    return [
        replace(event, correlation_id=replacement[event.truth_chain_id])
        if event.truth_chain_id in replacement
        else event
        for event in events
    ], len(pairs)


def _replace_late_arrivals(
    events: Sequence[Event],
    rate: float,
    delay_ms: int,
    seed: int,
    label: str,
) -> tuple[list[Event], int]:
    count = int(round(len(events) * rate))
    selected = {
        event.event_id
        for event in choose_exact(events, count, seed, label, lambda event: event.event_id)
    }
    return [
        replace(event, arrival_ms=event.arrival_ms + delay_ms)
        if event.event_id in selected
        else event
        for event in events
    ], len(selected)


def _replace_jitter(
    events: Sequence[Event], jitter_ms: int, seed: int, label: str
) -> list[Event]:
    return [
        replace(
            event,
            arrival_ms=event.arrival_ms
            + stable_integer(seed, label, event.event_id) % (jitter_ms + 1),
        )
        for event in events
    ]


def apply_scenario(
    pristine_events: Sequence[Event],
    spec: Mapping[str, Any],
    seed: int,
) -> tuple[list[Event], dict[str, int]]:
    """Apply one deterministic perturbation and return mutation counts."""

    events = list(pristine_events)
    metadata = {
        "missing_id_events": 0,
        "wrong_id_events": 0,
        "collision_pairs": 0,
        "exact_duplicate_observations": 0,
        "conflicting_duplicate_observations": 0,
        "clock_skewed_events": 0,
        "late_events": 0,
        "jittered_events": 0,
    }
    kind = spec["kind"]
    label = str(spec["name"])

    if kind == "control":
        pass
    elif kind == "missing_random":
        events, metadata["missing_id_events"] = _replace_selected_missing(
            events, float(spec["rate"]), seed, label
        )
    elif kind == "wrong_id":
        events, metadata["wrong_id_events"] = _replace_wrong_ids(
            events, float(spec["rate"]), seed, label
        )
    elif kind == "missing_plane":
        source_type = str(spec["source_type"])
        events = [
            replace(event, correlation_id=None)
            if event.source_type == source_type
            else event
            for event in events
        ]
        metadata["missing_id_events"] = sum(
            event.source_type == source_type for event in events
        )
    elif kind in {"collision_same_service", "collision_cross_service"}:
        events, metadata["collision_pairs"] = _replace_collisions(
            events,
            float(spec["rate"]),
            seed,
            label,
            same_service=kind == "collision_same_service",
        )
    elif kind == "duplicate_exact":
        events, metadata["exact_duplicate_observations"] = _add_exact_duplicates(
            events, float(spec["rate"]), seed, label
        )
    elif kind == "duplicate_source_conflict":
        events, metadata["conflicting_duplicate_observations"] = (
            _add_conflicting_duplicates(events, float(spec["rate"]), seed, label)
        )
    elif kind == "clock_skew":
        events, metadata["clock_skewed_events"] = _replace_clock_skew(
            events,
            float(spec["rate"]),
            int(spec["skew_ms"]),
            seed,
            label,
        )
    elif kind == "late_arrival":
        events, metadata["late_events"] = _replace_late_arrivals(
            events,
            float(spec["rate"]),
            int(spec["delay_ms"]),
            seed,
            label,
        )
    elif kind == "out_of_order_jitter":
        events = _replace_jitter(events, int(spec["jitter_ms"]), seed, label)
        metadata["jittered_events"] = len(events)
    elif kind == "compound":
        events, metadata["collision_pairs"] = _replace_collisions(
            events,
            float(spec["collision_rate"]),
            seed,
            f"{label}-collision",
            same_service=True,
        )
        events, metadata["missing_id_events"] = _replace_selected_missing(
            events,
            float(spec["missing_rate"]),
            seed,
            f"{label}-missing",
        )
        events, metadata["late_events"] = _replace_late_arrivals(
            events,
            float(spec["late_rate"]),
            int(spec["delay_ms"]),
            seed,
            f"{label}-late",
        )
        events = _replace_jitter(
            events, int(spec["jitter_ms"]), seed, f"{label}-jitter"
        )
        metadata["jittered_events"] = len(events)
    else:
        raise ValueError(f"unknown scenario kind: {kind}")

    return sorted(events, key=lambda event: (event.source_ms, event.event_id)), metadata


def observable_ambiguity(group: Sequence[Event], maximum_chain_span_ms: int) -> bool:
    """Flag contradictions visible without consulting evaluation ground truth."""

    source_types = [event.source_type for event in group]
    duplicate_plane = len(source_types) != len(set(source_types))
    source_span_ms = max(event.source_ms for event in group) - min(
        event.source_ms for event in group
    )
    inferred_starts = {
        event.source_ms - DEFAULT_SOURCE_OFFSETS_MS[SOURCE_TYPES.index(event.source_type)]
        for event in group
    }
    inconsistent_cadence = len(inferred_starts) > 1
    return (
        duplicate_plane
        or source_span_ms > maximum_chain_span_ms
        or inconsistent_cadence
    )


def prepare_observations(
    events: Sequence[Event],
) -> tuple[list[Event], frozenset[str], dict[str, tuple[Event, ...]]]:
    """Suppress exact replays and expose conflicting source records.

    This function uses only observable fields.  An exact replay has the same
    source plane, source ID, and payload hash.  A conflict has the same source
    plane and source ID but more than one payload hash.
    """

    exact_groups: dict[tuple[str, str, str], list[Event]] = defaultdict(list)
    for event in events:
        exact_groups[(event.source_type, event.source_id, event.payload_hash)].append(event)

    retained: list[Event] = []
    deduplicated: set[str] = set()
    for observations in exact_groups.values():
        ordered = sorted(observations, key=lambda event: event.event_id)
        retained.append(ordered[0])
        deduplicated.update(event.event_id for event in ordered[1:])

    by_source_key: dict[tuple[str, str], list[Event]] = defaultdict(list)
    for event in retained:
        by_source_key[(event.source_type, event.source_id)].append(event)
    conflicts = {
        f"{source_type}:{source_id}": tuple(
            sorted(observations, key=lambda event: event.event_id)
        )
        for (source_type, source_id), observations in by_source_key.items()
        if len({event.payload_hash for event in observations}) > 1
    }
    return (
        sorted(retained, key=lambda event: (event.source_ms, event.event_id)),
        frozenset(deduplicated),
        conflicts,
    )


def strict_reconstruct(
    events: Sequence[Event], maximum_chain_span_ms: int
) -> Reconstruction:
    """Group on a complete composite key and abstain on contradictions."""

    prepared, deduplicated, conflicts = prepare_observations(events)
    conflicting_ids = {
        event.event_id for observations in conflicts.values() for event in observations
    }
    accepted_groups: dict[str, tuple[Event, ...]] = {}
    candidates: dict[str, list[Event]] = defaultdict(list)
    abstained: set[str] = set(conflicting_ids)

    for event in prepared:
        if event.event_id in conflicting_ids:
            accepted_groups[f"strict:source-conflict:{event.event_id}"] = (event,)
        elif event.correlation_id is None:
            accepted_groups[f"strict:missing-id:{event.event_id}"] = (event,)
            abstained.add(event.event_id)
        else:
            candidates[f"strict:{event.service}:{event.correlation_id}"].append(event)

    frozen_candidates = {
        key: tuple(sorted(group, key=lambda event: (event.source_ms, event.event_id)))
        for key, group in candidates.items()
    }
    flags = frozenset(
        key
        for key, group in frozen_candidates.items()
        if observable_ambiguity(group, maximum_chain_span_ms)
    )
    for key, group in frozen_candidates.items():
        if key in flags:
            for event in group:
                accepted_groups[f"strict:ambiguous:{event.event_id}"] = (event,)
                abstained.add(event.event_id)
        else:
            accepted_groups[key] = group
    return Reconstruction(
        accepted_groups,
        flags,
        frozen_candidates,
        frozenset(abstained),
        deduplicated,
        frozenset(conflicts),
    )


def correlation_only_reconstruct(
    events: Sequence[Event], maximum_chain_span_ms: int
) -> Reconstruction:
    """Ablate service scoping to mirror the v1.2 correlation lookup key."""

    prepared, deduplicated, conflicts = prepare_observations(events)
    groups: dict[str, list[Event]] = defaultdict(list)
    abstained: set[str] = set()
    candidates: dict[str, list[Event]] = defaultdict(list)
    for event in prepared:
        if event.correlation_id is None:
            key = f"correlation-only:unjoined:{event.event_id}"
            abstained.add(event.event_id)
        else:
            key = f"correlation-only:{event.correlation_id}"
        groups[key].append(event)
        if event.correlation_id is not None:
            candidates[key].append(event)
    frozen_groups = {
        key: tuple(sorted(group, key=lambda event: (event.source_ms, event.event_id)))
        for key, group in groups.items()
    }
    flags = frozenset(
        key
        for key, group in frozen_groups.items()
        if observable_ambiguity(group, maximum_chain_span_ms)
    )
    return Reconstruction(
        frozen_groups,
        flags,
        {key: tuple(group) for key, group in candidates.items()},
        frozenset(abstained),
        deduplicated,
        frozenset(conflicts),
    )


def temporal_reconstruct(
    events: Sequence[Event],
    window_ms: int,
    maximum_chain_span_ms: int,
) -> Reconstruction:
    """Greedily sessionize each service by source time, ignoring identifiers.

    This is a deliberately simple and favorable post-hoc comparator.  It sorts
    by source time before grouping, so delivery reordering affects availability
    latency but not its final groups.  A window is anchored at the first event
    of each episode; it does not expand transitively.
    """

    prepared, deduplicated, conflicts = prepare_observations(events)
    by_service: dict[str, list[Event]] = defaultdict(list)
    for event in prepared:
        by_service[event.service].append(event)

    groups: dict[str, tuple[Event, ...]] = {}
    for service, service_events in sorted(by_service.items()):
        ordered = sorted(service_events, key=lambda event: (event.source_ms, event.event_id))
        episode: list[Event] = []
        episode_start = -1
        episode_index = 0
        for event in ordered:
            if not episode:
                episode = [event]
                episode_start = event.source_ms
            elif event.source_ms - episode_start <= window_ms:
                episode.append(event)
            else:
                groups[f"temporal:{service}:{episode_index:06d}"] = tuple(episode)
                episode_index += 1
                episode = [event]
                episode_start = event.source_ms
        if episode:
            groups[f"temporal:{service}:{episode_index:06d}"] = tuple(episode)

    flags = frozenset(
        key
        for key, group in groups.items()
        if observable_ambiguity(group, maximum_chain_span_ms)
    )
    return Reconstruction(
        groups,
        flags,
        groups,
        frozenset(),
        deduplicated,
        frozenset(conflicts),
    )


def choose_two(value: int) -> int:
    return value * (value - 1) // 2


def inversion_count(events: Sequence[Event]) -> int:
    """Count physical-source/arrival inversions for canonical events in O(n log n)."""

    canonical = [event for event in events if event.event_id == event.canonical_event_id]
    source_order = sorted(
        canonical, key=lambda event: (event.truth_source_ms, event.event_id)
    )
    source_rank = {event.event_id: index for index, event in enumerate(source_order)}
    arrival_order = sorted(canonical, key=lambda event: (event.arrival_ms, event.event_id))
    ranks = [source_rank[event.event_id] for event in arrival_order]

    tree = [0] * (len(ranks) + 1)

    def add(position: int) -> None:
        position += 1
        while position < len(tree):
            tree[position] += 1
            position += position & -position

    def prefix(position: int) -> int:
        total = 0
        position += 1
        while position:
            total += tree[position]
            position -= position & -position
        return total

    inversions = 0
    seen = 0
    for rank in ranks:
        inversions += seen - prefix(rank)
        add(rank)
        seen += 1
    return inversions


def evaluate(
    events: Sequence[Event],
    reconstruction: Reconstruction,
) -> dict[str, int | float | None]:
    """Compare reconstructed groups with synthetic ground truth."""

    canonical_events = [
        event for event in events if event.event_id == event.canonical_event_id
    ]
    canonical_by_id = {event.event_id: event for event in canonical_events}
    if len(canonical_by_id) != len(canonical_events):
        raise AssertionError("canonical event IDs must be unique")
    truth_groups: dict[str, list[Event]] = defaultdict(list)
    for event in canonical_events:
        truth_groups[event.truth_chain_id].append(event)

    assigned_event_ids: set[str] = set()
    for group_id, group in reconstruction.groups.items():
        for event in group:
            if event.event_id in assigned_event_ids:
                raise AssertionError(f"event appears in multiple predicted groups: {event.event_id}")
            assigned_event_ids.add(event.event_id)
    input_event_ids = {event.event_id for event in events}
    accounted = assigned_event_ids | set(reconstruction.deduplicated_event_ids)
    if accounted != input_event_ids:
        missing = sorted(input_event_ids - accounted)[:3]
        unexpected = sorted(accounted - input_event_ids)[:3]
        raise AssertionError(
            f"observations not accounted exactly once; missing={missing} unexpected={unexpected}"
        )
    if assigned_event_ids & set(reconstruction.deduplicated_event_ids):
        raise AssertionError("a deduplicated observation cannot also be assigned")

    truth_pair_set: set[tuple[str, str]] = set()
    for group in truth_groups.values():
        for first, second in combinations(sorted(event.event_id for event in group), 2):
            truth_pair_set.add((first, second))
    total_true_pairs = len(truth_pair_set)
    total_predicted_pairs = sum(
        choose_two(len(group)) for group in reconstruction.groups.values()
    )
    correct_pair_set: set[tuple[str, str]] = set()
    accepted_ambiguous_groups: set[str] = set()
    for group_id, group in reconstruction.groups.items():
        truth_ids = {event.truth_chain_id for event in group}
        if len(truth_ids) > 1:
            accepted_ambiguous_groups.add(group_id)
        for first, second in combinations(group, 2):
            if first.canonical_event_id == second.canonical_event_id:
                continue
            canonical_pair = tuple(
                sorted((first.canonical_event_id, second.canonical_event_id))
            )
            if canonical_pair in truth_pair_set:
                correct_pair_set.add(canonical_pair)

    true_positive_pairs = len(correct_pair_set)
    false_join_count = total_predicted_pairs - true_positive_pairs
    missed_join_count = total_true_pairs - true_positive_pairs

    truth_event_sets = {
        chain_id: {event.event_id for event in group}
        for chain_id, group in truth_groups.items()
    }
    predicted_chain_group_count = 0
    exact_truth_ids: set[str] = set()
    canonical_to_groups: dict[str, set[str]] = defaultdict(set)
    for group_id, group in reconstruction.groups.items():
        canonical_ids = [event.canonical_event_id for event in group]
        for canonical_id in set(canonical_ids):
            canonical_to_groups[canonical_id].add(group_id)
        if len(set(canonical_ids)) >= 2:
            predicted_chain_group_count += 1
        if len(canonical_ids) != len(set(canonical_ids)):
            continue
        predicted_set = set(canonical_ids)
        matching_truth = {
            event.truth_chain_id for event in group if event.canonical_event_id in predicted_set
        }
        if len(matching_truth) == 1:
            truth_id = next(iter(matching_truth))
            if predicted_set == truth_event_sets[truth_id]:
                exact_truth_ids.add(truth_id)

    exact_chain_count = len(exact_truth_ids)
    chain_member_coverages: list[float] = []
    completion_times_ms: list[float] = []
    for truth_id, truth_group in truth_groups.items():
        truth_ids = truth_event_sets[truth_id]
        group_counts: Counter[str] = Counter()
        for canonical_id in truth_ids:
            group_counts.update(canonical_to_groups.get(canonical_id, ()))
        best_count = max(group_counts.values(), default=0)
        chain_member_coverages.append(best_count / len(truth_group))
        if truth_id in exact_truth_ids:
            completion_times_ms.append(
                float(
                    max(event.arrival_ms for event in truth_group)
                    - min(event.truth_source_ms for event in truth_group)
                )
            )

    candidate_ambiguous_groups = {
        group_id
        for group_id, group in reconstruction.ambiguity_candidates.items()
        if len({event.truth_chain_id for event in group}) > 1
    }
    candidate_ambiguous_event_ids = {
        event.canonical_event_id
        for group_id in candidate_ambiguous_groups
        for event in reconstruction.ambiguity_candidates[group_id]
    }
    detection_true_positive = len(
        candidate_ambiguous_groups & reconstruction.ambiguity_flags
    )
    detection_false_positive = len(
        reconstruction.ambiguity_flags - candidate_ambiguous_groups
    )
    detection_false_negative = len(
        candidate_ambiguous_groups - reconstruction.ambiguity_flags
    )
    join_precision = (
        true_positive_pairs / total_predicted_pairs if total_predicted_pairs else 1.0
    )
    join_recall = true_positive_pairs / total_true_pairs if total_true_pairs else 1.0
    # Leave zero-denominator detection metrics undefined rather than presenting
    # an unevaluable no-positive case as perfect classifier performance.
    detection_precision = (
        detection_true_positive / len(reconstruction.ambiguity_flags)
        if reconstruction.ambiguity_flags
        else None
    )
    detection_recall = (
        detection_true_positive / len(candidate_ambiguous_groups)
        if candidate_ambiguous_groups
        else None
    )

    expected_conflicts = {
        f"{event.source_type}:{event.source_id}"
        for event in events
        if event.observation_kind == "conflicting_duplicate"
    }
    conflict_true_positive = len(expected_conflicts & reconstruction.source_conflict_flags)
    conflict_precision = (
        conflict_true_positive / len(reconstruction.source_conflict_flags)
        if reconstruction.source_conflict_flags
        else None
    )
    conflict_recall = (
        conflict_true_positive / len(expected_conflicts) if expected_conflicts else None
    )

    exact_chain_accuracy = exact_chain_count / len(truth_groups)
    exact_chain_precision = (
        exact_chain_count / predicted_chain_group_count
        if predicted_chain_group_count
        else None
    )
    exact_chain_recall = exact_chain_accuracy
    if exact_chain_precision is None:
        exact_chain_f1 = None
    elif exact_chain_precision + exact_chain_recall == 0:
        exact_chain_f1 = 0.0
    else:
        exact_chain_f1 = (
            2
            * exact_chain_precision
            * exact_chain_recall
            / (exact_chain_precision + exact_chain_recall)
        )

    inversions = inversion_count(events)
    possible_event_pairs = choose_two(len(canonical_events))
    return {
        "truth_chain_count": len(truth_groups),
        "event_count": len(canonical_events),
        "canonical_event_count": len(canonical_events),
        "observation_count": len(events),
        "predicted_group_count": len(reconstruction.groups),
        "predicted_chain_group_count": predicted_chain_group_count,
        "complete_chain_count": exact_chain_count,
        "complete_chain_coverage": exact_chain_accuracy,
        "exact_chain_accuracy": exact_chain_accuracy,
        "exact_chain_precision": exact_chain_precision,
        "exact_chain_recall": exact_chain_recall,
        "exact_chain_f1": exact_chain_f1,
        "mean_chain_member_coverage": statistics.mean(chain_member_coverages),
        "true_join_pair_count": total_true_pairs,
        "predicted_join_pair_count": total_predicted_pairs,
        "correct_join_count": true_positive_pairs,
        "missed_join_count": missed_join_count,
        "missed_join_rate": missed_join_count / total_true_pairs,
        "false_join_count": false_join_count,
        "false_join_rate": (
            false_join_count / total_predicted_pairs if total_predicted_pairs else 0.0
        ),
        "join_precision": join_precision,
        "join_recall": join_recall,
        "ambiguous_group_count": len(candidate_ambiguous_groups),
        "ambiguous_event_count": len(candidate_ambiguous_event_ids),
        "ambiguous_event_rate": len(candidate_ambiguous_event_ids) / len(canonical_events),
        "accepted_ambiguous_group_count": len(accepted_ambiguous_groups),
        "detected_ambiguous_group_count": len(reconstruction.ambiguity_flags),
        "ambiguity_detection_true_positive": detection_true_positive,
        "ambiguity_detection_false_positive": detection_false_positive,
        "ambiguity_detection_false_negative": detection_false_negative,
        "ambiguity_detection_precision": detection_precision,
        "ambiguity_detection_recall": detection_recall,
        "source_conflict_group_count": len(expected_conflicts),
        "detected_source_conflict_group_count": len(reconstruction.source_conflict_flags),
        "source_conflict_detection_precision": conflict_precision,
        "source_conflict_detection_recall": conflict_recall,
        "abstained_observation_count": len(reconstruction.abstained_event_ids),
        "abstention_rate": len(reconstruction.abstained_event_ids) / len(events),
        "deduplicated_observation_count": len(reconstruction.deduplicated_event_ids),
        "deduplication_rate": len(reconstruction.deduplicated_event_ids) / len(events),
        "time_to_completeness_observations": len(completion_times_ms),
        "time_to_completeness_p50_ms": percentile(completion_times_ms, 0.50),
        "time_to_completeness_p95_ms": percentile(completion_times_ms, 0.95),
        "time_to_completeness_max_ms": max(completion_times_ms, default=None),
        "arrival_inversion_count": inversions,
        "arrival_inversion_rate": (
            inversions / possible_event_pairs if possible_event_pairs else 0.0
        ),
    }


def run_trial(
    seed: int,
    chain_count: int,
    service_count: int,
    overlap_fraction: float,
    temporal_window_ms: int,
    specs: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    pristine = generate_events(chain_count, service_count, seed, overlap_fraction)
    maximum_chain_span_ms = max(DEFAULT_SOURCE_OFFSETS_MS) - min(
        DEFAULT_SOURCE_OFFSETS_MS
    )
    rows: list[dict[str, Any]] = []
    for spec in specs:
        events, mutation_metadata = apply_scenario(pristine, spec, seed)
        algorithms = (
            ("strict_service_plus_correlation", strict_reconstruct(events, maximum_chain_span_ms)),
            (
                "correlation_id_only_ablation",
                correlation_only_reconstruct(events, maximum_chain_span_ms),
            ),
            (
                "naive_temporal_window",
                temporal_reconstruct(
                    events, temporal_window_ms, maximum_chain_span_ms
                ),
            ),
        )
        for algorithm, reconstruction in algorithms:
            row: dict[str, Any] = {
                "scenario": spec["name"],
                "algorithm": algorithm,
                "seed": seed,
                "configured_chain_count": chain_count,
                "configured_service_count": service_count,
                "configured_overlap_fraction": overlap_fraction,
                "temporal_window_ms": temporal_window_ms,
                **mutation_metadata,
            }
            row.update(evaluate(events, reconstruction))
            rows.append(row)
    return rows


SUMMARY_METRICS = (
    "complete_chain_coverage",
    "exact_chain_accuracy",
    "exact_chain_precision",
    "exact_chain_recall",
    "exact_chain_f1",
    "mean_chain_member_coverage",
    "missed_join_rate",
    "false_join_rate",
    "join_precision",
    "join_recall",
    "ambiguous_group_count",
    "ambiguous_event_rate",
    "accepted_ambiguous_group_count",
    "detected_ambiguous_group_count",
    "ambiguity_detection_precision",
    "ambiguity_detection_recall",
    "source_conflict_group_count",
    "detected_source_conflict_group_count",
    "source_conflict_detection_precision",
    "source_conflict_detection_recall",
    "abstained_observation_count",
    "abstention_rate",
    "deduplicated_observation_count",
    "deduplication_rate",
    "time_to_completeness_observations",
    "time_to_completeness_p50_ms",
    "time_to_completeness_p95_ms",
    "time_to_completeness_max_ms",
    "arrival_inversion_count",
    "arrival_inversion_rate",
)


def summarize(rows: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str], list[Mapping[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[(str(row["scenario"]), str(row["algorithm"]))].append(row)

    result: list[dict[str, Any]] = []
    for scenario, algorithm in sorted(grouped):
        group = grouped[(scenario, algorithm)]
        summary: dict[str, Any] = {
            "scenario": scenario,
            "algorithm": algorithm,
            "trials": len(group),
        }
        for metric in SUMMARY_METRICS:
            values = [float(row[metric]) for row in group if row[metric] is not None]
            summary[f"{metric}_median"] = statistics.median(values) if values else None
            summary[f"{metric}_q1"] = percentile(values, 0.25)
            summary[f"{metric}_q3"] = percentile(values, 0.75)
            summary[f"{metric}_min"] = min(values, default=None)
            summary[f"{metric}_max"] = max(values, default=None)
        result.append(summary)
    return result


METRIC_DEFINITIONS = {
    "complete_chain_coverage": (
        "Fraction of truth chains recovered as one predicted group containing all and "
        "only that chain's events."
    ),
    "mean_chain_member_coverage": (
        "Mean, over truth chains, of the largest fraction of its events placed in one "
        "predicted group; contamination does not reduce this metric."
    ),
    "exact_chain_accuracy": (
        "Exactly recovered truth chains / all truth chains; equivalent to complete-chain "
        "coverage for this closed-set experiment."
    ),
    "exact_chain_precision": (
        "Exact, uncontaminated predicted chain groups / all predicted groups containing at "
        "least two distinct canonical events."
    ),
    "exact_chain_recall": "Exactly recovered truth chains / all truth chains.",
    "exact_chain_f1": "Harmonic mean of exact-chain precision and recall.",
    "missed_join_rate": "Truth same-chain event pairs not joined / all truth join pairs.",
    "false_join_rate": (
        "Predicted cross-chain event pairs / all predicted join pairs; zero when no "
        "predicted pairs are present."
    ),
    "join_precision": "Correct same-chain predicted pairs / all predicted pairs.",
    "join_recall": "Correct same-chain predicted pairs / all truth pairs.",
    "ambiguous_group_count": (
        "Candidate key groups containing events from multiple truth chains, measured before "
        "a strict policy abstains."
    ),
    "ambiguous_event_rate": "Canonical events in ambiguous candidate groups / all canonical events.",
    "accepted_ambiguous_group_count": (
        "Mixed-truth groups actually emitted as joins after policy handling; zero is the safe-failure target."
    ),
    "ambiguity_detection_precision": (
        "Observable ambiguity warnings that identify truly mixed groups / all warnings."
    ),
    "ambiguity_detection_recall": (
        "Truly mixed candidate groups caught by duplicate-plane, excessive-span, or cadence checks."
    ),
    "source_conflict_detection_recall": (
        "Injected same-source-ID/different-payload conflicts detected / injected conflicts."
    ),
    "abstention_rate": (
        "Retained observations withheld from multi-event joining / all input observations."
    ),
    "deduplication_rate": "Exact replay observations suppressed / all input observations.",
    "time_to_completeness_p50_ms": (
        "Median, among exactly recovered chains only, of last evidence arrival minus first "
        "physical source event; logged source timestamps may be skewed."
    ),
    "time_to_completeness_p95_ms": (
        "95th percentile of the same exactly-recovered-chain availability interval."
    ),
    "arrival_inversion_rate": (
        "Physical-source-order/arrival-order inversions divided by all canonical event pairs."
    ),
}


def write_csv(path: Path, rows: Sequence[Mapping[str, Any]]) -> None:
    if not rows:
        raise ValueError("refusing to write an empty CSV")
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def canonical_json(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n"


def write_checksums(output: Path) -> None:
    checksum_path = output / "SHA256SUMS"
    lines: list[str] = []
    for path in sorted(output.iterdir(), key=lambda item: item.name):
        if path.is_file() and path != checksum_path:
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            lines.append(f"{digest}  {path.name}")
    checksum_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def environment_record(argv: Sequence[str]) -> dict[str, Any]:
    return {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        # Record a portable invocation without publishing a local account path.
        "command": [
            Path(sys.executable).name,
            "experiments/correlation_robustness/correlation_robustness.py",
            *argv,
        ],
        "python": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "cpu_count": os.cpu_count(),
        "stdlib_only": True,
    }


def parse_rate(value: str) -> float:
    rate = float(value)
    if not 0.0 <= rate <= 1.0:
        raise argparse.ArgumentTypeError("rates must be between 0 and 1")
    return rate


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--chains", type=int, default=600)
    parser.add_argument("--services", type=int, default=24)
    parser.add_argument("--seeds", nargs="+", type=int, default=list(DEFAULT_SEEDS))
    parser.add_argument(
        "--missing-rates", nargs="+", type=parse_rate, default=[0.01, 0.05, 0.10, 0.20]
    )
    parser.add_argument(
        "--collision-rates", nargs="+", type=parse_rate, default=[0.01, 0.05, 0.10]
    )
    parser.add_argument("--overlap-fraction", type=parse_rate, default=0.25)
    parser.add_argument("--temporal-window-ms", type=int, default=1500)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(__file__).resolve().parent / "results" / "reference",
    )
    return parser.parse_args(argv)


def validate_args(args: argparse.Namespace) -> None:
    if args.chains < 2:
        raise ValueError("--chains must be at least 2")
    if args.services < 2:
        raise ValueError("--services must be at least 2")
    if args.services > args.chains:
        raise ValueError("--services cannot exceed --chains")
    if not args.seeds:
        raise ValueError("at least one seed is required")
    if args.temporal_window_ms <= 0:
        raise ValueError("--temporal-window-ms must be positive")


def run_campaign(args: argparse.Namespace) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    validate_args(args)
    specs = scenario_specs(args.missing_rates, args.collision_rates)
    trial_rows: list[dict[str, Any]] = []
    for seed in args.seeds:
        trial_rows.extend(
            run_trial(
                seed=seed,
                chain_count=args.chains,
                service_count=args.services,
                overlap_fraction=args.overlap_fraction,
                temporal_window_ms=args.temporal_window_ms,
                specs=specs,
            )
        )
    summary_document = {
        "schema_version": RESULT_SCHEMA_VERSION,
        "experiment": "EACP adversarial correlation robustness",
        "data_classification": "fully synthetic; contains no user or production data",
        "configuration": {
            "chains_per_seed": args.chains,
            "events_per_chain": len(SOURCE_TYPES),
            "services": args.services,
            "seeds": list(args.seeds),
            "missing_rates": list(args.missing_rates),
            "collision_rates": list(args.collision_rates),
            "controlled_overlap_fraction": args.overlap_fraction,
            "temporal_window_ms": args.temporal_window_ms,
            "natural_observation_delay_ms": DEFAULT_NATURAL_OBSERVATION_DELAY_MS,
            "source_offsets_ms": list(DEFAULT_SOURCE_OFFSETS_MS),
        },
        "metric_definitions": METRIC_DEFINITIONS,
        "scenario_definitions": specs,
        "limitations": [
            "Synthetic six-event chains are not production traffic.",
            "The strict policy never infers a missing identifier and abstains on observable "
            "ambiguity; abstained evidence remains individually retained but unjoined.",
            "The temporal comparator is a simple post-hoc source-time heuristic, not a SIEM, "
            "tracing system, or production correlation engine.",
            "The correlation-ID-only policy is an ablation of service scoping, included to "
            "expose the consequence of the v1.2 lookup-key shape; it is not a separate product.",
            "Time-to-completeness is reported only for exactly and uncontaminated recovered chains.",
            "Ambiguity detection assumes a chain contains at most one event per modeled plane "
            "and follows the exact synthetic cadence/span; this rule is not transferable without "
            "independently justified domain invariants.",
            "A complete internally consistent semantic substitution can evade structural checks.",
            "The 30 deterministic seeds summarize controlled schedule and injection variation; "
            "they are not samples from a claimed production population.",
        ],
        "summaries": summarize(trial_rows),
    }
    return trial_rows, summary_document


def main(argv: Sequence[str] | None = None) -> int:
    from generate_figure import generate_svg

    actual_argv = list(sys.argv[1:] if argv is None else argv)
    args = parse_args(actual_argv)
    trial_rows, summary_document = run_campaign(args)
    args.output.mkdir(parents=True, exist_ok=True)

    write_csv(args.output / "trial_results.csv", trial_rows)
    write_csv(args.output / "summary_results.csv", summary_document["summaries"])
    (args.output / "trial_results.json").write_text(
        canonical_json(trial_rows), encoding="utf-8"
    )
    (args.output / "summary_results.json").write_text(
        canonical_json(summary_document), encoding="utf-8"
    )
    (args.output / "figure_correlation_robustness.svg").write_text(
        generate_svg(summary_document), encoding="utf-8"
    )
    (args.output / "environment.json").write_text(
        canonical_json(environment_record(actual_argv)), encoding="utf-8"
    )
    write_checksums(args.output)

    print(
        f"completed seeds={len(args.seeds)} scenarios={len(summary_document['scenario_definitions'])} "
        f"trial_rows={len(trial_rows)} output={args.output}",
        flush=True,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
