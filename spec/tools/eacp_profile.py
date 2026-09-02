#!/usr/bin/env python3
"""Validate, migrate, and conservatively resolve EACP Profile 1.3 records.

This reference utility uses only the Python standard library.  It implements
the EACP profile's checks directly; it is not a general JSON Schema validator.
Resolution uses exact typed/scoped link keys and abstains on a missing or
multivalued seed key.  Inferred links are disabled unless explicitly enabled.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import os
import re
import sys
import tempfile
import urllib.parse
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


PROFILE = "eacp.profile/1.3"
COLLECTION_PROFILE = "eacp.collection/1.3"
RESOLUTION_PROFILE = "eacp.link-resolution/1.3"

TOP_LEVEL_REQUIRED = {
    "profile",
    "source_type",
    "source_id",
    "source_ts",
    "observed_ts",
    "actors",
    "service",
    "intent",
    "policy",
    "action",
    "outcome",
    "source_pointer",
    "links",
}
TOP_LEVEL_OPTIONAL = {"source_digest", "extensions"}
ACTOR_ROLES = {
    "initiator",
    "triggering_actor",
    "execution_principal",
    "attester",
}
ACTOR_TYPES = {
    "human",
    "service_account",
    "workload_identity",
    "automation",
    "system",
    "unknown",
    "legacy_opaque",
}
SERVICE_TYPES = {
    "logical_service",
    "application",
    "repository",
    "workload",
    "kubernetes_resource",
    "cloud_service",
    "system",
    "unknown",
    "legacy_opaque",
}
SCOPE_TYPES = {
    "global",
    "organization",
    "repository",
    "account",
    "tenant",
    "project",
    "cluster",
    "namespace",
    "environment",
    "system",
    "custom",
    "legacy_dataset",
}
LINK_TYPES = {
    "operational_correlation",
    "vcs_revision",
    "artifact_digest",
    "deployment_uid",
    "workflow_run",
    "policy_decision",
    "incident_id",
    "trace_id",
    "recovery_point",
    "ticket_id",
    "custom",
}
EVIDENCE_METHODS = {"source_native", "explicit", "digest_match", "inferred"}
REPRESENTATIONS = {
    "raw_bytes",
    "canonical_json",
    "sanitized_canonical_json",
    "adapter_defined",
}
LEGACY_FIELDS = (
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

SOURCE_TYPE_RE = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$")
CUSTOM_TYPE_RE = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)+$")
EXTENSION_KEY_RE = re.compile(
    r"^[a-z0-9][a-z0-9.-]*/[A-Za-z0-9][A-Za-z0-9._-]*$"
)
RFC3339_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)
URI_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:[^\s]+$")
CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
DIGEST_LINK_RE = re.compile(
    r"^(?:sha256:[0-9a-f]{64}|sha512:[0-9a-f]{128})$"
)
HEX_RE = re.compile(r"^[0-9a-f]+$")
LEGACY_HASH_RE = re.compile(r"^[0-9A-Fa-f]{64}$")


class ProfileError(RuntimeError):
    """An input, migration, collection, or CLI contract error."""


def _is_mapping(value: Any) -> bool:
    return isinstance(value, Mapping)


def _unknown_fields(
    value: Mapping[str, Any], allowed: set[str], path: str, errors: list[str]
) -> None:
    for key in sorted(set(value) - allowed, key=lambda item: str(item)):
        errors.append(f"{path}: unknown field {key!r}")


def _require_fields(
    value: Mapping[str, Any], required: set[str], path: str, errors: list[str]
) -> None:
    for key in sorted(required - set(value)):
        errors.append(f"{path}: missing required field {key!r}")


def _validate_text(
    value: Any,
    path: str,
    errors: list[str],
    *,
    maximum: int = 2048,
) -> bool:
    if not isinstance(value, str):
        errors.append(f"{path}: expected string")
        return False
    if not value:
        errors.append(f"{path}: must not be empty")
        return False
    if len(value) > maximum:
        errors.append(f"{path}: exceeds {maximum} characters")
    if CONTROL_RE.search(value):
        errors.append(f"{path}: contains a control character")
    return True


def _validate_timestamp(value: Any, path: str, errors: list[str]) -> None:
    if not _validate_text(value, path, errors):
        return
    assert isinstance(value, str)
    if not RFC3339_RE.fullmatch(value):
        errors.append(f"{path}: expected an RFC 3339 timestamp with a UTC offset")
        return
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.utcoffset() is None:
            raise ValueError("missing UTC offset")
    except ValueError:
        errors.append(f"{path}: invalid RFC 3339 timestamp")


def _validate_uri(value: Any, path: str, errors: list[str]) -> None:
    if not _validate_text(value, path, errors, maximum=4096):
        return
    assert isinstance(value, str)
    if not URI_RE.fullmatch(value):
        errors.append(f"{path}: expected an absolute URI without raw whitespace")
        return
    try:
        parsed = urllib.parse.urlsplit(value)
    except ValueError:
        errors.append(f"{path}: invalid URI")
        return
    if not parsed.scheme:
        errors.append(f"{path}: URI has no scheme")


def _validate_scope(value: Any, path: str, errors: list[str]) -> None:
    if not _is_mapping(value):
        errors.append(f"{path}: expected object")
        return
    scope = value
    _require_fields(scope, {"type", "id"}, path, errors)
    _unknown_fields(scope, {"type", "id"}, path, errors)
    scope_type = scope.get("type")
    if scope_type not in SCOPE_TYPES:
        errors.append(f"{path}.type: unsupported scope type {scope_type!r}")
    _validate_text(scope.get("id"), f"{path}.id", errors)


def _validate_actor(value: Any, path: str, errors: list[str]) -> None:
    if not _is_mapping(value):
        errors.append(f"{path}: expected object")
        return
    actor = value
    _require_fields(actor, {"id", "type", "scope"}, path, errors)
    _unknown_fields(actor, {"id", "type", "scope", "display_name"}, path, errors)
    _validate_text(actor.get("id"), f"{path}.id", errors)
    actor_type = actor.get("type")
    if actor_type not in ACTOR_TYPES:
        errors.append(f"{path}.type: unsupported actor type {actor_type!r}")
    _validate_scope(actor.get("scope"), f"{path}.scope", errors)
    if "display_name" in actor:
        _validate_text(actor["display_name"], f"{path}.display_name", errors)


def _validate_actors(value: Any, path: str, errors: list[str]) -> None:
    if not _is_mapping(value):
        errors.append(f"{path}: expected object")
        return
    actors = value
    _unknown_fields(actors, ACTOR_ROLES, path, errors)
    for role in sorted(set(actors) & ACTOR_ROLES):
        _validate_actor(actors[role], f"{path}.{role}", errors)


def _validate_service(value: Any, path: str, errors: list[str]) -> None:
    if not _is_mapping(value):
        errors.append(f"{path}: expected object")
        return
    service = value
    _require_fields(service, {"id", "type", "scope"}, path, errors)
    _unknown_fields(service, {"id", "type", "scope"}, path, errors)
    _validate_text(service.get("id"), f"{path}.id", errors)
    service_type = service.get("type")
    if service_type not in SERVICE_TYPES:
        errors.append(f"{path}.type: unsupported service type {service_type!r}")
    _validate_scope(service.get("scope"), f"{path}.scope", errors)


def _validate_source_digest(value: Any, path: str, errors: list[str]) -> None:
    if not _is_mapping(value):
        errors.append(f"{path}: expected object")
        return
    digest = value
    allowed = {"algorithm", "value", "representation", "canonicalization"}
    _require_fields(digest, {"algorithm", "value", "representation"}, path, errors)
    _unknown_fields(digest, allowed, path, errors)
    algorithm = digest.get("algorithm")
    if algorithm not in {"sha256", "sha512"}:
        errors.append(f"{path}.algorithm: expected 'sha256' or 'sha512'")
    digest_value = digest.get("value")
    if _validate_text(digest_value, f"{path}.value", errors):
        assert isinstance(digest_value, str)
        expected_length = 64 if algorithm == "sha256" else 128 if algorithm == "sha512" else None
        if not HEX_RE.fullmatch(digest_value) or (
            expected_length is not None and len(digest_value) != expected_length
        ):
            length_description = expected_length or "a supported number of"
            errors.append(
                f"{path}.value: expected {length_description} lowercase hexadecimal characters"
            )
    representation = digest.get("representation")
    if representation not in REPRESENTATIONS:
        errors.append(f"{path}.representation: unsupported representation {representation!r}")
    if representation != "raw_bytes" and "canonicalization" not in digest:
        errors.append(
            f"{path}.canonicalization: required unless representation is 'raw_bytes'"
        )
    if "canonicalization" in digest:
        _validate_text(digest["canonicalization"], f"{path}.canonicalization", errors)


def _link_key(link: Mapping[str, Any]) -> tuple[str, str | None, str, str, str]:
    scope = link.get("scope") if _is_mapping(link.get("scope")) else {}
    return (
        str(link.get("type")),
        str(link.get("custom_type")) if link.get("type") == "custom" else None,
        str(scope.get("type")),
        str(scope.get("id")),
        str(link.get("value")),
    )


def _link_key_object(key: tuple[str, str | None, str, str, str]) -> dict[str, Any]:
    link_type, custom_type, scope_type, scope_id, value = key
    result: dict[str, Any] = {
        "type": link_type,
        "scope": {"type": scope_type, "id": scope_id},
        "value": value,
    }
    if custom_type is not None:
        result["custom_type"] = custom_type
    return result


def _validate_link(value: Any, path: str, errors: list[str]) -> None:
    if not _is_mapping(value):
        errors.append(f"{path}: expected object")
        return
    link = value
    allowed = {"type", "custom_type", "value", "scope", "evidence_method", "confidence"}
    required = {"type", "value", "scope", "evidence_method"}
    _require_fields(link, required, path, errors)
    _unknown_fields(link, allowed, path, errors)
    link_type = link.get("type")
    if link_type not in LINK_TYPES:
        errors.append(f"{path}.type: unsupported link type {link_type!r}")
    if link_type == "custom":
        custom_type = link.get("custom_type")
        if not isinstance(custom_type, str) or not CUSTOM_TYPE_RE.fullmatch(custom_type):
            errors.append(f"{path}.custom_type: required namespaced type for a custom link")
    elif "custom_type" in link:
        errors.append(f"{path}.custom_type: permitted only when type is 'custom'")
    _validate_text(link.get("value"), f"{path}.value", errors)
    _validate_scope(link.get("scope"), f"{path}.scope", errors)
    method = link.get("evidence_method")
    if method not in EVIDENCE_METHODS:
        errors.append(f"{path}.evidence_method: unsupported method {method!r}")
    if method == "inferred":
        confidence = link.get("confidence")
        if (
            isinstance(confidence, bool)
            or not isinstance(confidence, (int, float))
            or not math.isfinite(float(confidence))
            or not 0 < float(confidence) <= 1
        ):
            errors.append(f"{path}.confidence: inferred links require a number in (0, 1]")
    elif "confidence" in link:
        errors.append(f"{path}.confidence: forbidden unless evidence_method is 'inferred'")
    if method == "digest_match" and link_type != "artifact_digest":
        errors.append(f"{path}: digest_match is valid only for artifact_digest")
    if link_type == "artifact_digest":
        digest_value = link.get("value")
        if not isinstance(digest_value, str) or not DIGEST_LINK_RE.fullmatch(digest_value):
            errors.append(
                f"{path}.value: artifact_digest requires sha256:<64 hex> or sha512:<128 hex>"
            )


def _validate_extensions(value: Any, path: str, errors: list[str]) -> None:
    if not _is_mapping(value):
        errors.append(f"{path}: expected object")
        return
    for key in value:
        if not isinstance(key, str) or not EXTENSION_KEY_RE.fullmatch(key):
            errors.append(f"{path}: extension key {key!r} is not namespaced")


def _validate_json_values(value: Any, path: str, errors: list[str]) -> None:
    """Reject values that JSON permits in Python but the JSON data model does not."""

    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            errors.append(f"{path}: non-finite number is not valid JSON")
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_json_values(item, f"{path}[{index}]", errors)
        return
    if _is_mapping(value):
        for key, item in value.items():
            if not isinstance(key, str):
                errors.append(f"{path}: object key {key!r} is not a string")
            else:
                _validate_json_values(item, f"{path}.{key}", errors)
        return
    errors.append(f"{path}: value of type {type(value).__name__} is not JSON")


def validate_record(record: Any, path: str = "$") -> list[str]:
    """Return all independent profile errors found in one record."""

    errors: list[str] = []
    _validate_json_values(record, path, errors)
    if not _is_mapping(record):
        return errors + [f"{path}: expected object"]

    _require_fields(record, TOP_LEVEL_REQUIRED, path, errors)
    _unknown_fields(record, TOP_LEVEL_REQUIRED | TOP_LEVEL_OPTIONAL, path, errors)
    if record.get("profile") != PROFILE:
        errors.append(f"{path}.profile: expected {PROFILE!r}")

    source_type = record.get("source_type")
    if not isinstance(source_type, str) or not SOURCE_TYPE_RE.fullmatch(source_type):
        errors.append(f"{path}.source_type: expected a lowercase namespaced source type")
    _validate_text(record.get("source_id"), f"{path}.source_id", errors)
    _validate_timestamp(record.get("source_ts"), f"{path}.source_ts", errors)
    _validate_timestamp(record.get("observed_ts"), f"{path}.observed_ts", errors)
    _validate_actors(record.get("actors"), f"{path}.actors", errors)
    _validate_service(record.get("service"), f"{path}.service", errors)

    for field in ("intent", "policy", "action", "outcome"):
        _validate_text(record.get(field), f"{path}.{field}", errors)
    _validate_uri(record.get("source_pointer"), f"{path}.source_pointer", errors)

    if "source_digest" in record:
        _validate_source_digest(record["source_digest"], f"{path}.source_digest", errors)

    links = record.get("links")
    if not isinstance(links, list):
        errors.append(f"{path}.links: expected array")
    else:
        seen: dict[tuple[str, str | None, str, str, str], int] = {}
        for index, link in enumerate(links):
            _validate_link(link, f"{path}.links[{index}]", errors)
            if _is_mapping(link):
                key = _link_key(link)
                if key in seen:
                    previous = seen[key]
                    errors.append(
                        f"{path}.links[{index}]: duplicates typed/scoped key "
                        f"from links[{previous}]"
                    )
                else:
                    seen[key] = index

    if "extensions" in record:
        _validate_extensions(record["extensions"], f"{path}.extensions", errors)
    return errors


def validate_collection(records: Sequence[Any]) -> list[str]:
    """Validate records and collection-level source-key uniqueness."""

    errors: list[str] = []
    seen: dict[tuple[str, str], int] = {}
    for index, record in enumerate(records):
        errors.extend(validate_record(record, f"$[{index}]"))
        if _is_mapping(record):
            source_type = record.get("source_type")
            source_id = record.get("source_id")
            if isinstance(source_type, str) and isinstance(source_id, str):
                key = (source_type, source_id)
                if key in seen:
                    errors.append(
                        f"$[{index}]: duplicate source_key {key!r}; first seen at $[{seen[key]}]"
                    )
                else:
                    seen[key] = index
    return errors


def _reject_nonstandard_constant(value: str) -> None:
    raise ValueError(f"non-standard JSON constant {value!r}")


def load_records(path: Path) -> list[dict[str, Any]]:
    """Load one record, a collection, an array, or JSON Lines."""

    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ProfileError(f"cannot read {path}: {exc}") from exc
    if not text.strip():
        raise ProfileError(f"{path}: input is empty")

    parsed: Any
    try:
        parsed = json.loads(text, parse_constant=_reject_nonstandard_constant)
    except (json.JSONDecodeError, ValueError):
        records: list[dict[str, Any]] = []
        for line_number, line in enumerate(text.splitlines(), 1):
            if not line.strip():
                continue
            try:
                item = json.loads(line, parse_constant=_reject_nonstandard_constant)
            except (json.JSONDecodeError, ValueError) as exc:
                raise ProfileError(f"{path}:{line_number}: invalid JSON Lines item: {exc}") from exc
            if not isinstance(item, dict):
                raise ProfileError(f"{path}:{line_number}: JSON Lines item must be an object")
            records.append(item)
        if not records:
            raise ProfileError(f"{path}: input contains no records")
        return records

    if isinstance(parsed, list):
        if not all(isinstance(item, dict) for item in parsed):
            raise ProfileError(f"{path}: JSON array items must be objects")
        return list(parsed)
    if isinstance(parsed, dict) and parsed.get("profile") == COLLECTION_PROFILE:
        if set(parsed) != {"profile", "records"} or not isinstance(parsed.get("records"), list):
            raise ProfileError(f"{path}: malformed {COLLECTION_PROFILE} object")
        if not all(isinstance(item, dict) for item in parsed["records"]):
            raise ProfileError(f"{path}: collection records must be objects")
        return list(parsed["records"])
    if isinstance(parsed, dict):
        return [parsed]
    raise ProfileError(f"{path}: expected a record, record array, collection, or JSON Lines")


def migrate_legacy_row(
    row: Mapping[str, str],
    *,
    scope_type: str,
    scope_id: str,
) -> dict[str, Any]:
    """Losslessly project one parsed 13-field EACP 1.2 CSV row."""

    if scope_type not in SCOPE_TYPES:
        raise ProfileError(f"unsupported migration scope type {scope_type!r}")
    if not isinstance(scope_id, str) or not scope_id or CONTROL_RE.search(scope_id):
        raise ProfileError("migration scope ID must be a non-empty string without controls")
    if set(row) != set(LEGACY_FIELDS):
        missing = sorted(set(LEGACY_FIELDS) - set(row))
        extra = sorted(set(row) - set(LEGACY_FIELDS))
        raise ProfileError(f"legacy row fields differ; missing={missing}, extra={extra}")
    for field in LEGACY_FIELDS:
        if not isinstance(row[field], str):
            raise ProfileError(f"legacy field {field!r} is not a string")
    for field in LEGACY_FIELDS:
        if field != "correlation_id" and not row[field]:
            raise ProfileError(f"legacy field {field!r} must not be empty")
    if not LEGACY_HASH_RE.fullmatch(row["content_hash"]):
        raise ProfileError("legacy content_hash must contain exactly 64 hexadecimal characters")

    scope = {"type": scope_type, "id": scope_id}
    links: list[dict[str, Any]] = []
    if row["correlation_id"]:
        links.append(
            {
                "type": "operational_correlation",
                "value": row["correlation_id"],
                "scope": dict(scope),
                "evidence_method": "explicit",
            }
        )
    record: dict[str, Any] = {
        "profile": PROFILE,
        "source_type": row["source_type"],
        "source_id": row["source_id"],
        "source_ts": row["source_ts"],
        "observed_ts": row["observed_ts"],
        "actors": {
            "execution_principal": {
                "id": row["actor"],
                "type": "legacy_opaque",
                "scope": dict(scope),
            }
        },
        "service": {
            "id": row["service"],
            "type": "legacy_opaque",
            "scope": dict(scope),
        },
        "intent": row["intent"],
        "policy": row["policy"],
        "action": row["action"],
        "outcome": row["outcome"],
        "source_pointer": row["source_pointer"],
        "links": links,
        "extensions": {
            "org.eacp/legacy_v1_2": {
                "projection": "eacp-13-field-csv",
                "original_row": {field: row[field] for field in LEGACY_FIELDS},
                "content_hash_interpretation": "preserved_opaque_not_source_digest",
            }
        },
    }
    errors = validate_record(record)
    if errors:
        raise ProfileError("migrated row is invalid: " + "; ".join(errors))
    return record


def read_legacy_csv(
    path: Path,
    *,
    scope_type: str,
    scope_id: str,
) -> list[dict[str, Any]]:
    """Read and migrate a complete EACP 1.2 CSV projection."""

    try:
        handle = path.open("r", encoding="utf-8", newline="")
    except OSError as exc:
        raise ProfileError(f"cannot read {path}: {exc}") from exc
    with handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames is None:
            raise ProfileError(f"{path}: CSV header is missing")
        if len(reader.fieldnames) != len(set(reader.fieldnames)):
            raise ProfileError(f"{path}: CSV header contains duplicate columns")
        if set(reader.fieldnames) != set(LEGACY_FIELDS):
            missing = sorted(set(LEGACY_FIELDS) - set(reader.fieldnames))
            extra = sorted(set(reader.fieldnames) - set(LEGACY_FIELDS))
            raise ProfileError(f"{path}: legacy header differs; missing={missing}, extra={extra}")
        records: list[dict[str, Any]] = []
        for line_number, row in enumerate(reader, 2):
            if None in row:
                raise ProfileError(f"{path}:{line_number}: row has more values than the header")
            try:
                records.append(
                    migrate_legacy_row(row, scope_type=scope_type, scope_id=scope_id)
                )
            except ProfileError as exc:
                raise ProfileError(f"{path}:{line_number}: {exc}") from exc
    errors = validate_collection(records)
    if errors:
        raise ProfileError("migrated collection is invalid: " + "; ".join(errors))
    return records


def _eligible_links(
    record: Mapping[str, Any],
    *,
    link_type: str,
    custom_type: str | None,
    scope: tuple[str, str] | None,
    allow_inferred: bool,
    minimum_confidence: float,
) -> dict[tuple[str, str | None, str, str, str], Mapping[str, Any]]:
    eligible: dict[tuple[str, str | None, str, str, str], Mapping[str, Any]] = {}
    for value in record.get("links", []):
        if not _is_mapping(value) or value.get("type") != link_type:
            continue
        if link_type == "custom" and value.get("custom_type") != custom_type:
            continue
        key = _link_key(value)
        if scope is not None and (key[2], key[3]) != scope:
            continue
        if value.get("evidence_method") == "inferred":
            confidence = value.get("confidence")
            if not allow_inferred or not isinstance(confidence, (int, float)):
                continue
            if isinstance(confidence, bool) or float(confidence) < minimum_confidence:
                continue
        eligible[key] = value
    return eligible


def resolve_record_links(
    records: Sequence[Mapping[str, Any]],
    *,
    source_type: str,
    source_id: str,
    link_type: str,
    custom_type: str | None = None,
    scope_type: str | None = None,
    scope_id: str | None = None,
    allow_inferred: bool = False,
    minimum_confidence: float = 1.0,
) -> dict[str, Any]:
    """Resolve a seed's one exact link key, or explicitly abstain."""

    errors = validate_collection(records)
    if errors:
        raise ProfileError("cannot resolve an invalid collection: " + "; ".join(errors))
    if link_type not in LINK_TYPES:
        raise ProfileError(f"unsupported link type {link_type!r}")
    if link_type == "custom":
        if custom_type is None or not CUSTOM_TYPE_RE.fullmatch(custom_type):
            raise ProfileError("custom link resolution requires a valid custom_type")
    elif custom_type is not None:
        raise ProfileError("custom_type is permitted only with link_type='custom'")
    if (scope_type is None) != (scope_id is None):
        raise ProfileError("scope_type and scope_id must be provided together")
    if scope_type is not None and scope_type not in SCOPE_TYPES:
        raise ProfileError(f"unsupported scope type {scope_type!r}")
    if isinstance(minimum_confidence, bool) or not 0 <= minimum_confidence <= 1:
        raise ProfileError("minimum_confidence must be a number in [0, 1]")

    source_key = (source_type, source_id)
    seed = next(
        (
            record
            for record in records
            if (record.get("source_type"), record.get("source_id")) == source_key
        ),
        None,
    )
    if seed is None:
        raise ProfileError(f"source_key {source_key!r} does not exist")
    scope = (scope_type, scope_id) if scope_type is not None and scope_id is not None else None
    candidates = _eligible_links(
        seed,
        link_type=link_type,
        custom_type=custom_type,
        scope=scope,
        allow_inferred=allow_inferred,
        minimum_confidence=float(minimum_confidence),
    )
    query: dict[str, Any] = {
        "source_key": {"source_type": source_type, "source_id": source_id},
        "link_type": link_type,
        "allow_inferred": allow_inferred,
        "minimum_confidence": float(minimum_confidence),
    }
    if custom_type is not None:
        query["custom_type"] = custom_type
    if scope is not None:
        query["scope"] = {"type": scope[0], "id": scope[1]}

    base: dict[str, Any] = {
        "profile": RESOLUTION_PROFILE,
        "query": query,
        "selected_link": None,
        "matches": [],
        "ambiguous_candidates": [],
        "excluded_ambiguous_records": [],
    }
    if not candidates:
        return {
            **base,
            "status": "missing",
            "abstained": True,
            "reason": "no_eligible_link",
        }
    if len(candidates) > 1:
        return {
            **base,
            "status": "ambiguous",
            "abstained": True,
            "ambiguous_candidates": [
                _link_key_object(key) for key in sorted(candidates)
            ],
            "reason": "multiple_eligible_link_keys",
        }

    selected = next(iter(candidates))
    selected_scope = (selected[2], selected[3])
    matches: list[dict[str, str]] = []
    excluded: list[dict[str, str]] = []
    for record in records:
        peer_candidates = _eligible_links(
            record,
            link_type=link_type,
            custom_type=custom_type,
            scope=selected_scope,
            allow_inferred=allow_inferred,
            minimum_confidence=float(minimum_confidence),
        )
        if selected not in peer_candidates:
            continue
        peer_key = {
            "source_type": str(record["source_type"]),
            "source_id": str(record["source_id"]),
        }
        if len(peer_candidates) == 1:
            matches.append(peer_key)
        else:
            excluded.append(peer_key)
    matches.sort(key=lambda item: (item["source_type"], item["source_id"]))
    excluded.sort(key=lambda item: (item["source_type"], item["source_id"]))
    return {
        **base,
        "status": "resolved",
        "abstained": False,
        "selected_link": _link_key_object(selected),
        "matches": matches,
        "excluded_ambiguous_records": excluded,
        "reason": "one_exact_link_key",
    }


def _atomic_write_jsonl(
    path: Path, records: Iterable[Mapping[str, Any]], *, force: bool
) -> None:
    path = path.resolve()
    if path.exists() and not force:
        raise ProfileError(f"refusing to overwrite existing output {path}; pass --force")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", newline="\n", dir=path.parent, delete=False
        ) as handle:
            temporary = Path(handle.name)
            for record in records:
                handle.write(
                    json.dumps(
                        record,
                        ensure_ascii=False,
                        separators=(",", ":"),
                        sort_keys=True,
                        allow_nan=False,
                    )
                    + "\n"
                )
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except OSError as exc:
        if "temporary" in locals():
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass
        raise ProfileError(f"cannot write {path}: {exc}") from exc


def _emit(value: Mapping[str, Any]) -> None:
    print(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False))


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate_parser = subparsers.add_parser("validate", help="validate JSON or JSON Lines records")
    validate_parser.add_argument("input", type=Path)

    migrate_parser = subparsers.add_parser("migrate", help="migrate the EACP 1.2 13-field CSV")
    migrate_parser.add_argument("input", type=Path)
    migrate_parser.add_argument("output", type=Path)
    migrate_parser.add_argument("--scope-type", choices=sorted(SCOPE_TYPES), required=True)
    migrate_parser.add_argument("--scope-id", required=True)
    migrate_parser.add_argument("--force", action="store_true")

    resolve_parser = subparsers.add_parser("resolve", help="resolve or abstain on one seed link")
    resolve_parser.add_argument("input", type=Path)
    resolve_parser.add_argument("--source-type", required=True)
    resolve_parser.add_argument("--source-id", required=True)
    resolve_parser.add_argument("--link-type", choices=sorted(LINK_TYPES), required=True)
    resolve_parser.add_argument("--custom-type")
    resolve_parser.add_argument("--scope-type", choices=sorted(SCOPE_TYPES))
    resolve_parser.add_argument("--scope-id")
    resolve_parser.add_argument("--allow-inferred", action="store_true")
    resolve_parser.add_argument("--minimum-confidence", type=float, default=1.0)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        if args.command == "validate":
            records = load_records(args.input)
            errors = validate_collection(records)
            _emit(
                {
                    "profile": PROFILE,
                    "valid": not errors,
                    "record_count": len(records),
                    "errors": errors,
                }
            )
            return 0 if not errors else 2

        if args.command == "migrate":
            records = read_legacy_csv(
                args.input, scope_type=args.scope_type, scope_id=args.scope_id
            )
            _atomic_write_jsonl(args.output, records, force=args.force)
            _emit(
                {
                    "profile": PROFILE,
                    "migrated": True,
                    "record_count": len(records),
                    "output": str(args.output.resolve()),
                    "source_digest_promoted_from_legacy_content_hash": False,
                }
            )
            return 0

        records = load_records(args.input)
        result = resolve_record_links(
            records,
            source_type=args.source_type,
            source_id=args.source_id,
            link_type=args.link_type,
            custom_type=args.custom_type,
            scope_type=args.scope_type,
            scope_id=args.scope_id,
            allow_inferred=args.allow_inferred,
            minimum_confidence=args.minimum_confidence,
        )
        _emit(result)
        return 0 if result["status"] == "resolved" else 3
    except ProfileError as exc:
        _emit({"profile": PROFILE, "valid": False, "errors": [str(exc)]})
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
