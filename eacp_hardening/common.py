"""Small shared contracts; callers within this Python process are trusted."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


class HardeningError(ValueError):
    """Fail-closed validation or policy error safe to expose without raw input."""


def canonical_bytes(value: Any) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise HardeningError("value is not canonical JSON") from exc


def strict_json(content: str | bytes) -> Any:
    """Reject ambiguous duplicate fields and nonfinite/over-nested input."""
    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise HardeningError("duplicate JSON field")
            result[key] = value
        return result
    try:
        value = json.loads(content, object_pairs_hook=unique_pairs)
        canonical_bytes(value)
        return value
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise HardeningError("invalid or ambiguous JSON") from None


def utc_time(value: str) -> datetime:
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z", value):
        raise HardeningError("timestamp must use UTC Z notation")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise HardeningError("invalid timestamp") from exc
    return parsed.astimezone(timezone.utc)


def identifier(value: Any, label: str = "identifier") -> str:
    if not isinstance(value, str) or not value or len(value) > 512:
        raise HardeningError(f"invalid {label}")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise HardeningError(f"invalid {label}")
    return value


@dataclass(frozen=True)
class Principal:
    """Established by an authentication boundary, never by an untrusted request."""

    subject: str
    tenant_id: str
    roles: frozenset[str]


def require_role(principal: Principal, tenant_id: str, *roles: str) -> None:
    if not isinstance(principal, Principal):
        raise HardeningError("authenticated principal required")
    if principal.tenant_id != tenant_id or not principal.roles.intersection(roles):
        raise HardeningError("access denied")


@dataclass(frozen=True)
class VerifiedEvent:
    """Authenticated collector statement, NOT a verified true upstream event."""

    tenant_id: str
    source_id: str
    event_id: str
    sequence: int
    source_ts: str
    payload: dict[str, Any]
    collector_id: str
    key_id: str
    received_at: str
    source_proof: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class VerifiedInventory:
    """Authenticated finite source inventory; authority is explicitly scoped."""

    tenant_id: str
    source_id: str
    inventory_id: str
    expected_event_ids: tuple[str, ...]
    collector_id: str
    key_id: str
    received_at: str
    source_proof: dict[str, Any] = field(default_factory=dict)
