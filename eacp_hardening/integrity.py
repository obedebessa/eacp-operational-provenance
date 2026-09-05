"""Snapshot integrity relative to an independently acquired checkpoint policy.

An external authority must preserve the latest checkpoint digest and sequence
floor. Keeping that policy beside a replaceable database defeats this boundary.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .common import HardeningError, canonical_bytes, identifier, utc_time

SCHEMA = "eacp.external-checkpoint/1.4"
SHA256 = re.compile(r"^[0-9a-f]{64}$")


def digest(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


@dataclass(frozen=True)
class AnchorPolicy:
    """Protected external configuration, NOT supplied by the archive under test."""

    key_id: str
    public_key: bytes
    tenant_id: str
    store_id: str
    checkpoint_sha256: str
    minimum_sequence: int
    max_age_seconds: int = 3600
    revoked: bool = False


def create_checkpoint(material: dict, *, sequence: int, issued_at: str, key_id: str,
                      private_key: Ed25519PrivateKey,
                      previous_checkpoint_sha256: str | None = None) -> dict:
    if type(sequence) is not int or sequence < 1:
        raise HardeningError("checkpoint sequence must be positive")
    if not isinstance(material, dict):
        raise HardeningError("checkpoint material must be an object")
    utc_time(issued_at)
    if previous_checkpoint_sha256 is not None and not SHA256.fullmatch(previous_checkpoint_sha256):
        raise HardeningError("invalid prior checkpoint digest")
    body = {
        "schema": SCHEMA,
        "key_id": identifier(key_id),
        "tenant_id": identifier(material.get("tenant_id")),
        "store_id": identifier(material.get("store_id")),
        "sequence": sequence,
        "issued_at": issued_at,
        "material_sha256": digest(material),
        "previous_checkpoint_sha256": previous_checkpoint_sha256,
    }
    return {**body, "signature": base64.b64encode(private_key.sign(canonical_bytes(body))).decode("ascii")}


def verify_checkpoint(material: dict, checkpoint: dict, policy: AnchorPolicy | None,
                      *, now: str) -> dict[str, Any]:
    """Reject rollback/tampering relative to an external *current* expectation.

With no protected policy the honest result is UNKNOWN, not a passing checksum.
This does not prevent deletion, prove source truth, or secure privileged readers.
    """
    if policy is None:
        return {"status": "UNKNOWN", "reason": "independent_current_anchor_required",
                "source_truth_verified": False, "rollback_prevented": False}
    if not isinstance(policy, AnchorPolicy) or type(policy.revoked) is not bool or policy.revoked:
        raise HardeningError("checkpoint authority is not trusted")
    if (not isinstance(policy.checkpoint_sha256, str) or not SHA256.fullmatch(policy.checkpoint_sha256)
            or not isinstance(policy.public_key, bytes) or len(policy.public_key) != 32
            or type(policy.minimum_sequence) is not int or policy.minimum_sequence < 1
            or type(policy.max_age_seconds) is not int or policy.max_age_seconds <= 0):
        raise HardeningError("invalid external anchor policy")
    expected_keys = {"schema", "key_id", "tenant_id", "store_id", "sequence", "issued_at",
                     "material_sha256", "previous_checkpoint_sha256", "signature"}
    if not isinstance(checkpoint, dict) or set(checkpoint) != expected_keys:
        raise HardeningError("invalid checkpoint fields")
    if not hmac.compare_digest(digest(checkpoint), policy.checkpoint_sha256):
        raise HardeningError("checkpoint does not match independent current anchor")
    if checkpoint["schema"] != SCHEMA or checkpoint["key_id"] != policy.key_id:
        raise HardeningError("unexpected checkpoint signer")
    body = {key: value for key, value in checkpoint.items() if key != "signature"}
    try:
        signature = base64.b64decode(checkpoint["signature"], validate=True)
        Ed25519PublicKey.from_public_bytes(policy.public_key).verify(signature, canonical_bytes(body))
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise HardeningError("checkpoint signature verification failed") from exc
    for key in ("tenant_id", "store_id"):
        if (checkpoint[key] != getattr(policy, key) or not isinstance(material, dict)
                or material.get(key) != getattr(policy, key)):
            raise HardeningError("checkpoint scope mismatch")
    sequence = checkpoint["sequence"]
    if type(sequence) is not int or sequence < policy.minimum_sequence:
        raise HardeningError("checkpoint sequence below protected floor")
    when, issued = utc_time(now), utc_time(checkpoint["issued_at"])
    if issued > when or when - issued > timedelta(seconds=policy.max_age_seconds):
        raise HardeningError("checkpoint outside freshness policy")
    if not isinstance(checkpoint["material_sha256"], str) or not SHA256.fullmatch(checkpoint["material_sha256"]):
        raise HardeningError("invalid checkpoint material digest")
    if not hmac.compare_digest(digest(material), checkpoint["material_sha256"]):
        raise HardeningError("evidence differs from externally anchored snapshot")
    return {"status": "VERIFIED_RELATIVE_TO_CHECKPOINT", "sequence": sequence,
            "checkpoint_sha256": policy.checkpoint_sha256,
            "source_truth_verified": False, "rollback_prevented": False,
            "scope": "exact tenant-scoped snapshot at the protected checkpoint"}
