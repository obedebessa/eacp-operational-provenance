"""Local authenticated reference boundary; never an Internet-facing service."""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .common import HardeningError, VerifiedEvent, canonical_bytes, strict_json
from .integrity import AnchorPolicy, create_checkpoint, verify_checkpoint
from .privacy import project_github_metadata, project_kubernetes_audit
from .store import EvidenceStore
from .trust import CollectorPolicy, TokenPolicy, TrustRegistry, authenticate_token


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def load_json(path: str | Path, max_bytes: int = 2 * 1024 * 1024) -> Any:
    with Path(path).open("rb") as stream:
        content = stream.read(max_bytes + 1)
    if len(content) > max_bytes:
        raise HardeningError("input exceeds size limit")
    try:
        return strict_json(content)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise HardeningError("invalid JSON input") from None


def _key_from_environment(name: str) -> bytes:
    try:
        key = bytes.fromhex(os.environ.get(name, ""))
    except ValueError:
        raise HardeningError(f"invalid {name}; value suppressed") from None
    if len(key) != 32:
        raise HardeningError(f"{name} must provide 32 bytes as hex; value suppressed")
    return key


def collector_registry(config: dict) -> TrustRegistry:
    _validate_config_shape(config)
    policies = []
    for item in config.get("collectors", []):
        data = dict(item)
        data["public_key"] = bytes.fromhex(data.pop("public_key_hex"))
        data["allowed_origins"] = tuple(data["allowed_origins"])
        policies.append(CollectorPolicy(**data))
    return TrustRegistry(policies, max_age_seconds=config.get("max_statement_age_seconds", 300))


def token_policies(config: dict) -> list[TokenPolicy]:
    _validate_config_shape(config)
    policies = []
    for item in config.get("access", []):
        data = dict(item)
        data["roles"] = frozenset(data["roles"])
        policies.append(TokenPolicy(**data))
    return policies


def _validate_config_shape(config: Any) -> None:
    if not isinstance(config, dict):
        raise HardeningError("configuration must be an object")
    if set(config) - {"collectors", "access", "max_statement_age_seconds", "max_pending"}:
        raise HardeningError("unexpected configuration field")
    for name in ("collectors", "access"):
        items = config.get(name, [])
        if not isinstance(items, list) or any(not isinstance(item, dict) for item in items):
            raise HardeningError("policy collection must be an array of objects")
    for item in config.get("access", []):
        if not isinstance(item.get("roles"), list) or any(not isinstance(role, str) for role in item["roles"]):
            raise HardeningError("policy roles must be an array of strings")
    for item in config.get("collectors", []):
        if not isinstance(item.get("allowed_origins"), list):
            raise HardeningError("allowed origins must be an array")


def emit(value: Any, output: str | None = None) -> None:
    encoded = json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False) + "\n"
    if output:
        # Explicit exclusive creation: never silently replace evidence or anchors.
        fd = os.open(output, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(encoded)
    else:
        sys.stdout.write(encoded)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    project = sub.add_parser("project", help="minimize a record before public export")
    project.add_argument("--kind", choices=("kubernetes", "run", "job", "artifact"), required=True)
    project.add_argument("--input", required=True)
    project.add_argument("--namespace")
    project.add_argument("--output")
    verify = sub.add_parser("verify-source", help="verify a pinned collector statement without storing its payload")
    verify.add_argument("--config", required=True)
    verify.add_argument("--statement", required=True)
    for name in ("ingest", "drain", "status", "read", "audit", "checkpoint-export", "prune", "hold"):
        command = sub.add_parser(name)
        command.add_argument("--database", required=True)
        command.add_argument("--config", required=True)
        command.add_argument("--output")
        if name == "ingest":
            command.add_argument("--statement", required=True)
        if name in {"status", "read", "hold"}:
            command.add_argument("--source", required=True)
        if name == "hold":
            command.add_argument("--event", required=True)
            command.add_argument("--release", action="store_true")
            command.add_argument("--reason", required=True)
        if name == "prune":
            command.add_argument("--before", required=True)
            command.add_argument("--reason", required=True)
    anchor = sub.add_parser("sign-checkpoint", help="run only in the separate checkpoint authority")
    anchor.add_argument("--material", required=True)
    anchor.add_argument("--key-id", required=True)
    anchor.add_argument("--sequence", type=int, required=True)
    anchor.add_argument("--previous-checkpoint-sha256")
    anchor.add_argument("--output", required=True)
    check = sub.add_parser("verify-checkpoint")
    check.add_argument("--material", required=True)
    check.add_argument("--checkpoint", required=True)
    check.add_argument("--anchor-policy", required=True, help="independently acquired protected policy; never from bundle")
    check.add_argument("--output")
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        now = now_utc()
        if args.command == "project":
            raw = load_json(args.input)
            result = (project_kubernetes_audit(raw, namespace=args.namespace) if args.kind == "kubernetes"
                      else project_github_metadata(raw, kind=args.kind))
            emit({"payload": result.payload, "report": result.report}, args.output)
            return 0
        if args.command == "sign-checkpoint":
            key = Ed25519PrivateKey.from_private_bytes(_key_from_environment("EACP_ANCHOR_PRIVATE_KEY_HEX"))
            result = create_checkpoint(load_json(args.material), sequence=args.sequence, issued_at=now,
                                       key_id=args.key_id, private_key=key,
                                       previous_checkpoint_sha256=args.previous_checkpoint_sha256)
            emit(result, args.output)
            return 0
        if args.command == "verify-checkpoint":
            policy = load_json(args.anchor_policy)
            if not isinstance(policy, dict):
                raise HardeningError("anchor policy must be an object")
            policy["public_key"] = bytes.fromhex(policy.pop("public_key_hex"))
            result = verify_checkpoint(load_json(args.material), load_json(args.checkpoint), AnchorPolicy(**policy), now=now)
            emit(result, args.output)
            return 0
        config = load_json(args.config)
        if args.command == "verify-source":
            verified = collector_registry(config).verify(load_json(args.statement), now=now)
            emit({"status": "authenticated_collector_statement", "kind": type(verified).__name__,
                  "tenant_id": verified.tenant_id, "source_id": verified.source_id,
                  "collector_id": verified.collector_id, "source_truth_verified": False})
            return 0
        principal = authenticate_token(os.environ.get("EACP_ACCESS_TOKEN", ""), token_policies(config), now=now)
        verified = None
        if args.command == "ingest":
            verified = collector_registry(config).verify(load_json(args.statement), now=now)
        with EvidenceStore(args.database, _key_from_environment("EACP_STORAGE_KEY_HEX"),
                           max_pending=config.get("max_pending", 1000)) as store:
            if args.command == "ingest":
                result = (store.enqueue(principal, verified) if isinstance(verified, VerifiedEvent)
                          else store.register_inventory(principal, verified))
            elif args.command == "drain":
                result = {"drained": store.drain(principal)}
            elif args.command == "status":
                result = store.status(principal, args.source)
            elif args.command == "read":
                result = store.read_events(principal, args.source)
            elif args.command == "audit":
                result = store.audit_log(principal)
            elif args.command == "checkpoint-export":
                result = store.checkpoint_material(principal)
            elif args.command == "prune":
                result = store.prune(principal, args.before, args.reason)
            elif args.command == "hold":
                result = store.set_hold(principal, args.source, args.event, not args.release, args.reason)
            else:
                raise HardeningError("unsupported operation")
        emit(result, args.output)
        return 0
    except (HardeningError, OSError, ValueError, TypeError, KeyError) as exc:
        message = str(exc) if isinstance(exc, HardeningError) else "operation failed; sensitive details suppressed"
        print(json.dumps({"status": "error", "message": message}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
