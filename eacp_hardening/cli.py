"""Local authenticated reference boundary; never an Internet-facing service."""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .common import HardeningError, VerifiedEvent, strict_json, identifier, utc_time
from .integrity import AnchorPolicy, create_checkpoint, verify_checkpoint
from .privacy import project_github_metadata, project_kubernetes_audit
from .trust import CollectorPolicy, TokenPolicy, TrustRegistry, authenticate_token, ROLES, SHA256
from .files import read_regular
from .operations import OperationalStore
from .transfer import verify_export, backup_store, restore_store, MAX_TRANSFER_BYTES
from .integrity import digest


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def load_json(path: str | Path, max_bytes: int = 2 * 1024 * 1024) -> Any:
    content = read_regular(path, max_bytes=max_bytes)
    try:
        return strict_json(content, max_bytes=max_bytes)
    except (ValueError, UnicodeError, RecursionError):
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
        policy = TokenPolicy(**data)
        if (not isinstance(policy.token_sha256, str) or not SHA256.fullmatch(policy.token_sha256)
                or not policy.roles or not policy.roles <= ROLES or type(policy.revoked) is not bool):
            raise HardeningError('invalid access policy')
        identifier(policy.subject)
        identifier(policy.tenant_id)
        utc_time(policy.valid_until)
        if any(p.token_sha256 == policy.token_sha256 for p in policies):
            raise HardeningError('duplicate access credential policy')
        policies.append(policy)
    return policies


def validate_config(config):
    registry = collector_registry(config)
    access = token_policies(config)
    if not registry.policies or not access:
        raise HardeningError('configuration requires collector and access policies')
    capacity = config.get('max_pending', 1000)
    if type(capacity) is not int or not 1 <= capacity <= 100000:
        raise HardeningError('max_pending must be an integer in 1..100000')
    return {'status': 'VALID_CONFIG', 'collector_count': len(registry.policies), 'access_policy_count': len(access),
            'config_sha256': digest(config), 'max_pending': capacity,
            'deployment': 'local owner-trusted CLI; physical backups require one tenant',
            'fixture_keys_enabled': sum(p.allow_fixture for p in registry.policies.values())}


def load_anchor_policy(path):
    policy = load_json(path)
    if not isinstance(policy, dict):
        raise HardeningError('anchor policy must be an object')
    policy['public_key'] = bytes.fromhex(policy.pop('public_key_hex'))
    return AnchorPolicy(**policy)


def _validate_config_shape(config: Any) -> None:
    if not isinstance(config, dict):
        raise HardeningError("configuration must be an object")
    if set(config) - {"collectors", "access", "max_statement_age_seconds", "max_pending"}:
        raise HardeningError("unexpected configuration field")
    age = config.get('max_statement_age_seconds', 300)
    if type(age) is not int or not 1 <= age <= 86400:
        raise HardeningError('statement freshness must be 1..86400 seconds')
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
    encoded = json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False) + "\n"
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
    demo = sub.add_parser('demo', help='synthetic installed CLI journey; no provider access')
    demo.add_argument('--output-directory', required=True)
    github = sub.add_parser('collect-github-run', help='read-only bounded public GitHub metadata; no workflow dispatch')
    github.add_argument('--repository', required=True)
    github.add_argument('--run-id', type=int, required=True)
    github.add_argument('--attempt', type=int, required=True)
    github.add_argument('--output')
    project = sub.add_parser("project", help="minimize a record before public export")
    project.add_argument("--kind", choices=("kubernetes", "run", "job", "artifact"), required=True)
    project.add_argument("--input", required=True)
    project.add_argument("--namespace")
    project.add_argument("--output")
    verify = sub.add_parser("verify-source", help="verify a pinned collector statement without storing its payload")
    verify.add_argument("--config", required=True)
    verify.add_argument("--statement", required=True)
    config_check = sub.add_parser('validate-config')
    config_check.add_argument('--config', required=True)
    config_check.add_argument('--output')
    for name in ("ingest", "drain", "status", "read", "audit", "checkpoint-export", "prune", "hold",
                 'query', 'diagnostics', 'backup', 'ingest-page', 'cursor'):
        command = sub.add_parser(name)
        command.add_argument("--database", required=True)
        command.add_argument("--config", required=True)
        command.add_argument("--output")
        if name == "ingest":
            command.add_argument("--statement", required=True)
        if name in {"status", "read", "hold", 'diagnostics', 'ingest-page', 'cursor'}:
            command.add_argument("--source", required=True)
        if name == 'ingest-page':
            command.add_argument('--page', required=True, help='JSON expected_cursor, next_cursor and signed statements')
        if name == 'query':
            command.add_argument('--sources', nargs='+', required=True)
            command.add_argument('--query', required=True)
            command.add_argument('--cutoff', help='inclusive persistence cutoff; default current UTC')
        if name == 'diagnostics':
            command.add_argument('--silence-seconds', type=int, default=300)
        if name == 'backup':
            command.add_argument('--destination', required=True, help='new private directory')
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
    export_verify = sub.add_parser('verify-export')
    for flag in ('material', 'checkpoint', 'anchor-policy', 'config', 'expected-query-sha256'):
        export_verify.add_argument('--' + flag, required=True)
    export_verify.add_argument('--output')
    restore = sub.add_parser('restore')
    for flag in ('backup', 'destination', 'config', 'checkpoint', 'anchor-policy'):
        restore.add_argument('--' + flag, required=True)
    restore.add_argument('--output')
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        now = now_utc()
        if args.command == 'collect-github-run':
            from .github_reader import collect_run
            emit(collect_run(args.repository, args.run_id, args.attempt), args.output)
            return 0
        if args.command == 'demo':
            from .demo import run_demo
            emit(run_demo(args.output_directory))
            return 0
        if args.command == "project":
            raw = load_json(args.input)
            result = (project_kubernetes_audit(raw, namespace=args.namespace) if args.kind == "kubernetes"
                      else project_github_metadata(raw, kind=args.kind))
            emit({"payload": result.payload, "report": result.report}, args.output)
            return 0
        if args.command == "sign-checkpoint":
            key = Ed25519PrivateKey.from_private_bytes(_key_from_environment("EACP_ANCHOR_PRIVATE_KEY_HEX"))
            result = create_checkpoint(load_json(args.material, MAX_TRANSFER_BYTES), sequence=args.sequence, issued_at=now,
                                       key_id=args.key_id, private_key=key,
                                       previous_checkpoint_sha256=args.previous_checkpoint_sha256)
            emit(result, args.output)
            return 0
        if args.command == "verify-checkpoint":
            policy = load_json(args.anchor_policy)
            if not isinstance(policy, dict):
                raise HardeningError("anchor policy must be an object")
            policy["public_key"] = bytes.fromhex(policy.pop("public_key_hex"))
            result = verify_checkpoint(load_json(args.material, MAX_TRANSFER_BYTES), load_json(args.checkpoint), AnchorPolicy(**policy), now=now)
            emit(result, args.output)
            return 0
        if args.command == 'verify-export':
            config = load_json(args.config)
            validate_config(config)
            result = verify_export(load_json(args.material, MAX_TRANSFER_BYTES), load_json(args.checkpoint),
                load_anchor_policy(args.anchor_policy), collector_registry(config),
                expected_query_sha256=args.expected_query_sha256, expected_config_sha256=digest(config), now=now)
            emit(result, args.output)
            return 0
        config = load_json(args.config)
        config_result = validate_config(config)
        if args.command == 'validate-config':
            emit(config_result, args.output)
            return 0
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
        if args.command == 'restore':
            result = restore_store(args.backup, args.destination, _key_from_environment('EACP_STORAGE_KEY_HEX'),
                                   principal, load_json(args.checkpoint), load_anchor_policy(args.anchor_policy),
                                   expected_config_sha256=digest(config), now=now)
            emit(result, args.output)
            return 0
        with OperationalStore(args.database, _key_from_environment("EACP_STORAGE_KEY_HEX"),
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
            elif args.command == 'query':
                result = store.query_export(principal, args.sources, cutoff=args.cutoff or now,
                                           query=load_json(args.query), config_sha256=digest(config))
            elif args.command == 'diagnostics':
                result = store.diagnostics(principal, args.source, now=now, silence_seconds=args.silence_seconds)
            elif args.command == 'backup':
                result = backup_store(store, principal, args.destination, config_sha256=digest(config))
            elif args.command == 'cursor':
                result = {'cursor': store.cursor(principal, args.source)}
            elif args.command == 'ingest-page':
                page = load_json(args.page)
                if not isinstance(page, dict) or set(page) != {'expected_cursor', 'next_cursor', 'statements'}:
                    raise HardeningError('invalid page fields')
                if not isinstance(page['statements'], list) or not 1 <= len(page['statements']) <= 1000:
                    raise HardeningError('page requires 1..1000 signed statements')
                registry = collector_registry(config)
                events = [registry.verify(item, now=now) for item in page['statements']]
                result = store.enqueue_page(principal, args.source, events, expected_cursor=page['expected_cursor'],
                                            next_cursor=page['next_cursor'])
            else:
                raise HardeningError("unsupported operation")
        emit(result, args.output)
        return 0
    except (HardeningError, OSError, ValueError, TypeError, KeyError, sqlite3.Error) as exc:
        message = str(exc) if isinstance(exc, HardeningError) else "operation failed; sensitive details suppressed"
        print(json.dumps({"status": "error", "message": message}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
