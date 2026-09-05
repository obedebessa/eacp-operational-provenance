"""Offline query verification and bounded, owner-operated SQLite recovery.

No executable archive input, bundled trust roots, or self-reported verification.
Backup directories contain encrypted evidence and sensitive plaintext metadata.
"""
from __future__ import annotations

import hashlib
import os
import sqlite3
import time
from dataclasses import asdict
from contextlib import closing
from pathlib import Path

from .common import HardeningError, canonical_bytes, strict_json, utc_time
from .files import private_file, read_regular
from .integrity import digest, verify_checkpoint
from .operations import OperationalStore, resolve_snapshot

MAX_TRANSFER_BYTES = 32 * 1024 * 1024
MAX_BACKUP_BYTES = 256 * 1024 * 1024
STORE_TABLES = {'store_meta', 'events', 'inventories', 'quarantine', 'access_audit',
                'retention_receipts', 'collection_cursors', 'sqlite_sequence'}


def verify_export(material, checkpoint, anchor_policy, registry, *, expected_query_sha256,
                  expected_config_sha256, now):
    if anchor_policy is None:
        raise HardeningError('independently acquired anchor policy required')
    verified = verify_checkpoint(material, checkpoint, anchor_policy, now=now)
    required = {'format', 'software_version', 'profile_version', 'tenant_id', 'store_id',
                'collector_config_sha256', 'query', 'snapshot', 'result', 'transform', 'source_truth_verified'}
    if set(material) != required or material['format'] != 'eacp.query-export/1' or material['profile_version'] != '1.3':
        raise HardeningError('unsupported query export')
    if material['source_truth_verified'] is not False:
        raise HardeningError('unsupported source truth assertion')
    if digest(material['query']) != expected_query_sha256 or material['collector_config_sha256'] != expected_config_sha256:
        raise HardeningError('export query or collector policy context mismatch')
    snapshot = material['snapshot']
    if snapshot['tenant_id'] != anchor_policy.tenant_id or snapshot['store_id'] != anchor_policy.store_id:
        raise HardeningError('snapshot scope mismatch')
    if snapshot['format'] != 'eacp.query-snapshot/1' or not 0 <= len(snapshot['events']) <= 10000:
        raise HardeningError('invalid snapshot contract')
    cutoff, identities = utc_time(snapshot['cutoff']), set()
    for item in snapshot['events']:
        event = item['event']
        if event['tenant_id'] != snapshot['tenant_id'] or event['source_id'] not in snapshot['sources']:
            raise HardeningError('exported event scope mismatch')
        if utc_time(item['persisted_at']) > cutoff:
            raise HardeningError('event is beyond export cutoff')
        key = (event['source_id'], event['event_id'])
        if key in identities:
            raise HardeningError('duplicate exported event identity')
        identities.add(key)
        # Replay signature validation at the captured verification instant, with
        # externally supplied policy. Current revocation still rejects the key.
        replay = registry.verify(event['source_proof']['signed_statement'], now=event['received_at'])
        if canonical_bytes(asdict(replay)) != canonical_bytes(event):
            raise HardeningError('event differs from its authenticated collector statement')
    expected_by_source = {}
    for item in snapshot['inventories']:
        inventory = item['inventory']
        if inventory['tenant_id'] != snapshot['tenant_id'] or inventory['source_id'] not in snapshot['sources']:
            raise HardeningError('inventory scope mismatch')
        if utc_time(item['persisted_at']) > cutoff or inventory['source_id'] in expected_by_source:
            raise HardeningError('invalid inventory selection')
        replay = registry.verify(inventory['source_proof']['signed_statement'], now=inventory['received_at'])
        replay_dict = asdict(replay)
        replay_dict['expected_event_ids'] = sorted(replay_dict['expected_event_ids'])
        if canonical_bytes(replay_dict) != canonical_bytes(inventory):
            raise HardeningError('inventory differs from its authenticated statement')
        expected_by_source[inventory['source_id']] = set(inventory['expected_event_ids'])
    completeness = []
    for source in sorted(snapshot['sources']):
        expected = expected_by_source.get(source)
        actual = {event for src, event in identities if src == source}
        missing = None if expected is None else sorted(expected - actual)
        completeness.append({'source_id': source, 'status': 'UNKNOWN' if missing is None else
                             ('INCOMPLETE' if missing else 'COMPLETE'), 'missing_event_ids': missing,
                             'scope': 'finite authenticated inventory only' if expected is not None else 'unknown'})
    if completeness != snapshot['completeness']:
        raise HardeningError('export completeness does not match identities')
    if canonical_bytes(resolve_snapshot(snapshot, material['query'])) != canonical_bytes(material['result']):
        raise HardeningError('exported resolution does not match recomputed result')
    return {**verified, 'status': 'VERIFIED_QUERY_RELATIVE_TO_EXTERNAL_ANCHOR',
            'events_verified': len(identities), 'query_sha256': expected_query_sha256,
            'revocation_network_check': 'NOT_PERFORMED; uses supplied policy snapshot',
            'independence_of_anchor_administration': 'NOT_ESTABLISHED_BY_OFFLINE_VERIFIER'}


def _copy_sqlite(source, destination, *, deadline_seconds=30):
    """SQLite backup API, not a casual copy of a potentially WAL-backed file."""
    fd = private_file(destination, exclusive=True)
    os.close(fd)
    started = time.monotonic()
    with closing(sqlite3.connect(str(destination))) as target:
        def progress(status, remaining, total):
            if time.monotonic() - started > deadline_seconds:
                raise HardeningError('backup exceeded deadline; incomplete destination retained')
            if total * 65536 > MAX_BACKUP_BYTES * 16:
                raise HardeningError('backup exceeds conservative page budget')
        source.backup(target, pages=128, progress=progress, sleep=0.01)
        if target.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
            raise HardeningError('backup SQLite structural check failed')
    # Backup contains all committed pages; destination has no inherited live WAL.
    with open(destination, 'rb') as stream:
        os.fsync(stream.fileno())
    if Path(destination).stat().st_size > MAX_BACKUP_BYTES:
        raise HardeningError('backup exceeds byte budget')


def backup_store(store, principal, destination, *, config_sha256):
    tenant = store._tenant(principal)
    store._authorize(principal, tenant, 'backup', 'operator')
    store._authorize(principal, tenant, 'backup_read', 'reader')
    destination = Path(destination)
    # Restrict physical recovery to one tenant. A shared key/volume is not a
    # security boundary against another tenant's OS administrator.
    started = time.monotonic()
    with store._transaction():
        for table in ('events', 'inventories', 'quarantine', 'access_audit', 'retention_receipts', 'collection_cursors'):
            if store._db.execute(f'SELECT 1 FROM {table} WHERE tenant_id NOT IN (?, ?) LIMIT 1', (tenant, '')).fetchone():
                raise HardeningError('physical backup requires a single-tenant deployment')
        page_count = store._db.execute('PRAGMA page_count').fetchone()[0]
        page_size = store._db.execute('PRAGMA page_size').fetchone()[0]
        if page_count * page_size > MAX_BACKUP_BYTES:
            raise HardeningError('database exceeds bounded backup size')
        material = store.checkpoint_material(principal)
        destination.mkdir(mode=0o700, parents=False, exist_ok=False)
        # Separate reader sees committed evidence while the outer writer lock
        # prevents concurrent state/cursor changes during the snapshot copy.
        with closing(sqlite3.connect(store.path.resolve().as_uri() + '?mode=ro', uri=True)) as source:
            _copy_sqlite(source, destination / 'evidence.sqlite')
    raw = read_regular(destination / 'evidence.sqlite', max_bytes=MAX_BACKUP_BYTES)
    manifest = {'format': 'eacp.physical-backup/1', 'tenant_id': tenant, 'store_id': store.store_id,
                'database_sha256': hashlib.sha256(raw).hexdigest(), 'material': material,
                'config_sha256': config_sha256, 'elapsed_seconds': time.monotonic() - started,
                'secrets_included': False, 'metadata_sensitive': True,
                'external_requirements': ['storage key', 'collector/access config', 'current independent anchor'],
                'rpo_scope': 'committed evidence at snapshot; later arrivals not included'}
    fd = private_file(destination / 'manifest.json', exclusive=True)
    with os.fdopen(fd, 'wb') as out:
        out.write(canonical_bytes(manifest))
        out.flush()
        os.fsync(out.fileno())
    return manifest


def restore_store(backup, destination, encryption_key, principal, checkpoint, anchor_policy,
                  *, expected_config_sha256, now):
    """Restore only to a NEW path; old snapshots fail against a newer anchor.

Policy and key are separate operator inputs, never acquired from the backup.
Failure leaves an explicitly incomplete private file for diagnosis, not a live
replacement. Expired data in an old backup is rejected when current anchor is
advanced after pruning. Without that current anchor, do not resume ingestion.
"""
    from .common import require_role
    require_role(principal, principal.tenant_id, 'operator')
    require_role(principal, principal.tenant_id, 'reader')
    if anchor_policy is None:
        raise HardeningError('restore requires independently protected current anchor')
    started = time.monotonic()
    backup = Path(backup)
    if backup.is_symlink():
        raise HardeningError('backup directory must not be a link')
    if {p.name for p in backup.iterdir()} != {'manifest.json', 'evidence.sqlite'}:
        raise HardeningError('backup members differ from exact expected set')
    manifest = strict_json(read_regular(backup / 'manifest.json', max_bytes=MAX_TRANSFER_BYTES), max_bytes=MAX_TRANSFER_BYTES)
    raw = read_regular(backup / 'evidence.sqlite', max_bytes=MAX_BACKUP_BYTES)
    if manifest['format'] != 'eacp.physical-backup/1' or manifest['tenant_id'] != principal.tenant_id:
        raise HardeningError('backup format or tenant mismatch')
    if manifest['config_sha256'] != expected_config_sha256 or hashlib.sha256(raw).hexdigest() != manifest['database_sha256']:
        raise HardeningError('backup bytes or policy context mismatch')
    # Bind physical bytes/config too: an adjacent recomputed manifest is not trust.
    verify_checkpoint(manifest, checkpoint, anchor_policy, now=now)
    destination = Path(destination)
    with closing(sqlite3.connect((backup / 'evidence.sqlite').resolve().as_uri() + '?mode=ro&immutable=1', uri=True)) as source:
        source.execute('PRAGMA trusted_schema=OFF')
        tables = {r[0] for r in source.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if tables != STORE_TABLES:
            raise HardeningError('backup schema member set is unsupported')
        if source.execute("SELECT 1 FROM sqlite_master WHERE type IN ('trigger','view') LIMIT 1").fetchone():
            raise HardeningError('executable schema objects are unsupported in backup')
        for table in STORE_TABLES - {'store_meta', 'sqlite_sequence'}:
            if source.execute(f'SELECT 1 FROM {table} WHERE tenant_id NOT IN (?, ?) LIMIT 1', (principal.tenant_id, '')).fetchone():
                raise HardeningError('physical restore requires a single-tenant deployment')
        _copy_sqlite(source, destination)
    with OperationalStore(destination, encryption_key) as restored:
        material = restored.checkpoint_material(principal)
        if digest(material) != digest(manifest['material']):
            raise HardeningError('restored evidence differs from anchored backup material')
        verified = verify_checkpoint(manifest, checkpoint, anchor_policy, now=now)
    return {'status': 'RESTORED_RELATIVE_TO_CURRENT_ANCHOR', 'elapsed_seconds': time.monotonic() - started,
            'snapshot_event_count': len(material['events']), 'material_sha256': digest(material),
            'checkpoint': verified, 'configuration_and_keys_restored': False,
            'rpo': 'exact anchored snapshot only; no claim about later arrivals'}
