"""Synthetic fixtures and installed CLI journey; never a live/provider review."""
from __future__ import annotations
import copy
import hashlib
import json
import os
import secrets
import subprocess
import sys
import time
from dataclasses import asdict
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from .common import HardeningError, canonical_bytes
from .files import private_file
from .integrity import digest, create_checkpoint, AnchorPolicy
from .trust import sign_statement

SCOPE = {'type': 'environment', 'id': 'urn:eacp:synthetic:lab'}


def record(name='seed', link_values=('operation-1',), source_type='synthetic.delivery', now='2026-09-05T06:00:00Z'):
    return {'profile': 'eacp.profile/1.3', 'source_type': source_type, 'source_id': name,
            'source_ts': now, 'observed_ts': now,
            'actors': {'execution_principal': {'id': 'synthetic-workload', 'type': 'automation', 'scope': dict(SCOPE)}},
            'service': {'id': 'synthetic-service', 'type': 'logical_service', 'scope': dict(SCOPE)},
            'intent': 'synthetic_evaluation', 'policy': 'synthetic-policy', 'action': 'synthetic-change', 'outcome': 'reported_success',
            'source_pointer': 'https://source.example.invalid/events/' + name,
            'links': [{'type': 'operational_correlation', 'scope': dict(SCOPE), 'value': value, 'evidence_method': 'explicit'}
                      for value in link_values]}


def query(name='seed', source_type='synthetic.delivery'):
    return dict(source_type=source_type, source_id=name, link_type='operational_correlation',
                scope_type=SCOPE['type'], scope_id=SCOPE['id'])


def fixture(now):
    key, token = Ed25519PrivateKey.generate(), secrets.token_hex(32)
    pub = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    config = {'max_pending': 20, 'collectors': [
        dict(key_id='key-' + source, public_key_hex=pub, tenant_id='demo', source_id=source,
             collector_id='synthetic-collector-' + source, adapter_sha256='a' * 64,
             valid_from='2020-01-01T00:00:00Z', valid_until='2099-01-01T00:00:00Z',
             allowed_origins=['https://source.example.invalid'], allow_fixture=True)
        for source in ('delivery', 'runtime')],
        'access': [dict(token_sha256=hashlib.sha256(token.encode()).hexdigest(), subject='demo-operator', tenant_id='demo',
                        roles=['reader', 'writer', 'operator', 'auditor'], valid_until='2099-01-01T00:00:00Z')]}

    def statement(source, kind, content):
        body = dict(kind=kind, tenant_id='demo', source_id=source, collector_id='synthetic-collector-' + source,
                    issued_at=now, adapter_sha256='a' * 64,
                    acquisition={'method': 'fixture', 'origin': 'https://source.example.invalid', 'raw_sha256': digest(content)},
                    content=content)
        return sign_statement(body, key_id='key-' + source, private_key=key)

    inputs = [('delivery', 'seed', ('operation-1',)), ('runtime', 'runtime', ('operation-1',)),
              ('delivery', 'missing', ()), ('delivery', 'ambiguous', ('operation-1', 'operation-2'))]
    events, sequences = [], {'delivery': 0, 'runtime': 0}
    for source, name, values in inputs:
        sequences[source] += 1
        events.append(statement(source, 'event', dict(event_id=name, sequence=sequences[source], source_ts=now,
            payload={'profile_record': record(name, values, 'synthetic.' + source, now)})))
    inventories = [statement(source, 'inventory', dict(inventory_id='finite-' + source,
                        expected_event_ids=[n for s, n, _ in inputs if s == source])) for source in sequences]
    return config, token, events, inventories


def anchor_for(material, key, now, sequence=1):
    checkpoint = create_checkpoint(material, sequence=sequence, issued_at=now, key_id='synthetic-anchor', private_key=key)
    policy = AnchorPolicy('synthetic-anchor', key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
                          material['tenant_id'], material['store_id'], digest(checkpoint), sequence)
    return checkpoint, policy


def write_json(path, value):
    fd = private_file(path, exclusive=True)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(canonical_bytes(value))


def run_demo(destination):
    from .cli import now_utc
    root = Path(destination).resolve()
    root.mkdir(mode=0o700, parents=False, exist_ok=False)
    private = root / 'private'
    private.mkdir(mode=0o700)
    config, token, events, inventories = fixture(now_utc())
    env = dict(os.environ, EACP_ACCESS_TOKEN=token, EACP_STORAGE_KEY_HEX=secrets.token_hex(32))
    authority = Ed25519PrivateKey.generate()
    write_json(root / 'config.json', config)
    commands = []

    def run(label, *args, expected=0):
        command = [sys.executable, '-m', 'eacp_hardening', *map(str, args)]
        started = time.monotonic()
        result = subprocess.run(command, cwd=root, env=env, capture_output=True, timeout=30)
        elapsed = time.monotonic() - started
        for suffix, raw in [('stdout', result.stdout), ('stderr', result.stderr)]:
            fd = private_file(root / (label + '.' + suffix), exclusive=True)
            with os.fdopen(fd, 'wb') as out:
                out.write(raw)
        receipt = dict(label=label, command=command, elapsed_seconds=elapsed, expected_exit=expected,
                       observed_exit=result.returncode, status='passed' if result.returncode == expected else 'failed')
        commands.append(receipt)
        write_json(root / (label + '.receipt.json'), receipt)
        if result.returncode != expected:
            raise HardeningError('demo command failed; inspect retained receipt ' + label)
        return json.loads(result.stdout) if result.stdout else None

    dbargs = ['--database', private / 'evidence.sqlite', '--config', root / 'config.json']
    run('01-config', 'validate-config', '--config', root / 'config.json')
    for index, item in enumerate(events + inventories):
        path = root / ('input-' + str(index) + '.json')
        write_json(path, item)
        run('02-ingest-' + str(index), 'ingest', *dbargs, '--statement', path)
    run('03-drain', 'drain', *dbargs)
    exports = {}
    for name, expected in [('seed', 'resolved'), ('missing', 'missing'), ('ambiguous', 'ambiguous')]:
        write_json(root / (name + '-query.json'), query(name))
        material = run('04-query-' + name, 'query', *dbargs, '--sources', 'delivery', 'runtime',
                       '--query', root / (name + '-query.json'))
        if material['result']['status'] != expected:
            raise HardeningError('demo manual oracle mismatch')
        exports[name] = material
    material = exports['seed']
    write_json(root / 'export.json', material)
    checkpoint, policy = anchor_for(material, authority, now_utc())
    write_json(root / 'checkpoint.json', checkpoint)
    policy_data = asdict(policy)
    policy_data['public_key_hex'] = policy_data.pop('public_key').hex()
    write_json(private / 'anchor-policy.json', policy_data)
    verify_args = ['verify-export', '--material', root / 'export.json', '--checkpoint', root / 'checkpoint.json',
                   '--anchor-policy', private / 'anchor-policy.json', '--config', root / 'config.json',
                   '--expected-query-sha256', digest(query())]
    run('05-offline-verify', *verify_args)
    wrong = copy.deepcopy(material)
    wrong['result']['matches'] = []
    write_json(root / 'tampered.json', wrong)
    bad_args = list(verify_args)
    bad_args[bad_args.index(root / 'export.json')] = root / 'tampered.json'
    run('06-tampered-rejected', *bad_args, expected=2)
    run('07-diagnostics', 'diagnostics', *dbargs, '--source', 'delivery')
    backup = run('08-backup', 'backup', *dbargs, '--destination', private / 'backup')
    cp, ap = anchor_for(backup, authority, now_utc(), 2)
    write_json(private / 'backup-checkpoint.json', cp)
    apd = asdict(ap)
    apd['public_key_hex'] = apd.pop('public_key').hex()
    write_json(private / 'backup-anchor.json', apd)
    run('09-restore', 'restore', '--backup', private / 'backup', '--destination', private / 'restored.sqlite',
        '--config', root / 'config.json', '--checkpoint', private / 'backup-checkpoint.json',
        '--anchor-policy', private / 'backup-anchor.json')
    restored = run('10-restored-query', 'query', '--database', private / 'restored.sqlite', '--config', root / 'config.json',
                   '--sources', 'delivery', 'runtime', '--query', root / 'seed-query.json')
    if restored['result'] != material['result'] or restored['snapshot']['events'] != material['snapshot']['events']:
        raise HardeningError('restored identities/content differ from manual expected snapshot')
    report = {'format': 'eacp.synthetic-cli-journey/1', 'commands': commands, 'status': 'passed',
              'oracle': {'seed': 'resolved', 'missing': 'missing', 'ambiguous': 'ambiguous'},
              'synthetic': True, 'external_human_execution': False, 'live_provider_integration': False,
              'independent_anchor_administration': False, 'ephemeral_private_keys_retained': False,
              'scope': 'local subprocess CLI and installed distribution; not organizational replication'}
    write_json(root / 'SUMMARY.json', report)
    return report
