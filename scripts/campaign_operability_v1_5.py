#!/usr/bin/env python3
"""Protocol-1 bounded local workload; receipts distinguish generation/ingestion."""
import argparse
import csv
import hashlib
import json
import platform
import random
import resource
import sqlite3
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from dataclasses import asdict

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from eacp_hardening.common import Principal, canonical_bytes, HardeningError
from eacp_hardening.cli import now_utc
from eacp_hardening.trust import CollectorPolicy, TrustRegistry, sign_statement
from eacp_hardening.operations import OperationalStore
from eacp_hardening.store import QueueFullError
from eacp_hardening.integrity import digest

OP = Principal('campaign-operator', 'synthetic', frozenset({'writer', 'reader', 'operator', 'auditor'}))
KEY = b'c' * 32


def execute(out):
    out.mkdir(exist_ok=False)
    plan = {'format': 'eacp.operability-campaign/1', 'seeds': [17, 29, 43], 'nominal_events_per_seed': 2000,
            'burst_events': 200, 'burst_capacity': 64, 'soak_seconds': 30, 'soak_rate_per_second': 20,
            'max_rss_bytes': 512 * 1024**2, 'max_disk_bytes': 256 * 1024**2, 'scenario_deadline_seconds': 120,
            'operator': 'author-directed AI-assisted; not an external review',
            'unit_of_analysis': 'one local scenario; events within it are not independent environment replications'}
    (out / 'plan.json').write_text(json.dumps(plan, indent=2))
    environment = {'platform': platform.platform(), 'python': sys.version, 'sqlite': sqlite3.sqlite_version,
                   'head': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT).decode().strip(),
                   'dirty_paths': subprocess.check_output(['git', 'status', '--short'], cwd=ROOT).decode(),
                   'source_sha256': {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
                                     for p in sorted((ROOT / 'eacp_hardening').glob('*.py'))},
                   'protocol_sha256': hashlib.sha256((ROOT / 'docs/v1.5/PROTOCOL.md').read_bytes()).hexdigest(),
                   'cache': 'ordinary OS/filesystem cache; not claimed cold'}
    (out / 'environment.json').write_text(json.dumps(environment, indent=2))
    key = Ed25519PrivateKey.generate()
    policy = CollectorPolicy('key', key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
                             'synthetic', 'source', 'collector', 'a' * 64,
                             '2020-01-01T00:00:00Z', '2099-01-01T00:00:00Z', ('https://source.example.invalid',), True)
    registry = TrustRegistry([policy])

    def signed(index):
        now = now_utc()
        content = dict(event_id='event-' + str(index), sequence=index, source_ts=now,
                       payload={'synthetic': True, 'service': index % 20, 'content': 'x' * 512})
        body = dict(kind='event', tenant_id='synthetic', source_id='source', collector_id='collector', issued_at=now,
                    adapter_sha256='a' * 64, acquisition=dict(method='fixture', origin='https://source.example.invalid', raw_sha256=digest(content)),
                    content=content)
        return sign_statement(body, key_id='key', private_key=key)

    results = []
    for name, seed, count, capacity in [(f'nominal-{s}', s, 2000, 2100) for s in plan['seeds']] + [('burst', 17, 200, 64), ('short-soak', 29, 600, 700)]:
        with tempfile.TemporaryDirectory(prefix='eacp-campaign-') as temp:
            path = Path(temp) / 'store.sqlite'
            offered = list(range(count))
            random.Random(seed).shuffle(offered)
            expected, retry, latencies, outcomes = {}, [], [], []
            start = time.monotonic()
            cpu = time.process_time()
            try:
                with OperationalStore(path, KEY, max_pending=capacity) as store:
                    for i, index in enumerate(offered):
                        if time.monotonic() - start > plan['scenario_deadline_seconds']:
                            raise HardeningError('scenario deadline exceeded')
                        if name == 'short-soak':
                            delay = start + i / 20 - time.monotonic()
                            if delay > 0:
                                time.sleep(delay)
                        statement = signed(index)
                        t = time.monotonic()
                        event = registry.verify(statement, now=now_utc())
                        try:
                            status = store.enqueue(OP, event)['status']
                            expected[event.event_id] = asdict(event)
                        except QueueFullError:
                            status = 'queue_full'
                            retry.append(event)
                        latencies.append((index, time.monotonic() - t, status))
                        outcomes.append(status)
                        if i % 100 == 0:
                            rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * (1 if sys.platform == 'darwin' else 1024)
                            if rss > plan['max_rss_bytes'] or sum(p.stat().st_size for p in Path(temp).iterdir()) > plan['max_disk_bytes']:
                                raise HardeningError('resource budget exceeded')
                    recovery_start = time.monotonic()
                    store.drain(OP, 10000)
                    for event in retry:
                        try:
                            store.enqueue(OP, event)
                        except QueueFullError:
                            store.drain(OP, 10000)
                            store.enqueue(OP, event)
                        expected[event.event_id] = asdict(event)
                    store.drain(OP, 10000)
                    actual = {e['event_id']: e for e in store.read_events(OP, 'source')}
                    if canonical_bytes(actual) != canonical_bytes(expected):
                        raise HardeningError('identity/content preservation oracle mismatch')
                    recovery = time.monotonic() - recovery_start
                with OperationalStore(path, KEY, max_pending=capacity) as reopened:
                    recovered = {e['event_id']: e for e in reopened.read_events(OP, 'source')}
                    if canonical_bytes(recovered) != canonical_bytes(expected):
                        raise HardeningError('restart preservation oracle mismatch')
                status, error = 'passed', None
            except (HardeningError, sqlite3.Error) as exc:
                status, error, recovery = 'failed', str(exc), None
            timings = sorted(t for _, t, _ in latencies)
            result = dict(scenario=name, seed=seed, status=status, error=error, offered=len(latencies),
                          initial_queued=outcomes.count('queued'), initial_rejected=outcomes.count('queue_full'),
                          recovered_distinct_count=len(expected), expected_id_content_sha256=digest(expected),
                          elapsed_seconds=time.monotonic() - start, cpu_seconds=time.process_time() - cpu,
                          max_rss_bytes=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * (1 if sys.platform == 'darwin' else 1024),
                          disk_bytes=sum(p.stat().st_size for p in Path(temp).iterdir()),
                          drain_retry_recovery_seconds=recovery, enqueue_p50_seconds=timings[len(timings)//2],
                          enqueue_p95_seconds=timings[min(len(timings)-1, int(len(timings)*0.95))],
                          enqueue_max_seconds=max(timings), cryptographic_verification='Ed25519 per event plus AES-GCM store',
                          signature_generation='outside timed ingest; synthetic source', finite_source_inventory='not registered; completeness remains UNKNOWN')
            with (out / (name + '.latencies.csv')).open('w', newline='') as stream:
                writer = csv.writer(stream)
                writer.writerow(['event_sequence', 'verify_plus_enqueue_seconds', 'status'])
                writer.writerows(latencies)
            (out / (name + '.json')).write_text(json.dumps(result, indent=2))
            results.append(result)
            print(json.dumps(result), flush=True)
    summary = dict(protocol=plan, scenarios=results, status='passed' if all(r['status']=='passed' for r in results) else 'failed',
                   scope='bounded local reference only; 30-second run is not long-term endurance, HA or enterprise capacity')
    (out / 'summary.json').write_text(json.dumps(summary, indent=2))
    return summary['status'] == 'passed'


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    raise SystemExit(not execute(parser.parse_args().output))
