"""Bounded snapshot queries, observable ingestion and atomic collector pages.

This is a local reference implementation, not a tenant boundary against the OS
owner. Source truth, provider delivery guarantees and clock accuracy are external.
"""
from __future__ import annotations

import hashlib
from .common import HardeningError, identifier, utc_time
from .profile_api import ProfileError, validate_collection, resolve_record_links
from .store import EvidenceStore, IntegrityError, _fingerprint, _now

MAX_QUERY_EVENTS = 10000
QUERY_KEYS = {'source_type', 'source_id', 'link_type', 'scope_type', 'scope_id',
              'allow_inferred', 'minimum_confidence', 'custom_type'}


def validate_query(query):
    required = {'source_type', 'source_id', 'link_type', 'scope_type', 'scope_id'}
    if not isinstance(query, dict) or set(query) - QUERY_KEYS or not required <= set(query):
        raise HardeningError('invalid query fields; explicit type and scope required')
    for key in required:
        identifier(query[key], 'query identifier')
    if type(query.get('allow_inferred', False)) is not bool:
        raise HardeningError('allow_inferred must be boolean')
    confidence = query.get('minimum_confidence', 1.0)
    if type(confidence) not in (int, float) or not 0 <= confidence <= 1:
        raise HardeningError('invalid query confidence')


def resolve_snapshot(snapshot, query):
    validate_query(query)
    records = []
    for item in snapshot['events']:
        body = item['event']
        payload = body.get('payload')
        if not isinstance(payload, dict) or set(payload) != {'profile_record'}:
            raise HardeningError('selected event lacks the explicit Profile 1.3 payload contract')
        record = payload['profile_record']
        records.append(record)
    try:
        if validate_collection(records):
            raise HardeningError('selected Profile collection is invalid')
        for item, record in zip(snapshot['events'], records):
            # Collection envelope is UTC-microsecond precision; the profile may
            # preserve another UTC offset. Compare instants without changing IDs.
            from datetime import datetime
            if datetime.fromisoformat(record['source_ts'].replace('Z', '+00:00')) != utc_time(item['event']['source_ts']):
                raise HardeningError('Profile and envelope source timestamps differ')
        if not any(r['source_type'] == query['source_type'] and r['source_id'] == query['source_id'] for r in records):
            return {'status': 'missing', 'abstained': True, 'reason': 'seed_not_in_snapshot',
                    'matches': [], 'profile': 'eacp.link-resolution/1.3'}
        return resolve_record_links(records, **query)
    except (ProfileError, TypeError, KeyError, ValueError, RecursionError):
        raise HardeningError('invalid Profile collection or resolution request') from None


class OperationalStore(EvidenceStore):
    """Additive cursor table; old event bodies/checkpoint format are preserved.

Do not run an older writer after using page ingestion: it cannot maintain cursor
progress. No distributed leases or provider pagination semantics are invented.
"""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        try:
            self._db.execute('''CREATE TABLE IF NOT EXISTS collection_cursors(
                tenant_id TEXT NOT NULL, source_id TEXT NOT NULL, fingerprint TEXT NOT NULL,
                nonce BLOB NOT NULL, ciphertext BLOB NOT NULL, updated_at TEXT NOT NULL,
                PRIMARY KEY(tenant_id,source_id))''')
        except BaseException:
            self.close()
            raise

    def _cursor(self, tenant, source):
        row = self._db.execute('SELECT * FROM collection_cursors WHERE tenant_id=? AND source_id=?',
                               (tenant, source)).fetchone()
        if row is None:
            return None
        body = self._decrypt(row['nonce'], row['ciphertext'], self._aad(
            'cursor', tenant, source, 'current', row['fingerprint']))
        if body.get('tenant_id') != tenant or body.get('source_id') != source:
            raise IntegrityError('cursor scope mismatch')
        return body['cursor']

    def cursor(self, principal, source):
        tenant = self._tenant(principal)
        self._authorize(principal, tenant, 'cursor', 'writer', 'operator')
        identifier(source)
        with self._transaction():
            value = self._cursor(tenant, source)
            self._audit(principal, 'cursor', 'success')
            return value

    def enqueue_page(self, principal, source, events, *, expected_cursor, next_cursor):
        tenant = self._tenant(principal)
        self._authorize(principal, tenant, 'enqueue_page', 'writer')
        identifier(source)
        if expected_cursor is not None:
            identifier(expected_cursor, 'cursor')
        identifier(next_cursor, 'cursor')
        if expected_cursor == next_cursor:
            raise HardeningError('page must advance cursor')
        if not isinstance(events, list) or not 1 <= len(events) <= 1000:
            raise HardeningError('page must contain 1..1000 verified events')
        for event in events:
            self._validate_event(event)
            if event.tenant_id != tenant or event.source_id != source:
                raise HardeningError('page source scope mismatch')
        # All-or-nothing page. A failed page retains neither cursor progress nor
        # partial events. Conflicts remain visible in the safe page error/audit;
        # submit separately to the original enqueue endpoint to quarantine.
        try:
            with self._transaction():
                if self._cursor(tenant, source) != expected_cursor:
                    raise HardeningError('cursor compare-and-set failed; reread progress')
                outcomes = [self.enqueue(principal, event) for event in events]
                body = dict(tenant_id=tenant, source_id=source, cursor=next_cursor)
                fingerprint = _fingerprint(body)
                nonce, ciphertext = self._encrypt(body, self._aad('cursor', tenant, source, 'current', fingerprint))
                self._db.execute('INSERT INTO collection_cursors VALUES(?,?,?,?,?,?) ON CONFLICT(tenant_id,source_id) '
                                 'DO UPDATE SET fingerprint=excluded.fingerprint,nonce=excluded.nonce,'
                                 'ciphertext=excluded.ciphertext,updated_at=excluded.updated_at',
                                 (tenant, source, fingerprint, nonce, ciphertext, _now()))
                self._audit(principal, 'enqueue_page', 'committed', {'count': len(events)})
        except HardeningError:
            with self._transaction():
                self._audit(principal, 'enqueue_page', 'rejected')
            raise
        return {'status': 'committed', 'outcomes': outcomes,
                'ack_scope': 'events and encrypted cursor committed together; local fsync assumptions'}

    def snapshot(self, principal, sources, *, cutoff, limit=MAX_QUERY_EVENTS):
        tenant = self._tenant(principal)
        self._authorize(principal, tenant, 'snapshot', 'reader')
        when = utc_time(cutoff)
        if (not isinstance(sources, list) or not 1 <= len(sources) <= 20
                or len(set(sources)) != len(sources)):
            raise HardeningError('query requires 1..20 distinct sources')
        for source in sources:
            identifier(source)
        if type(limit) is not int or not 1 <= limit <= MAX_QUERY_EVENTS:
            raise HardeningError('invalid query event limit')
        with self._transaction():
            self._verify_identity()
            placeholders = ','.join('?' for _ in sources)
            rows = self._db.execute('SELECT * FROM events WHERE tenant_id=? AND source_id IN (' + placeholders + ') '
                                   'ORDER BY source_id,event_id LIMIT ?', (tenant, *sources, limit + 1)).fetchall()
            if len(rows) > limit:
                raise HardeningError('query exceeds bounded scope; select fewer sources')
            # Cutoff is persistence time, not event time. Late events do not
            # retroactively appear. This is a snapshot of CURRENT retained state,
            # not temporal reconstruction of state before later prune/drain.
            selected = [r for r in rows if utc_time(r['ingested_at']) <= when]
            events, unavailable = [], []
            for row in selected:
                if row['state'] == 'stored':
                    events.append({'event': self._event_body(row), 'persisted_at': row['ingested_at']})
                else:
                    unavailable.append({k: row[k] for k in ('source_id', 'event_id', 'state')})
            inventories, completeness = [], []
            for source in sorted(sources):
                invrows = self._db.execute('SELECT * FROM inventories WHERE tenant_id=? AND source_id=? '
                                          'ORDER BY id DESC LIMIT 1001', (tenant, source)).fetchall()
                if len(invrows) > 1000:
                    raise HardeningError('inventory history exceeds bounded query limit')
                inv = next((r for r in invrows if utc_time(r['registered_at']) <= when), None)
                expected, invbody = None, None
                if inv:
                    invbody = self._decrypt(inv['nonce'], inv['ciphertext'], self._aad(
                        'inventory', tenant, source, inv['inventory_id'], inv['fingerprint']))
                    inventories.append({'inventory': invbody, 'persisted_at': inv['registered_at']})
                    expected = set(invbody['expected_event_ids'])
                actual = {i['event']['event_id'] for i in events if i['event']['source_id'] == source}
                missing = None if expected is None else sorted(expected - actual)
                completeness.append({'source_id': source, 'status': 'UNKNOWN' if missing is None else
                                     ('INCOMPLETE' if missing else 'COMPLETE'), 'missing_event_ids': missing,
                                     'scope': 'finite authenticated inventory only' if inv else 'unknown'})
            self._audit(principal, 'snapshot', 'success', {'count': len(events)})
            return {'format': 'eacp.query-snapshot/1', 'tenant_id': tenant, 'store_id': self.store_id,
                    'cutoff': cutoff, 'captured_at': _now(), 'sources': sorted(sources), 'limit': limit,
                    'events': events, 'unavailable': unavailable, 'inventories': inventories,
                    'completeness': completeness,
                    'time_semantics': 'current retained state; persistence cutoff inclusive; no causal ordering'}

    def query_export(self, principal, sources, *, cutoff, query, config_sha256):
        snapshot = self.snapshot(principal, sources, cutoff=cutoff)
        from . import __version__
        return {'format': 'eacp.query-export/1', 'software_version': __version__, 'profile_version': '1.3',
                'tenant_id': snapshot['tenant_id'], 'store_id': snapshot['store_id'],
                'collector_config_sha256': config_sha256, 'query': query, 'snapshot': snapshot,
                'result': resolve_snapshot(snapshot, query),
                'transform': 'none at export; previously minimized Profile payloads only; private by default',
                'source_truth_verified': False}

    def diagnostics(self, principal, source, *, now, silence_seconds=300):
        tenant = self._tenant(principal)
        self._authorize(principal, tenant, 'diagnostics', 'reader', 'operator', 'auditor')
        if type(silence_seconds) is not int or silence_seconds < 1:
            raise HardeningError('invalid silence threshold')
        when = utc_time(now)
        with self._transaction():
            status = self.status(principal, source)
            rows = self._db.execute('SELECT ingested_at FROM events WHERE tenant_id=? AND source_id=? '
                                    "AND state='pending'", (tenant, source)).fetchall()
            last = status['last_received_at']
            silence = None if last is None else (when - utc_time(last)).total_seconds()
            clock_anomaly = silence is not None and silence < 0
            alerts = []
            if silence is None or silence > silence_seconds:
                alerts.append('source_silent_or_idle_requires_reconciliation')
            if clock_anomaly:
                alerts.append('local_clock_anomaly')
            if status['status'] != 'COMPLETE':
                alerts.append('completeness_' + status['status'].lower())
            if status['pending_count']:
                alerts.append('backlog_present')
            counts = {r['outcome']: r['n'] for r in self._db.execute(
                "SELECT outcome,count(*) AS n FROM access_audit WHERE tenant_id=? AND action='enqueue' GROUP BY outcome", (tenant,))}
            return {'format': 'eacp.diagnostics/1', 'tenant_id': tenant, 'source_id': source,
                    'storage': 'read_and_protected_body_check_succeeded', 'source_health': 'UNKNOWN',
                    'application_health': 'NOT_OBSERVED', 'anchor_health': 'NOT_CHECKED',
                    'alerts': alerts, 'source_status': status, 'silence_seconds': silence,
                    'oldest_pending_age_seconds': max(((when - utc_time(r['ingested_at'])).total_seconds() for r in rows), default=None),
                    'enqueue_outcomes_tenant_wide': counts,
                    'preauthentication_rejections': 'NOT_OBSERVED_BY_STORE',
                    'metric_scope': 'local committed audit history; bounded labels, no event IDs as labels'}

    def checkpoint_material(self, principal):
        # Enclose both inherited commitment and cursor table in the same snapshot.
        with self._transaction():
            material = super().checkpoint_material(principal)
            cursors = []
            for row in self._db.execute('SELECT * FROM collection_cursors WHERE tenant_id=? ORDER BY source_id',
                                        (principal.tenant_id,)):
                self._cursor(principal.tenant_id, row['source_id'])
                cursors.append({'source_id': row['source_id'], 'fingerprint': row['fingerprint'],
                                'protected_body_sha256': hashlib.sha256(row['nonce'] + row['ciphertext']).hexdigest(),
                                'updated_at': row['updated_at']})
            # Do not alter old checkpoint material if no cursor has been used.
            if cursors:
                material['format'] = 'eacp-store-checkpoint/2'
                material['collection_cursors'] = cursors
            return material
