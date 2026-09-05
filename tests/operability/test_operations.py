from __future__ import annotations
import copy
import itertools
import json
import os
import random
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from eacp_hardening.cli import collector_registry, validate_config, load_json
from eacp_hardening.common import HardeningError, Principal, canonical_bytes, strict_json, require_role
from eacp_hardening.demo import fixture, record, query, anchor_for
from eacp_hardening.integrity import digest, verify_checkpoint
from eacp_hardening.operations import OperationalStore, resolve_snapshot
from eacp_hardening.profile_api import validate_collection
from eacp_hardening.store import EvidenceStore, ConflictError, QueueFullError
from eacp_hardening.transfer import backup_store, restore_store, verify_export

NOW = '2026-09-05T06:00:00Z'
LATER = '2026-09-05T06:00:01Z'
KEY = b'z' * 32
OP = Principal('operator', 'demo', frozenset({'reader', 'writer', 'operator', 'auditor'}))


class BoundaryTests(unittest.TestCase):
    def test_B01_json_depth_size_duplicate_truncation_and_nonfinite(self):
        for content in ('[' * 200 + '0' + ']' * 200, '{"a":1,"a":2}', '{"x":NaN}', '{', '"' + 'x' * (2**21) + '"'):
            with self.subTest(length=len(content)), self.assertRaises(HardeningError):
                strict_json(content)
        self.assertEqual(strict_json('{"é":1,"é":2," A ":3,"a":4}'), {'é': 1, 'é': 2, ' A ': 3, 'a': 4})

    def test_B02_no_key_coercion_or_cycles(self):
        for value in ({1: 'one', '1': 'other'}, {'bad': float('inf')}):
            with self.assertRaises(HardeningError):
                canonical_bytes(value)
        cycle = []
        cycle.append(cycle)
        with self.assertRaises(HardeningError):
            canonical_bytes(cycle)

    def test_B03_private_file_and_symlink_boundaries(self):
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / 'test.sqlite'
            target.touch(mode=0o600)
            target.chmod(0o644)
            with self.assertRaises(HardeningError):
                EvidenceStore(target, KEY)
            target.chmod(0o600)
            link = Path(d) / 'link.sqlite'
            link.symlink_to(target)
            with self.assertRaises((HardeningError, OSError)):
                EvidenceStore(link, KEY)
            with self.assertRaises((HardeningError, OSError)):
                load_json(link)

    def test_B04_fifo_never_blocks_input(self):
        with tempfile.TemporaryDirectory() as d:
            fifo = Path(d) / 'input'
            os.mkfifo(fifo)
            with self.assertRaises(HardeningError):
                load_json(fifo)

    def test_B05_full_config_validates_unmatched_policies(self):
        config, *_ = fixture(NOW)
        self.assertEqual(validate_config(config)['status'], 'VALID_CONFIG')
        for mutate in (lambda c: c.update(max_pending=True), lambda c: c.update(max_pending=0),
                       lambda c: c['access'][0].update(roles=['all']),
                       lambda c: c['access'].append(copy.deepcopy(c['access'][0])),
                       lambda c: c['access'][0].update(valid_until='not-time'),
                       lambda c: c['collectors'][0].update(revoked='false')):
            changed = copy.deepcopy(config)
            mutate(changed)
            with self.assertRaises(HardeningError):
                validate_config(changed)

    def test_A01_tenant_and_role_are_both_required(self):
        for p in (replace(OP, tenant_id='other'), replace(OP, roles=frozenset({'reader'}))):
            with self.assertRaises(HardeningError):
                require_role(p, 'demo', 'writer')

    def test_A02_authorization_mutation_sentinel(self):
        with self.assertRaises(HardeningError):
            require_role(Principal('intruder', 'other', frozenset({'writer'})), 'demo', 'writer')


class ProfileInvariantTests(unittest.TestCase):
    def snapshot(self, records):
        return {'events': [{'event': {'payload': {'profile_record': r}, 'source_ts': NOW}} for r in records]}

    def result(self, records, q=None):
        return resolve_snapshot(self.snapshot(records), query() if q is None else q)

    def test_R01_manual_exact_oracle_permutation_and_irrelevant_additions(self):
        records = [record(now=NOW), record('peer', source_type='synthetic.runtime', now=NOW),
                   record('unrelated', ('operation-9',), now=NOW)]
        expected = [{'source_type': 'synthetic.delivery', 'source_id': 'seed'},
                    {'source_type': 'synthetic.runtime', 'source_id': 'peer'}]
        for permutation in itertools.permutations(records):
            self.assertEqual(self.result(list(permutation))['matches'], expected)
        self.assertEqual(self.result(records[:2])['matches'], expected)

    def test_R02_missing_and_multivalued_are_distinct_abstentions(self):
        for values, status in [((), 'missing'), (('one', 'two'), 'ambiguous')]:
            result = self.result([record(link_values=values, now=NOW)])
            self.assertEqual(result['status'], status)
            self.assertEqual(result['matches'], [])
            self.assertTrue(result['abstained'])

    def test_R03_scope_mutation_sentinel(self):
        seed = record(now=NOW)
        wrong = copy.deepcopy(seed['links'][0])
        wrong['scope']['id'] = 'urn:other-scope'
        wrong['value'] = 'other-candidate'
        seed['links'].append(wrong)
        self.assertEqual(self.result([seed])['status'], 'resolved')

    def test_R04_inferred_links_are_opt_in(self):
        seed = record(now=NOW)
        seed['links'][0].update(evidence_method='inferred', confidence=0.9)
        errors = validate_collection([seed])
        if errors:
            # Do not mask invalid fixtures: any validator error is a test failure.
            self.fail(str(errors))
        self.assertEqual(self.result([seed])['status'], 'missing')
        q = {**query(), 'allow_inferred': True, 'minimum_confidence': 0.8}
        self.assertEqual(self.result([seed], q)['status'], 'resolved')

    def test_R05_competing_key_introduced_later_makes_seed_ambiguous(self):
        seed = record(now=NOW)
        self.assertEqual(self.result([seed])['status'], 'resolved')
        another = copy.deepcopy(seed['links'][0])
        another['value'] = 'legitimate-competing-key'
        seed['links'].append(another)
        self.assertEqual(self.result([seed])['status'], 'ambiguous')

    def test_R06_consistent_false_chain_is_undetectable_semantic_boundary(self):
        records = [record(now=NOW), record('fabricated-peer', now=NOW)]
        for r in records:
            r['links'][0]['value'] = 'consistent-but-false-assertion'
        self.assertEqual(len(self.result(records)['matches']), 2)

    def test_R07_invalid_field_types_and_digest_fail_closed(self):
        for field, bad in [('source_id', []), ('source_ts', 'unknown'), ('actors', []), ('links', 'invalid'),
                           ('source_digest', {'algorithm': 'sha256', 'value': 'g' * 64, 'representation': 'raw_bytes'})]:
            seed = record(now=NOW)
            seed[field] = bad
            with self.assertRaises(HardeningError):
                self.result([seed])

    def test_R08_generated_order_identity_and_scope_cases(self):
        for seed_number in range(20):
            rng = random.Random(seed_number)
            records = [record(now=NOW)] + [record('peer-' + str(i), ('operation-1' if i % 2 else 'unrelated',), now=NOW) for i in range(10)]
            expected_ids = {'seed', 'peer-1', 'peer-3', 'peer-5', 'peer-7', 'peer-9'}
            rng.shuffle(records)
            self.assertEqual({r['source_id'] for r in self.result(records)['matches']}, expected_ids)


class OperationsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.config, _, events, inventories = fixture(NOW)
        self.registry = collector_registry(self.config)
        self.events = [self.registry.verify(item, now=NOW) for item in events]
        self.inventories = [self.registry.verify(item, now=NOW) for item in inventories]
        self.store = OperationalStore(self.root / 'store.sqlite', KEY, max_pending=10)
        self.addCleanup(self.store.close)
        self.clock = mock.patch('eacp_hardening.store._now', return_value=NOW)
        self.clock.start()
        self.addCleanup(self.clock.stop)
        self.authority = Ed25519PrivateKey.generate()

    def populated(self):
        for item in self.events:
            self.store.enqueue(OP, item)
        for item in self.inventories:
            self.store.register_inventory(OP, item)
        self.store.drain(OP)

    def exported(self):
        return self.store.query_export(OP, ['delivery', 'runtime'], cutoff=LATER, query=query(), config_sha256=digest(self.config))

    def verify(self, material, cp, policy, **kwargs):
        return verify_export(material, cp, policy, self.registry, now=LATER,
                             expected_query_sha256=kwargs.get('expected_query_sha256', digest(query())),
                             expected_config_sha256=kwargs.get('expected_config_sha256', digest(self.config)))

    def test_Q01_complete_snapshot_export_and_recompute(self):
        self.populated()
        material = self.exported()
        self.assertEqual([x['status'] for x in material['snapshot']['completeness']], ['COMPLETE', 'COMPLETE'])
        cp, policy = anchor_for(material, self.authority, NOW)
        self.assertEqual(self.verify(material, cp, policy)['events_verified'], 4)
        self.assertEqual(material['result']['status'], 'resolved')

    def test_Q02_missing_inventory_is_unknown_and_pending_is_incomplete(self):
        self.store.enqueue(OP, self.events[0])
        snap = self.exported()['snapshot']
        self.assertEqual(snap['completeness'][0]['status'], 'UNKNOWN')
        self.store.register_inventory(OP, self.inventories[0])
        snap = self.exported()['snapshot']
        self.assertEqual(snap['completeness'][0]['status'], 'INCOMPLETE')
        self.assertEqual(snap['events'], [])

    def test_Q03_late_arrival_cutoff_and_exact_boundary(self):
        self.populated()
        exact = self.store.snapshot(OP, ['delivery'], cutoff=NOW)
        self.assertEqual(len(exact['events']), 3)
        early = self.store.snapshot(OP, ['delivery'], cutoff='2026-09-05T05:59:59Z')
        self.assertEqual(early['events'], [])
        self.assertEqual(early['completeness'][0]['status'], 'UNKNOWN')

    def test_Q04_query_budget_and_sql_injection_are_safe(self):
        self.populated()
        with self.assertRaises(HardeningError):
            self.store.snapshot(OP, ['delivery'], cutoff=LATER, limit=1)
        hostile = self.store.snapshot(OP, ["delivery' OR 1=1 --"], cutoff=LATER)
        self.assertEqual(hostile['events'], [])

    def test_Q05_denied_reader_cannot_query_counts_export_or_cursor(self):
        self.populated()
        writer = replace(OP, roles=frozenset({'writer'}))
        with self.assertRaises(HardeningError):
            self.store.query_export(writer, ['delivery'], cutoff=LATER, query=query(), config_sha256=digest(self.config))
        other = replace(OP, tenant_id='other')
        self.assertEqual(self.store.snapshot(other, ['delivery'], cutoff=LATER)['events'], [])
        self.assertIsNone(self.store.cursor(other, 'delivery'))

    def test_X01_tampered_missing_extra_member_and_context_rejected(self):
        self.populated()
        material = self.exported()
        cp, policy = anchor_for(material, self.authority, NOW)
        for mutate in (lambda m: m['snapshot']['events'].pop(), lambda m: m.update(extra='member'),
                       lambda m: m['result'].update(matches=[]), lambda m: m.update(tenant_id='other')):
            wrong = copy.deepcopy(material)
            mutate(wrong)
            with self.assertRaises(HardeningError):
                self.verify(wrong, cp, policy)
        for overrides in ({'expected_query_sha256': '0' * 64}, {'expected_config_sha256': '0' * 64}):
            with self.assertRaises(HardeningError):
                self.verify(material, cp, policy, **overrides)

    def test_X02_validly_signed_wrong_result_not_trusted(self):
        self.populated()
        material = self.exported()
        material['result']['matches'] = []
        cp, policy = anchor_for(material, self.authority, NOW)
        with self.assertRaises(HardeningError):
            self.verify(material, cp, policy)

    def test_X03_validly_signed_changed_event_proof_not_trusted(self):
        self.populated()
        material = self.exported()
        material['snapshot']['events'][0]['event']['payload']['profile_record']['outcome'] = 'forged'
        cp, policy = anchor_for(material, self.authority, NOW)
        with self.assertRaises(HardeningError):
            self.verify(material, cp, policy)

    def test_X04_validly_signed_wrong_completeness_rejected(self):
        self.populated()
        material = self.exported()
        material['snapshot']['completeness'][0]['status'] = 'UNKNOWN'
        cp, policy = anchor_for(material, self.authority, NOW)
        with self.assertRaises(HardeningError):
            self.verify(material, cp, policy)

    def test_X05_digest_mutation_sentinel(self):
        self.populated()
        material = self.store.checkpoint_material(OP)
        cp, policy = anchor_for(material, self.authority, NOW)
        material['events'].pop()
        with self.assertRaises(HardeningError):
            verify_checkpoint(material, cp, policy, now=LATER)

    def test_X06_missing_stale_revoked_and_substituted_anchor(self):
        self.populated()
        material = self.exported()
        cp, policy = anchor_for(material, self.authority, NOW)
        for bad in (None, replace(policy, revoked=True), replace(policy, checkpoint_sha256='a' * 64)):
            with self.assertRaises(HardeningError):
                self.verify(material, cp, bad)
        with self.assertRaises(HardeningError):
            verify_checkpoint(material, cp, policy, now='2026-09-05T08:00:00Z')

    def test_I01_page_and_cursor_commit_together_and_survive_restart(self):
        events = [e for e in self.events if e.source_id == 'delivery']
        result = self.store.enqueue_page(OP, 'delivery', events, expected_cursor=None, next_cursor='page-1')
        self.assertEqual(result['status'], 'committed')
        with OperationalStore(self.store.path, KEY) as reopened:
            self.assertEqual(reopened.cursor(OP, 'delivery'), 'page-1')
            self.assertEqual(reopened.status(OP, 'delivery')['pending_count'], 3)
        with self.assertRaises(HardeningError):
            self.store.enqueue_page(OP, 'delivery', events, expected_cursor=None, next_cursor='page-1')

    def test_I02_conflicting_page_rolls_back_earlier_event_and_cursor(self):
        a = self.events[0]
        b = replace(a, event_id='different', sequence=a.sequence)
        with self.assertRaises(ConflictError):
            self.store.enqueue_page(OP, 'delivery', [a, b], expected_cursor=None, next_cursor='page-1')
        self.assertEqual(self.store.status(OP, 'delivery')['pending_count'], 0)
        self.assertIsNone(self.store.cursor(OP, 'delivery'))

    def test_I03_capacity_failure_is_atomic_and_retry_can_succeed(self):
        self.store.max_pending = 1
        events = [e for e in self.events if e.source_id == 'delivery']
        with self.assertRaises(QueueFullError):
            self.store.enqueue_page(OP, 'delivery', events, expected_cursor=None, next_cursor='page-1')
        self.assertIsNone(self.store.cursor(OP, 'delivery'))
        self.assertEqual(self.store.status(OP, 'delivery')['pending_count'], 0)
        self.store.max_pending = 10
        self.store.enqueue_page(OP, 'delivery', events, expected_cursor=None, next_cursor='page-1')
        self.assertEqual(self.store.drain(OP), 3)

    def test_I04_cursor_encrypted_and_covered_by_checkpoint(self):
        self.store.enqueue_page(OP, 'delivery', [self.events[0]], expected_cursor=None, next_cursor='SYNTHETIC_CURSOR_SECRET')
        material = self.store.checkpoint_material(OP)
        self.assertEqual(material['format'], 'eacp-store-checkpoint/2')
        for path in self.root.glob('store.sqlite*'):
            self.assertNotIn(b'SYNTHETIC_CURSOR_SECRET', path.read_bytes())
        self.assertNotIn('SYNTHETIC_CURSOR_SECRET', json.dumps(material))

    def test_I05_two_writers_exact_identity_and_index_equivalence(self):
        def writer(offset):
            with OperationalStore(self.store.path, KEY, max_pending=100) as store:
                for i in range(offset, offset + 20):
                    store.enqueue(OP, replace(self.events[0], event_id='event-' + str(i), sequence=i + 10))
        with ThreadPoolExecutor(max_workers=2) as pool:
            list(pool.map(writer, [0, 20]))
        self.store.drain(OP, 100)
        before = self.store.read_events(OP, 'delivery')
        self.store._db.execute('DROP INDEX events_queue')
        after = self.store.read_events(OP, 'delivery')
        self.assertEqual(before, after)
        self.assertEqual({r['event_id'] for r in after}, {'event-' + str(i) for i in range(40)})

    def test_O01_health_does_not_equate_process_with_complete_evidence(self):
        health = self.store.diagnostics(OP, 'delivery', now=LATER)
        self.assertEqual(health['application_health'], 'NOT_OBSERVED')
        self.assertEqual(health['source_health'], 'UNKNOWN')
        self.assertIn('completeness_unknown', health['alerts'])
        self.populated()
        health = self.store.diagnostics(OP, 'delivery', now='2026-09-05T08:00:00Z')
        self.assertIn('source_silent_or_idle_requires_reconciliation', health['alerts'])

    def test_O02_clock_backwards_and_duplicate_metrics(self):
        self.store.enqueue(OP, self.events[0])
        self.store.enqueue(OP, self.events[0])
        health = self.store.diagnostics(OP, 'delivery', now='2026-09-05T05:59:59Z')
        self.assertIn('local_clock_anomaly', health['alerts'])
        self.assertEqual(health['enqueue_outcomes_tenant_wide']['duplicate'], 1)

    def test_D01_consistent_backup_restore_content_cursor_and_resume(self):
        self.populated()
        self.store.enqueue_page(OP, 'delivery', [self.events[0]], expected_cursor=None, next_cursor='page-1')
        before = self.store.checkpoint_material(OP)
        manifest = backup_store(self.store, OP, self.root / 'backup', config_sha256=digest(self.config))
        cp, ap = anchor_for(manifest, self.authority, NOW)
        result = restore_store(self.root / 'backup', self.root / 'restored.sqlite', KEY, OP, cp, ap,
                               expected_config_sha256=digest(self.config), now=LATER)
        self.assertEqual(result['status'], 'RESTORED_RELATIVE_TO_CURRENT_ANCHOR')
        with OperationalStore(self.root / 'restored.sqlite', KEY) as restored:
            self.assertEqual(restored.checkpoint_material(OP), before)
            self.assertEqual(restored.cursor(OP, 'delivery'), 'page-1')
            self.assertEqual(restored.enqueue(OP, self.events[0])['status'], 'duplicate')

    def test_D02_old_backup_rejected_against_latest_anchor(self):
        self.populated()
        backup_store(self.store, OP, self.root / 'backup', config_sha256=digest(self.config))
        self.store.prune(OP, LATER, 'synthetic retention')
        material = self.store.checkpoint_material(OP)
        cp, ap = anchor_for(material, self.authority, NOW, 2)
        with self.assertRaises(HardeningError):
            restore_store(self.root / 'backup', self.root / 'restored.sqlite', KEY, OP, cp, ap,
                          expected_config_sha256=digest(self.config), now=LATER)
        self.assertFalse((self.root / 'restored.sqlite').exists())

    def test_D03_backup_requires_single_tenant_and_both_roles(self):
        self.populated()
        with self.assertRaises(HardeningError):
            backup_store(self.store, replace(OP, roles=frozenset({'operator'})), self.root / 'backup', config_sha256=digest(self.config))
        other = replace(OP, tenant_id='other')
        self.store.enqueue(other, replace(self.events[0], tenant_id='other'))
        with self.assertRaises(HardeningError):
            backup_store(self.store, OP, self.root / 'backup', config_sha256=digest(self.config))

    def test_D04_extra_backup_member_and_existing_destination_rejected(self):
        self.populated()
        backup = self.root / 'backup'
        manifest = backup_store(self.store, OP, backup, config_sha256=digest(self.config))
        cp, ap = anchor_for(manifest, self.authority, NOW)
        target = self.root / 'existing.sqlite'
        target.write_bytes(b'original evidence')
        with self.assertRaises(FileExistsError):
            restore_store(backup, target, KEY, OP, cp, ap, expected_config_sha256=digest(self.config), now=LATER)
        self.assertEqual(target.read_bytes(), b'original evidence')
        (backup / 'execute-me.sh').write_text('not executed')
        with self.assertRaises(HardeningError):
            restore_store(backup, self.root / 'new.sqlite', KEY, OP, cp, ap, expected_config_sha256=digest(self.config), now=LATER)


    def test_D05_recomputed_local_backup_manifest_is_not_an_anchor(self):
        import hashlib
        self.populated()
        backup = self.root / 'backup'
        manifest = backup_store(self.store, OP, backup, config_sha256=digest(self.config))
        cp, ap = anchor_for(manifest, self.authority, NOW)
        database = backup / 'evidence.sqlite'
        with database.open('ab') as stream:
            stream.write(b'consistent-local-substitution')
        manifest['database_sha256'] = hashlib.sha256(database.read_bytes()).hexdigest()
        (backup / 'manifest.json').write_bytes(canonical_bytes(manifest))
        with self.assertRaises(HardeningError):
            restore_store(backup, self.root / 'new.sqlite', KEY, OP, cp, ap,
                          expected_config_sha256=digest(self.config), now=LATER)
        self.assertFalse((self.root / 'new.sqlite').exists())


if __name__ == '__main__':
    unittest.main()
