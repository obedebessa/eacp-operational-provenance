"""Failure-oriented tests for the bounded encrypted SQLite ingestion reference."""

from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path

from eacp_hardening.common import HardeningError, Principal, VerifiedEvent, VerifiedInventory
from eacp_hardening.store import ConflictError, EvidenceStore, IntegrityError, QueueFullError


KEY = b"a" * 32
TIME = "2026-09-04T12:00:00Z"


def principal(role: str, tenant: str = "tenant-a") -> Principal:
    return Principal("reviewer-" + role, tenant, frozenset({role}))


def event(event_id: str = "event-1", sequence: int = 1, tenant: str = "tenant-a", **updates) -> VerifiedEvent:
    base = VerifiedEvent(tenant, "source-1", event_id, sequence, TIME,
                         {"secret": "private-payload-never-in-database-plaintext", "change": "deployment"},
                         "collector-1", "key-1", TIME)
    return replace(base, **updates)


def inventory(ids: tuple[str, ...] = ("event-1",), inventory_id: str = "inventory-1",
              tenant: str = "tenant-a") -> VerifiedInventory:
    return VerifiedInventory(tenant, "source-1", inventory_id, ids, "collector-1", "key-1", TIME)


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "evidence.sqlite"
        self.store = EvidenceStore(self.path, KEY, max_pending=3)
        self.writer, self.reader = principal("writer"), principal("reader")
        self.operator, self.auditor = principal("operator"), principal("auditor")

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def test_ack_is_persistent_and_duplicate_retry_ignores_acquisition_time(self):
        self.assertEqual(self.store.enqueue(self.writer, event())["status"], "queued")
        self.store.close()
        self.store = EvidenceStore(self.path, KEY, max_pending=3)
        self.assertEqual(self.store.status(self.reader, "source-1")["pending_count"], 1)
        later = replace(event(), received_at="2026-09-05T00:00:00Z")
        self.assertEqual(self.store.enqueue(self.writer, later)["status"], "duplicate")
        self.assertEqual(self.store.drain(self.operator), 1)
        self.assertEqual(self.store.read_events(self.reader, "source-1")[0]["received_at"], TIME)
        self.assertEqual(self.store.enqueue(self.writer, later)["status"], "duplicate")

    def test_reissued_authenticated_statement_with_new_key_and_proof_is_duplicate(self):
        original = event(source_proof={"signed_statement": "original-proof", "assurance": "collector-only"})
        self.store.enqueue(self.writer, original)
        reissued = replace(original, collector_id="replacement-collector", key_id="rotated-key",
                           received_at="2026-09-05T00:00:00Z", source_proof={"signed_statement": "renewed-proof"})
        self.assertEqual(self.store.enqueue(self.writer, reissued)["status"], "duplicate")
        self.store.drain(self.operator)
        stored = self.store.read_events(self.reader, "source-1")[0]
        self.assertEqual(stored["collector_id"], original.collector_id)
        self.assertEqual(stored["key_id"], original.key_id)
        self.assertEqual(stored["source_proof"], original.source_proof)
        with self.assertRaises(ConflictError):
            self.store.enqueue(self.writer, replace(reissued, payload={"changed": True}))
        first_inventory = inventory()
        self.store.register_inventory(self.writer, first_inventory)
        renewed_inventory = replace(first_inventory, collector_id="collector-2", key_id="key-2",
                                    received_at="2026-09-05T00:00:00Z", source_proof={"new_signature": "retained-in-transit"})
        self.assertEqual(self.store.register_inventory(self.writer, renewed_inventory)["status"], "duplicate")

    def test_duplicates_are_accepted_at_capacity_but_new_events_are_not(self):
        for i in range(1, 4):
            self.store.enqueue(self.writer, event(f"event-{i}", i))
        with self.assertRaises(QueueFullError):
            self.store.enqueue(self.writer, event("event-4", 4))
        self.assertEqual(self.store.enqueue(self.writer, event())["status"], "duplicate")
        self.assertEqual(self.store.drain(self.operator, limit=1), 1)
        self.assertEqual(self.store.enqueue(self.writer, event("event-4", 4))["status"], "queued")
        self.assertTrue(any(r["outcome"] == "queue_full" for r in self.store.audit_log(self.auditor)))

    def test_conflicts_and_sequence_collisions_preserve_original_and_quarantine_input(self):
        self.store.enqueue(self.writer, event())
        with self.assertRaisesRegex(ConflictError, "event_id_conflict"):
            self.store.enqueue(self.writer, event(payload={"secret": "different-private-payload"}))
        with self.assertRaisesRegex(ConflictError, "sequence_conflict"):
            self.store.enqueue(self.writer, event("event-imposter", 1))
        self.assertEqual(self.store.drain(self.operator), 1)
        self.assertEqual(self.store.read_events(self.reader, "source-1")[0]["payload"], event().payload)
        q = self.store.read_quarantine(self.auditor)
        self.assertEqual(len(q), 2)
        self.assertEqual({r["reason"] for r in q}, {"event_id_conflict", "sequence_conflict"})
        with self.assertRaises(HardeningError):
            self.store.read_quarantine(self.reader)

    def test_inventory_arrival_out_of_order_pending_missing_and_late_recovery(self):
        self.assertEqual(self.store.status(self.reader, "source-1")["status"], "UNKNOWN")
        self.store.enqueue(self.writer, event("event-3", 3))
        self.store.enqueue(self.writer, event())
        self.store.register_inventory(self.writer, inventory(("event-1", "event-2", "event-3")))
        self.assertEqual(self.store.status(self.reader, "source-1")["missing_event_ids"],
                         ["event-1", "event-2", "event-3"])
        self.store.drain(self.operator)
        before = self.store.status(self.reader, "source-1")
        self.assertEqual(before["status"], "INCOMPLETE")
        self.assertEqual(before["missing_event_ids"], ["event-2"])
        self.assertEqual(before["sequence_gap_ranges"], [[2, 2]])
        self.store.enqueue(self.writer, event("event-2", 2, source_ts="2026-09-03T12:00:00Z"))
        self.store.drain(self.operator)
        after = self.store.status(self.reader, "source-1")
        self.assertEqual(after["status"], "COMPLETE")
        self.assertEqual(after["sequence_gap_ranges"], [])
        self.assertEqual([r["event_id"] for r in self.store.read_events(self.reader, "source-1")],
                         ["event-1", "event-2", "event-3"])

    def test_no_inventory_is_unknown_even_with_contiguous_sequences(self):
        self.store.enqueue(self.writer, event())
        self.store.drain(self.operator)
        self.assertEqual(self.store.status(self.reader, "source-1")["status"], "UNKNOWN")
        self.store.register_inventory(self.writer, inventory(()))
        empty = self.store.status(self.reader, "source-1")
        self.assertEqual((empty["status"], empty["expected_count"]), ("COMPLETE", 0))
        self.assertEqual(empty["scope"], "finite_authenticated_inventory")

    def test_inventory_is_immutable_and_selection_is_explicit(self):
        first = inventory(("event-2", "event-1"))
        self.store.register_inventory(self.writer, first)
        reordered = inventory(("event-1", "event-2"))
        self.assertEqual(self.store.register_inventory(self.writer, reordered)["status"], "duplicate")
        with self.assertRaises(ConflictError):
            self.store.register_inventory(self.writer, inventory(("event-1",)))
        self.store.register_inventory(self.writer, inventory((), "inventory-2"))
        self.assertEqual(self.store.status(self.reader, "source-1")["inventory_id"], "inventory-2")
        old = self.store.status(self.reader, "source-1", "inventory-1")
        self.assertEqual((old["status"], old["expected_count"]), ("INCOMPLETE", 2))
        self.assertEqual(self.store.read_quarantine(self.operator)[0]["kind"], "inventory")

    def test_access_is_tenant_scoped_roles_fail_closed_and_denials_are_audited(self):
        with self.assertRaises(HardeningError):
            self.store.enqueue(self.reader, event())
        with self.assertRaises(HardeningError):
            self.store.enqueue(principal("writer", "tenant-b"), event())
        with self.assertRaises(HardeningError):
            self.store.register_inventory(principal("writer", "tenant-b"), inventory())
        self.store.enqueue(self.writer, event())
        self.store.enqueue(principal("writer", "tenant-b"), event(tenant="tenant-b"))
        self.store.drain(self.operator)
        self.assertEqual(self.store.read_events(principal("reader", "tenant-b"), "source-1"), [])
        self.assertEqual(self.store.status(principal("reader", "tenant-b"), "source-1")["pending_count"], 1)
        with self.assertRaises(HardeningError):
            self.store.read_events(self.writer, "source-1")
        with self.assertRaises(HardeningError):
            self.store.drain(self.reader)
        with self.assertRaises(HardeningError):
            self.store.prune(self.reader, "2099-01-01T00:00:00Z", "test")
        with self.assertRaises(HardeningError):
            self.store.read_events(replace(self.reader, roles=frozenset()), "source-1")
        audit = self.store.audit_log(self.auditor)
        self.assertTrue(any(r["action"] == "enqueue" and r["outcome"] == "denied" for r in audit))
        self.assertTrue(all(r["tenant_id"] == "tenant-a" for r in audit))
        self.assertNotIn("private-payload", json.dumps(audit))

    def test_encryption_protects_bodies_and_wrong_key_cannot_open_store(self):
        self.store.enqueue(self.writer, event())
        with self.assertRaises(ConflictError):
            self.store.enqueue(self.writer, event(payload={"value": "quarantined-private-payload"}))
        self.store.register_inventory(self.writer, inventory())
        for path in Path(self.tmp.name).iterdir():
            if path.is_file():
                raw = path.read_bytes()
                self.assertNotIn(b"private-payload-never-in-database-plaintext", raw)
                self.assertNotIn(b"quarantined-private-payload", raw)
        with self.assertRaises(IntegrityError):
            EvidenceStore(self.path, b"b" * 32, max_pending=3)
        with self.assertRaises(HardeningError):
            EvidenceStore(self.path, b"short")
        self.assertEqual(self.store._db.execute("PRAGMA synchronous").fetchone()[0], 2)
        self.assertEqual(self.store._db.execute("PRAGMA foreign_keys").fetchone()[0], 1)
        self.assertEqual(self.store._db.execute("PRAGMA journal_mode").fetchone()[0], "wal")

    def test_tampered_ciphertext_fails_drain_read_status_and_checkpoint(self):
        self.store.enqueue(self.writer, event())
        raw = self.store._db.execute("SELECT ciphertext FROM events").fetchone()[0]
        tampered = bytes([raw[0] ^ 1]) + raw[1:]
        self.store._db.execute("UPDATE events SET ciphertext=?", (tampered,))
        with self.assertRaises(IntegrityError):
            self.store.drain(self.operator)
        self.assertEqual(self.store._db.execute("SELECT state FROM events").fetchone()[0], "pending")
        with self.assertRaises(IntegrityError):
            self.store.status(self.reader, "source-1")
        with self.assertRaises(IntegrityError):
            self.store.checkpoint_material(self.operator)
        with self.assertRaises(IntegrityError):
            self.store.enqueue(self.writer, event())
        self.store._db.execute("UPDATE events SET state='stored'")
        with self.assertRaises(IntegrityError):
            self.store.read_events(self.reader, "source-1")
        self.assertTrue(any(r["outcome"] == "integrity_error" for r in self.store.audit_log(self.auditor)))

    def test_ciphertext_row_swap_and_visible_metadata_tampering_fail(self):
        self.store.enqueue(self.writer, event())
        self.store.enqueue(self.writer, event("event-2", 2))
        self.store.drain(self.operator)
        row = self.store._db.execute("SELECT nonce,ciphertext FROM events WHERE event_id='event-1'").fetchone()
        self.store._db.execute("UPDATE events SET nonce=?,ciphertext=? WHERE event_id='event-2'", tuple(row))
        with self.assertRaises(IntegrityError):
            self.store.read_events(self.reader, "source-1")
        self.store._db.execute("UPDATE events SET source_ts='2020-01-01T00:00:00Z' WHERE event_id='event-1'")
        with self.assertRaises(IntegrityError):
            self.store.status(self.reader, "source-1")

    def test_same_identity_and_key_cannot_transplant_proof_from_another_store(self):
        first = event(source_proof={"signed_statement": "first-accepted-proof"})
        second = replace(first, source_proof={"signed_statement": "other-store-proof"})
        self.store.enqueue(self.writer, first)
        self.store.drain(self.operator)
        self.store.register_inventory(self.writer, inventory())
        with EvidenceStore(Path(self.tmp.name) / "independent.sqlite", KEY) as other:
            self.assertNotEqual(self.store.store_id, other.store_id)
            other.enqueue(self.writer, second)
            other.drain(self.operator)
            other.register_inventory(self.writer, replace(inventory(), source_proof={"signed_statement": "other-inventory-proof"}))
            original = self.store._db.execute("SELECT nonce,ciphertext,fingerprint FROM events").fetchone()
            transplanted = other._db.execute("SELECT nonce,ciphertext,fingerprint FROM events").fetchone()
            # The source-content fingerprint intentionally ignores delivery
            # proofs. Store binding must therefore be separate from deduplication.
            self.assertEqual(original["fingerprint"], transplanted["fingerprint"])
            self.store._db.execute("UPDATE events SET nonce=?,ciphertext=?", tuple(transplanted)[:2])
            with self.assertRaises(IntegrityError):
                self.store.read_events(self.reader, "source-1")
            with self.assertRaises(IntegrityError):
                self.store.enqueue(self.writer, first)
            with self.assertRaises(IntegrityError):
                self.store.checkpoint_material(self.operator)
            self.store._db.execute("UPDATE events SET nonce=?,ciphertext=?", tuple(original)[:2])
            self.assertEqual(self.store.read_events(self.reader, "source-1")[0]["source_proof"], first.source_proof)
            transplanted_inventory = other._db.execute("SELECT nonce,ciphertext FROM inventories").fetchone()
            self.store._db.execute("UPDATE inventories SET nonce=?,ciphertext=?", tuple(transplanted_inventory))
            with self.assertRaises(IntegrityError):
                self.store.status(self.reader, "source-1")
            with self.assertRaises(IntegrityError):
                self.store.register_inventory(self.writer, inventory())

    def test_retention_holds_receipts_and_pruned_replay_cannot_resurrect_or_complete(self):
        self.store.register_inventory(self.writer, inventory(("event-1", "event-2")))
        self.store.enqueue(self.writer, event())
        self.store.enqueue(self.writer, event("event-2", 2))
        self.store.drain(self.operator)
        self.assertEqual(self.store.status(self.reader, "source-1")["status"], "COMPLETE")
        self.store.set_hold(self.operator, "source-1", "event-2", True, "case-123")
        receipt = self.store.prune(self.operator, "2099-01-01T00:00:00Z", "retention-expired")
        self.assertEqual(receipt["deleted_events"], [{"source_id": "source-1", "event_id": "event-1"}])
        self.assertEqual(receipt["held_count"], 1)
        self.assertIn("backups", receipt["scope"])
        state = self.store.status(self.reader, "source-1")
        self.assertEqual((state["status"], state["missing_event_ids"], state["pruned_count"]),
                         ("INCOMPLETE", ["event-1"], 1))
        self.assertEqual(self.store.enqueue(self.writer, event())["status"], "pruned")
        self.assertEqual(self.store.status(self.reader, "source-1")["status"], "INCOMPLETE")
        self.assertEqual(self.store.read_pruned(self.auditor)[0]["event_id"], "event-1")
        self.assertEqual(self.store.retention_receipts(self.operator)[0]["id"], receipt["receipt_id"])
        with self.assertRaises(HardeningError):
            self.store.set_hold(self.operator, "source-1", "event-1", True, "too-late")
        self.store.set_hold(self.operator, "source-1", "event-2", False, "case-closed")
        self.assertEqual(len(self.store.prune(self.operator, "2099-01-01T00:00:00Z", "expired")["deleted_events"]), 1)

    def test_checkpoint_stable_tenant_isolated_and_state_changes_are_committed(self):
        start = self.store.checkpoint_material(self.operator)
        self.assertEqual(start, self.store.checkpoint_material(self.operator))
        self.store.enqueue(principal("writer", "tenant-b"), event(tenant="tenant-b"))
        self.assertEqual(start, self.store.checkpoint_material(self.operator))
        self.store.enqueue(self.writer, event())
        pending = self.store.checkpoint_material(self.operator)
        self.assertNotEqual(start, pending)
        self.assertEqual(pending, self.store.checkpoint_material(self.operator))
        self.assertNotIn("private-payload", json.dumps(pending))
        self.store.drain(self.operator)
        stored = self.store.checkpoint_material(self.operator)
        self.assertNotEqual(pending, stored)
        self.store.prune(self.operator, "2099-01-01T00:00:00Z", "expired")
        self.assertNotEqual(stored, self.store.checkpoint_material(self.operator))
        with self.assertRaises(HardeningError):
            self.store.checkpoint_material(self.auditor)

    def test_concurrent_connections_cannot_race_past_queue_capacity(self):
        def submit(number):
            with EvidenceStore(self.path, KEY, max_pending=3) as other:
                try:
                    return other.enqueue(self.writer, event(f"event-{number}", number))["status"]
                except QueueFullError:
                    return "full"
        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(submit, range(1, 5)))
        self.assertEqual(results.count("queued"), 3)
        self.assertEqual(results.count("full"), 1)
        self.assertEqual(self.store.status(self.reader, "source-1")["pending_count"], 3)

    def test_store_identity_and_inventory_tampering_are_detected(self):
        self.store.register_inventory(self.writer, inventory())
        self.store._db.execute("UPDATE inventories SET ciphertext=zeroblob(length(ciphertext))")
        with self.assertRaises(IntegrityError):
            self.store.status(self.reader, "source-1")
        with self.assertRaises(IntegrityError):
            self.store.register_inventory(self.writer, inventory())
        with self.assertRaises(IntegrityError):
            self.store.checkpoint_material(self.operator)
        self.store._db.execute("UPDATE store_meta SET value='changed' WHERE key='store_id'")
        with self.assertRaisesRegex(IntegrityError, "identity"):
            self.store.checkpoint_material(self.operator)

    def test_abrupt_process_exit_before_and_after_commit(self):
        self.store.close()
        # A real child process is terminated without close(), exception unwinding,
        # or an acknowledged reply. SQL trace fires immediately BEFORE COMMIT.
        script = """
import os, sys
from eacp_hardening.common import Principal, VerifiedEvent
from eacp_hardening.store import EvidenceStore
s = EvidenceStore(sys.argv[1], b'a'*32, max_pending=3)
if sys.argv[2] == 'before':
    s._db.set_trace_callback(lambda statement: os._exit(37) if statement == 'COMMIT' else None)
e = VerifiedEvent('tenant-a','source-1','crash-event',1,'2026-09-04T12:00:00Z',
                  {'value':'retained'},'collector-1','key-1','2026-09-04T12:00:00Z')
s.enqueue(Principal('worker','tenant-a',frozenset({'writer'})), e)
os._exit(38)
"""
        before = subprocess.run([sys.executable, "-c", script, str(self.path), "before"],
                                capture_output=True, text=True, timeout=15)
        self.assertEqual(before.returncode, 37, before.stderr)
        self.store = EvidenceStore(self.path, KEY, max_pending=3)
        self.assertEqual(self.store.status(self.reader, "source-1")["pending_count"], 0)
        self.store.close()
        after = subprocess.run([sys.executable, "-c", script, str(self.path), "after"],
                               capture_output=True, text=True, timeout=15)
        self.assertEqual(after.returncode, 38, after.stderr)
        self.store = EvidenceStore(self.path, KEY, max_pending=3)
        self.assertEqual(self.store.status(self.reader, "source-1")["pending_count"], 1)
        self.assertEqual(self.store.drain(self.operator), 1)
        self.assertEqual(self.store.read_events(self.reader, "source-1")[0]["event_id"], "crash-event")


if __name__ == "__main__":
    unittest.main()
