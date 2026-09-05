"""Bounded, tenant-scoped SQLite reference ingestion, not a production service.

Verified inputs and Principals must originate at the trusted authentication
boundary. AES-GCM protects event/inventory/quarantine bodies, not lookup metadata.
SQLite durability requires a local filesystem and storage honoring fsync.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import uuid
from contextlib import contextmanager
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .common import (HardeningError, Principal, VerifiedEvent, VerifiedInventory,
                     canonical_bytes, identifier, require_role, utc_time)


class QueueFullError(HardeningError):
    """No acknowledgement: retry after capacity becomes available."""


class ConflictError(HardeningError):
    """The conflicting submission is quarantined; accepted history is unchanged."""


class IntegrityError(HardeningError):
    """A protected body cannot be authenticated or validated."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _fingerprint(body: dict[str, Any]) -> str:
    # A collector may re-sign the same source statement after an outage/key
    # rotation. Identity covers source content, not its renewed delivery proof;
    # the first accepted body and proof remain encrypted and unchanged.
    return hashlib.sha256(canonical_bytes({k: v for k, v in body.items()
                                          if k not in {"received_at", "collector_id", "key_id", "source_proof"}})).hexdigest()


_SCHEMA = """
CREATE TABLE IF NOT EXISTS store_meta(key TEXT PRIMARY KEY, value BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS events(
 tenant_id TEXT NOT NULL, source_id TEXT NOT NULL, event_id TEXT NOT NULL,
 sequence INTEGER NOT NULL CHECK(sequence >= 0), source_ts TEXT NOT NULL,
 fingerprint TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN ('pending','stored','pruned')),
 nonce BLOB, ciphertext BLOB, ingested_at TEXT NOT NULL,
 held INTEGER NOT NULL DEFAULT 0 CHECK(held IN (0,1)), pruned_at TEXT,
 PRIMARY KEY(tenant_id,source_id,event_id), UNIQUE(tenant_id,source_id,sequence),
 CHECK((state='pruned' AND nonce IS NULL AND ciphertext IS NULL) OR
       (state!='pruned' AND nonce IS NOT NULL AND ciphertext IS NOT NULL))
);
CREATE INDEX IF NOT EXISTS events_queue ON events(tenant_id,state,ingested_at);
CREATE TABLE IF NOT EXISTS inventories(
 id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id TEXT NOT NULL, source_id TEXT NOT NULL,
 inventory_id TEXT NOT NULL, fingerprint TEXT NOT NULL, nonce BLOB NOT NULL,
 ciphertext BLOB NOT NULL, registered_at TEXT NOT NULL,
 UNIQUE(tenant_id,source_id,inventory_id)
);
CREATE TABLE IF NOT EXISTS quarantine(
 id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, source_id TEXT NOT NULL,
 item_id TEXT NOT NULL, kind TEXT NOT NULL, reason TEXT NOT NULL,
 fingerprint TEXT NOT NULL, nonce BLOB NOT NULL, ciphertext BLOB NOT NULL,
 received_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS access_audit(
 id INTEGER PRIMARY KEY AUTOINCREMENT, time TEXT NOT NULL, tenant_id TEXT NOT NULL,
 subject TEXT NOT NULL, action TEXT NOT NULL, outcome TEXT NOT NULL, details TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS retention_receipts(
 id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, time TEXT NOT NULL,
 before_time TEXT NOT NULL, reason TEXT NOT NULL, event_ids TEXT NOT NULL,
 held_count INTEGER NOT NULL
);
"""


class EvidenceStore:
    """One synchronous connection; use separate instances for concurrent callers.

    Pending capacity is global to this database, and must be set consistently by
    operators. Queue commits precede acknowledgements. A crash can lose a reply
    after the commit; replaying the same verified event then returns duplicate.
    """

    def __init__(self, path: str | Path, encryption_key: bytes, max_pending: int = 1000):
        if not isinstance(encryption_key, bytes) or len(encryption_key) != 32:
            raise HardeningError("a 32-byte externally supplied encryption key is required")
        if type(max_pending) is not int or max_pending < 1:
            raise HardeningError("max_pending must be a positive integer")
        self.path = Path(path)
        self.max_pending = max_pending
        self._cipher = AESGCM(encryption_key)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.path, os.O_CREAT | os.O_RDWR, 0o600)
        os.close(fd)
        self._db = sqlite3.connect(str(self.path), isolation_level=None, timeout=5)
        self._db.row_factory = sqlite3.Row
        try:
            self._db.execute("PRAGMA foreign_keys=ON")
            self._db.execute("PRAGMA busy_timeout=5000")
            mode = self._db.execute("PRAGMA journal_mode=WAL").fetchone()[0]
            if mode.lower() != "wal":
                raise HardeningError("WAL mode is required")
            self._db.execute("PRAGMA synchronous=FULL")
            self._db.executescript(_SCHEMA)
            with self._transaction():
                row = self._db.execute("SELECT value FROM store_meta WHERE key='key_check'").fetchone()
                store_id_row = self._db.execute("SELECT value FROM store_meta WHERE key='store_id'").fetchone()
                if store_id_row is None and row is not None:
                    raise IntegrityError("store identity is missing")
                self.store_id = store_id_row[0] if store_id_row is not None else uuid.uuid4().hex
                aad = canonical_bytes({"format": "EACP/reference-store/v1/key-check", "store_id": self.store_id})
                if row is None:
                    if any(self._db.execute(f"SELECT 1 FROM {table} LIMIT 1").fetchone()
                           for table in ("events", "inventories", "quarantine", "access_audit")):
                        raise IntegrityError("store key check is missing")
                    nonce = os.urandom(12)
                    value = nonce + self._cipher.encrypt(nonce, b"EACP reference store", aad)
                    if store_id_row is None:
                        self._db.execute("INSERT INTO store_meta VALUES('store_id',?)", (self.store_id,))
                    self._db.execute("INSERT INTO store_meta VALUES('key_check',?)", (value,))
                else:
                    value = bytes(row[0])
                    try:
                        plain = self._cipher.decrypt(value[:12], value[12:], aad)
                    except (InvalidTag, ValueError) as exc:
                        raise IntegrityError("store encryption key check failed") from exc
                    if plain != b"EACP reference store":
                        raise IntegrityError("store encryption key check failed")
        except BaseException:
            self._db.close()
            raise

    def close(self) -> None:
        self._db.close()

    def __enter__(self) -> "EvidenceStore":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()

    @contextmanager
    def _transaction(self) -> Iterator[None]:
        self._db.execute("BEGIN IMMEDIATE")
        try:
            yield
            self._db.execute("COMMIT")
        except BaseException:
            if self._db.in_transaction:
                self._db.execute("ROLLBACK")
            raise

    def _audit(self, principal: Principal, action: str, outcome: str,
               details: dict[str, Any] | None = None) -> None:
        self._db.execute("INSERT INTO access_audit(time,tenant_id,subject,action,outcome,details) "
                         "VALUES(?,?,?,?,?,?)", (_now(), principal.tenant_id, principal.subject,
                          action, outcome, canonical_bytes(details or {}).decode()))

    def _authorize(self, principal: Principal, tenant_id: str, action: str, *roles: str) -> None:
        try:
            require_role(principal, tenant_id, *roles)
        except HardeningError:
            # Invalid caller identity is never interpolated into a security log.
            safe = principal if isinstance(principal, Principal) else Principal("unauthenticated", "", frozenset())
            with self._transaction():
                self._audit(safe, action, "denied")
            raise

    def _tenant(self, principal: Principal) -> str:
        if not isinstance(principal, Principal):
            with self._transaction():
                self._audit(Principal("unauthenticated", "", frozenset()), "authenticate", "denied")
            raise HardeningError("authenticated principal required")
        return principal.tenant_id

    def _verify_identity(self) -> None:
        rows = dict(self._db.execute("SELECT key,value FROM store_meta"))
        if rows.get("store_id") != self.store_id or "key_check" not in rows:
            raise IntegrityError("store identity is missing or changed")
        value = rows["key_check"]
        aad = canonical_bytes({"format": "EACP/reference-store/v1/key-check", "store_id": self.store_id})
        try:
            plain = self._cipher.decrypt(value[:12], value[12:], aad)
        except (InvalidTag, ValueError, TypeError) as exc:
            raise IntegrityError("store encryption key check failed") from exc
        if plain != b"EACP reference store":
            raise IntegrityError("store encryption key check failed")

    def _encrypt(self, body: dict[str, Any], aad: dict[str, Any]) -> tuple[bytes, bytes]:
        nonce = os.urandom(12)
        return nonce, self._cipher.encrypt(nonce, canonical_bytes(body), canonical_bytes(aad))

    def _decrypt(self, nonce: bytes, ciphertext: bytes, aad: dict[str, Any]) -> dict[str, Any]:
        try:
            body = json.loads(self._cipher.decrypt(nonce, ciphertext, canonical_bytes(aad)))
            if not isinstance(body, dict):
                raise ValueError("invalid protected object")
            if _fingerprint(body) != aad["fingerprint"]:
                raise ValueError("fingerprint mismatch")
            return body
        except (InvalidTag, ValueError, TypeError, KeyError) as exc:
            raise IntegrityError("protected evidence integrity check failed") from exc

    def _aad(self, kind: str, tenant_id: str, source_id: str, item_id: str,
             fingerprint: str) -> dict[str, Any]:
        # Separate databases may legitimately use the same externally managed
        # key and source identities. Bind ciphertext to the particular store so
        # a valid body/proof from one database cannot be transplanted to another.
        return dict(format="eacp-store/1", store_id=self.store_id, kind=kind, tenant_id=tenant_id,
                    source_id=source_id, item_id=item_id, fingerprint=fingerprint)

    def _event_body(self, row: sqlite3.Row) -> dict[str, Any]:
        body = self._decrypt(row["nonce"], row["ciphertext"], self._aad(
            "event", row["tenant_id"], row["source_id"], row["event_id"], row["fingerprint"]))
        if any(body[key] != row[key] for key in ("tenant_id", "source_id", "event_id", "sequence", "source_ts")):
            raise IntegrityError("protected event metadata does not match")
        return body

    def _quarantine(self, principal: Principal, body: dict[str, Any], kind: str,
                    reason: str) -> str:
        quarantine_id, digest = uuid.uuid4().hex, _fingerprint(body)
        item_id = body["event_id" if kind == "event" else "inventory_id"]
        nonce, ciphertext = self._encrypt(body, self._aad(
            "quarantine:" + kind, body["tenant_id"], body["source_id"], quarantine_id, digest))
        self._db.execute("INSERT INTO quarantine VALUES(?,?,?,?,?,?,?,?,?,?)", (
            quarantine_id, body["tenant_id"], body["source_id"], item_id, kind,
            reason, digest, nonce, ciphertext, _now()))
        self._audit(principal, "enqueue" if kind == "event" else "register_inventory", "quarantined",
                    {"quarantine_id": quarantine_id, "reason": reason})
        return quarantine_id

    @staticmethod
    def _validate_event(event: VerifiedEvent) -> dict[str, Any]:
        if not isinstance(event, VerifiedEvent):
            raise HardeningError("verified event required")
        body = asdict(event)
        for field in ("tenant_id", "source_id", "event_id", "collector_id", "key_id"):
            identifier(body[field], field)
        if type(event.sequence) is not int or not 0 <= event.sequence <= 2**63 - 1:
            raise HardeningError("invalid event sequence")
        if not isinstance(event.payload, dict):
            raise HardeningError("event payload must be an object")
        utc_time(event.source_ts)
        utc_time(event.received_at)
        canonical_bytes(body)
        return body

    def enqueue(self, principal: Principal, event: VerifiedEvent) -> dict[str, Any]:
        if not isinstance(event, VerifiedEvent):
            raise HardeningError("verified event required")
        self._authorize(principal, event.tenant_id, "enqueue", "writer")
        body, error = self._validate_event(event), None
        digest = _fingerprint(body)
        with self._transaction():
            old = self._db.execute("SELECT * FROM events WHERE tenant_id=? AND source_id=? AND event_id=?",
                                   (event.tenant_id, event.source_id, event.event_id)).fetchone()
            sequence_owner = self._db.execute("SELECT event_id FROM events WHERE tenant_id=? AND source_id=? AND sequence=?",
                                             (event.tenant_id, event.source_id, event.sequence)).fetchone()
            if old is not None and old["fingerprint"] == digest:
                try:
                    if old["state"] != "pruned":
                        self._event_body(old)
                except IntegrityError as exc:
                    self._audit(principal, "enqueue", "integrity_error")
                    error = exc
                if error is None:
                    result = {"status": "pruned" if old["state"] == "pruned" else "duplicate", "event_id": event.event_id}
                    self._audit(principal, "enqueue", result["status"], {"event_id": event.event_id})
            elif old is not None or sequence_owner is not None:
                reason = "event_id_conflict" if old is not None else "sequence_conflict"
                receipt = self._quarantine(principal, body, "event", reason)
                error = ConflictError(f"{reason}; quarantine receipt {receipt}")
            elif self._db.execute("SELECT count(*) FROM events WHERE state='pending'").fetchone()[0] >= self.max_pending:
                self._audit(principal, "enqueue", "queue_full")
                error = QueueFullError("pending queue is full; event was not acknowledged")
            else:
                nonce, ciphertext = self._encrypt(body, self._aad("event", event.tenant_id,
                                                          event.source_id, event.event_id, digest))
                self._db.execute("INSERT INTO events(tenant_id,source_id,event_id,sequence,source_ts,fingerprint,state,"
                                 "nonce,ciphertext,ingested_at) VALUES(?,?,?,?,?,?,'pending',?,?,?)", (
                                     event.tenant_id, event.source_id, event.event_id, event.sequence,
                                     event.source_ts, digest, nonce, ciphertext, _now()))
                self._audit(principal, "enqueue", "queued", {"event_id": event.event_id})
                result = {"status": "queued", "event_id": event.event_id}
        if error:
            raise error
        return result

    def drain(self, principal: Principal, limit: int | None = None) -> int:
        tenant = self._tenant(principal)
        self._authorize(principal, tenant, "drain", "operator")
        if limit is not None and (type(limit) is not int or limit < 1):
            raise HardeningError("drain limit must be positive")
        error = None
        with self._transaction():
            rows = self._db.execute("SELECT * FROM events WHERE tenant_id=? AND state='pending' "
                                    "ORDER BY ingested_at,event_id LIMIT ?", (tenant, limit or self.max_pending)).fetchall()
            try:
                for row in rows:
                    self._event_body(row)
            except IntegrityError as exc:
                self._audit(principal, "drain", "integrity_error")
                error = exc
            if error is None:
                for row in rows:
                    self._db.execute("UPDATE events SET state='stored' WHERE tenant_id=? AND source_id=? AND event_id=?",
                                     (tenant, row["source_id"], row["event_id"]))
                self._audit(principal, "drain", "success", {"count": len(rows)})
        if error:
            raise error
        return len(rows)

    def register_inventory(self, principal: Principal, inventory: VerifiedInventory) -> dict[str, Any]:
        if not isinstance(inventory, VerifiedInventory):
            raise HardeningError("verified inventory required")
        self._authorize(principal, inventory.tenant_id, "register_inventory", "writer")
        body = asdict(inventory)
        for key in ("tenant_id", "source_id", "inventory_id", "collector_id", "key_id"):
            identifier(body[key], key)
        for event_id in inventory.expected_event_ids:
            identifier(event_id, "expected event id")
        if len(set(inventory.expected_event_ids)) != len(inventory.expected_event_ids):
            raise HardeningError("inventory event ids must be unique")
        utc_time(inventory.received_at)
        body["expected_event_ids"] = sorted(inventory.expected_event_ids)
        digest, error = _fingerprint(body), None
        with self._transaction():
            row = self._db.execute("SELECT fingerprint FROM inventories WHERE tenant_id=? AND source_id=? AND inventory_id=?",
                                   (inventory.tenant_id, inventory.source_id, inventory.inventory_id)).fetchone()
            if row and row[0] != digest:
                receipt = self._quarantine(principal, body, "inventory", "inventory_id_conflict")
                error = ConflictError(f"inventory_id_conflict; quarantine receipt {receipt}")
            elif row:
                protected = self._db.execute("SELECT * FROM inventories WHERE tenant_id=? AND source_id=? AND inventory_id=?",
                                            (inventory.tenant_id, inventory.source_id, inventory.inventory_id)).fetchone()
                try:
                    self._decrypt(protected["nonce"], protected["ciphertext"], self._aad(
                        "inventory", inventory.tenant_id, inventory.source_id, inventory.inventory_id, digest))
                except IntegrityError as exc:
                    self._audit(principal, "register_inventory", "integrity_error")
                    error = exc
                if error is None:
                    self._audit(principal, "register_inventory", "duplicate", {"inventory_id": inventory.inventory_id})
                    result = {"status": "duplicate", "inventory_id": inventory.inventory_id}
            else:
                nonce, ciphertext = self._encrypt(body, self._aad("inventory", inventory.tenant_id,
                                                                inventory.source_id, inventory.inventory_id, digest))
                self._db.execute("INSERT INTO inventories(tenant_id,source_id,inventory_id,fingerprint,nonce,ciphertext,registered_at) "
                                 "VALUES(?,?,?,?,?,?,?)", (inventory.tenant_id, inventory.source_id, inventory.inventory_id,
                                                          digest, nonce, ciphertext, _now()))
                self._audit(principal, "register_inventory", "registered", {"inventory_id": inventory.inventory_id})
                result = {"status": "registered", "inventory_id": inventory.inventory_id}
        if error:
            raise error
        return result

    def status(self, principal: Principal, source_id: str, inventory_id: str | None = None) -> dict[str, Any]:
        tenant = self._tenant(principal)
        self._authorize(principal, tenant, "status", "reader", "operator", "auditor")
        identifier(source_id, "source id")
        error = None
        with self._transaction():
            query = "SELECT * FROM inventories WHERE tenant_id=? AND source_id=?"
            params: tuple[Any, ...] = (tenant, source_id)
            if inventory_id is not None:
                identifier(inventory_id, "inventory id")
                query += " AND inventory_id=?"
                params += (inventory_id,)
            inventory = self._db.execute(query + " ORDER BY id DESC LIMIT 1", params).fetchone()
            rows = self._db.execute("SELECT * FROM events WHERE tenant_id=? AND source_id=? ORDER BY sequence",
                                    (tenant, source_id)).fetchall()
            try:
                # COMPLETE must fail closed on corrupt protected bodies, not just
                # count unauthenticated lookup rows that look present.
                for row in rows:
                    if row["state"] != "pruned":
                        self._event_body(row)
                expected = None
                if inventory:
                    body = self._decrypt(inventory["nonce"], inventory["ciphertext"], self._aad(
                        "inventory", tenant, source_id, inventory["inventory_id"], inventory["fingerprint"]))
                    expected = set(body["expected_event_ids"])
            except IntegrityError as exc:
                self._audit(principal, "status", "integrity_error")
                error = exc
            if error is None:
                stored = {row["event_id"] for row in rows if row["state"] == "stored"}
                pending = {row["event_id"] for row in rows if row["state"] == "pending"}
                pruned = {row["event_id"] for row in rows if row["state"] == "pruned"}
                sequences = [row["sequence"] for row in rows if row["state"] != "pruned"]
                # Ranges avoid allocating billions of missing sequence numbers.
                gaps = [[a + 1, b - 1] for a, b in zip(sequences, sequences[1:]) if b > a + 1]
                missing = None if expected is None else sorted(expected - stored)
                result = {"source_id": source_id, "inventory_id": inventory["inventory_id"] if inventory else None,
                          "scope": "finite_authenticated_inventory" if inventory else "unknown",
                          "status": "UNKNOWN" if expected is None else ("INCOMPLETE" if missing else "COMPLETE"),
                          "expected_count": None if expected is None else len(expected),
                          "stored_count": len(stored), "pending_count": len(pending),
                          "pruned_count": len(pruned), "missing_event_ids": missing,
                          "pending_event_ids": sorted(pending), "pruned_event_ids": sorted(pruned),
                          "sequence_gap_ranges": gaps,
                          "last_received_at": max((r["ingested_at"] for r in rows), default=None)}
                result["quarantine_count"] = self._db.execute(
                    "SELECT count(*) FROM quarantine WHERE tenant_id=? AND source_id=?", (tenant, source_id)).fetchone()[0]
                self._audit(principal, "status", "success", {"source_id": source_id, "status": result["status"]})
        if error:
            raise error
        return result

    def read_events(self, principal: Principal, source_id: str) -> list[dict[str, Any]]:
        tenant = self._tenant(principal)
        self._authorize(principal, tenant, "read_events", "reader")
        identifier(source_id, "source id")
        error = None
        with self._transaction():
            rows = self._db.execute("SELECT * FROM events WHERE tenant_id=? AND source_id=? AND state='stored' ORDER BY sequence",
                                    (tenant, source_id)).fetchall()
            try:
                result = [self._event_body(row) for row in rows]
            except IntegrityError as exc:
                self._audit(principal, "read_events", "integrity_error")
                error = exc
            if error is None:
                self._audit(principal, "read_events", "success", {"source_id": source_id, "count": len(rows)})
        if error:
            raise error
        return result

    def read_quarantine(self, principal: Principal) -> list[dict[str, Any]]:
        tenant = self._tenant(principal)
        self._authorize(principal, tenant, "read_quarantine", "operator", "auditor")
        error = None
        with self._transaction():
            rows = self._db.execute("SELECT * FROM quarantine WHERE tenant_id=? ORDER BY received_at,id", (tenant,)).fetchall()
            try:
                result = [{"quarantine_id": row["id"], "reason": row["reason"], "kind": row["kind"],
                           "body": self._decrypt(row["nonce"], row["ciphertext"], self._aad(
                               "quarantine:" + row["kind"], tenant, row["source_id"], row["id"], row["fingerprint"]))}
                          for row in rows]
            except IntegrityError as exc:
                self._audit(principal, "read_quarantine", "integrity_error")
                error = exc
            if error is None:
                self._audit(principal, "read_quarantine", "success", {"count": len(rows)})
        if error:
            raise error
        return result

    def read_pruned(self, principal: Principal) -> list[dict[str, Any]]:
        tenant = self._tenant(principal)
        self._authorize(principal, tenant, "read_pruned", "reader", "operator", "auditor")
        with self._transaction():
            rows = self._db.execute("SELECT source_id,event_id,sequence,fingerprint,pruned_at FROM events "
                                    "WHERE tenant_id=? AND state='pruned' ORDER BY pruned_at,event_id", (tenant,)).fetchall()
            self._audit(principal, "read_pruned", "success", {"count": len(rows)})
        return [dict(row) for row in rows]

    def audit_log(self, principal: Principal) -> list[dict[str, Any]]:
        tenant = self._tenant(principal)
        self._authorize(principal, tenant, "audit_log", "auditor")
        with self._transaction():
            self._audit(principal, "audit_log", "success")
            rows = self._db.execute("SELECT * FROM access_audit WHERE tenant_id=? ORDER BY id", (tenant,)).fetchall()
        return [{**dict(row), "details": json.loads(row["details"])} for row in rows]

    def set_hold(self, principal: Principal, source_id: str, event_id: str,
                 held: bool, reason: str) -> None:
        tenant = self._tenant(principal)
        self._authorize(principal, tenant, "set_hold", "operator")
        identifier(source_id, "source id")
        identifier(event_id, "event id")
        identifier(reason, "hold reason")
        if type(held) is not bool:
            raise HardeningError("held must be boolean")
        error = None
        with self._transaction():
            row = self._db.execute("SELECT state FROM events WHERE tenant_id=? AND source_id=? AND event_id=?",
                                   (tenant, source_id, event_id)).fetchone()
            if row is None or row["state"] == "pruned":
                self._audit(principal, "set_hold", "unavailable")
                error = HardeningError("record does not exist or has already been pruned")
            else:
                self._db.execute("UPDATE events SET held=? WHERE tenant_id=? AND source_id=? AND event_id=?",
                                 (int(held), tenant, source_id, event_id))
                self._audit(principal, "set_hold", "success", {"source_id": source_id, "event_id": event_id,
                                                                "held": held, "reason": reason})
        if error:
            raise error

    def prune(self, principal: Principal, before: str, reason: str) -> dict[str, Any]:
        tenant = self._tenant(principal)
        self._authorize(principal, tenant, "prune", "operator")
        cutoff = utc_time(before)
        identifier(reason, "retention reason")
        with self._transaction():
            candidates = self._db.execute("SELECT source_id,event_id,ingested_at,held FROM events "
                                          "WHERE tenant_id=? AND state!='pruned'", (tenant,)).fetchall()
            eligible = [r for r in candidates if utc_time(r["ingested_at"]) < cutoff]
            deleted = [{"source_id": r["source_id"], "event_id": r["event_id"]} for r in eligible if not r["held"]]
            held_count = sum(bool(r["held"]) for r in eligible)
            receipt_id, at = uuid.uuid4().hex, _now()
            for row in deleted:
                self._db.execute("UPDATE events SET state='pruned',nonce=NULL,ciphertext=NULL,pruned_at=? "
                                 "WHERE tenant_id=? AND source_id=? AND event_id=?",
                                 (at, tenant, row["source_id"], row["event_id"]))
            self._db.execute("INSERT INTO retention_receipts VALUES(?,?,?,?,?,?,?)", (
                receipt_id, tenant, at, before, reason, canonical_bytes(deleted).decode(), held_count))
            self._audit(principal, "prune", "success", {"receipt_id": receipt_id, "deleted_count": len(deleted),
                                                       "held_count": held_count})
        return {"receipt_id": receipt_id, "tenant_id": tenant, "time": at, "before": before,
                "reason": reason, "deleted_events": deleted, "held_count": held_count,
                "scope": "live_store_payloads_only; tombstones and receipts retained; backups and WAL may retain ciphertext"}

    def retention_receipts(self, principal: Principal) -> list[dict[str, Any]]:
        tenant = self._tenant(principal)
        self._authorize(principal, tenant, "retention_receipts", "operator", "auditor")
        with self._transaction():
            rows = self._db.execute("SELECT * FROM retention_receipts WHERE tenant_id=? ORDER BY time,id", (tenant,)).fetchall()
            self._audit(principal, "retention_receipts", "success", {"count": len(rows)})
        return [{**dict(row), "event_ids": json.loads(row["event_ids"])} for row in rows]

    def checkpoint_material(self, principal: Principal) -> dict[str, Any]:
        """Authenticated body checks plus deterministic tenant-scoped commitment.

        Anchor this result independently of the database and encryption key.
        Audit log is deliberately excluded, so exporting twice is stable.
        This does not itself protect against DB replacement or source falsehood.
        """
        tenant = self._tenant(principal)
        self._authorize(principal, tenant, "checkpoint_material", "operator")
        error = None
        with self._transaction():
            result: dict[str, Any] = {"format": "eacp-store-checkpoint/1", "store_id": self.store_id,
                                      "tenant_id": tenant, "events": [], "inventories": [],
                                      "quarantine": [], "retention_receipts": []}
            try:
                self._verify_identity()
                for row in self._db.execute("SELECT * FROM events WHERE tenant_id=? ORDER BY source_id,event_id", (tenant,)):
                    if row["state"] != "pruned":
                        self._event_body(row)
                    material = {k: row[k] for k in ("source_id", "event_id", "sequence", "source_ts", "fingerprint",
                                                    "state", "ingested_at", "held", "pruned_at")}
                    material["protected_body_sha256"] = (None if row["state"] == "pruned" else
                        hashlib.sha256(bytes(row["nonce"]) + bytes(row["ciphertext"])).hexdigest())
                    result["events"].append(material)
                for row in self._db.execute("SELECT * FROM inventories WHERE tenant_id=? ORDER BY source_id,inventory_id", (tenant,)):
                    self._decrypt(row["nonce"], row["ciphertext"], self._aad(
                        "inventory", tenant, row["source_id"], row["inventory_id"], row["fingerprint"]))
                    material = {k: row[k] for k in ("id", "source_id", "inventory_id", "fingerprint", "registered_at")}
                    material["protected_body_sha256"] = hashlib.sha256(bytes(row["nonce"]) + bytes(row["ciphertext"])).hexdigest()
                    result["inventories"].append(material)
                for row in self._db.execute("SELECT * FROM quarantine WHERE tenant_id=? ORDER BY id", (tenant,)):
                    self._decrypt(row["nonce"], row["ciphertext"], self._aad(
                        "quarantine:" + row["kind"], tenant, row["source_id"], row["id"], row["fingerprint"]))
                    material = {k: row[k] for k in ("id", "source_id", "item_id", "kind", "reason", "fingerprint", "received_at")}
                    material["protected_body_sha256"] = hashlib.sha256(bytes(row["nonce"]) + bytes(row["ciphertext"])).hexdigest()
                    result["quarantine"].append(material)
                for row in self._db.execute("SELECT * FROM retention_receipts WHERE tenant_id=? ORDER BY id", (tenant,)):
                    result["retention_receipts"].append({**dict(row), "event_ids": json.loads(row["event_ids"])})
            except IntegrityError as exc:
                self._audit(principal, "checkpoint_material", "integrity_error")
                error = exc
            if error is None:
                self._audit(principal, "checkpoint_material", "success")
        if error:
            raise error
        return result
