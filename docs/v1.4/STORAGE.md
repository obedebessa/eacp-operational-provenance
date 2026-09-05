# Bounded encrypted ingestion reference

`eacp_hardening.store.EvidenceStore` adds a local ingestion and evidence-management
reference to the frozen v1.3 work. Its tests demonstrate specific failure behavior
in a local SQLite process. They do not establish production availability, a managed
service, enterprise capacity, secure multi-host operation, or regulatory compliance.

## Trust and authorization

The caller must supply a `Principal` created by an authentication boundary and
`VerifiedEvent` / `VerifiedInventory` objects returned by authenticated collector
verification. These Python dataclasses are contracts, not unforgeable capabilities.
Anyone able to execute arbitrary code in the process can construct them, obtain
the encryption key, or open the database directly. Never deserialize a Principal
or VerifiedEvent directly from an untrusted request and treat it as authenticated.

Every public operation checks the principal's tenant and required role. Source
identities, event identities, sequences, and inventories are scoped by tenant and
source. A caller cannot select another tenant using an API parameter. Ingestion
also checks that the verified statement belongs to the caller's tenant.

| Role | Operations |
| --- | --- |
| `writer` | Enqueue verified events; register verified inventories |
| `reader` | Read stored event bodies; inspect source status and pruned tombstones |
| `operator` | Drain the queue; inspect status/quarantine/tombstones; manage holds and retention; export checkpoint material |
| `auditor` | Read the tenant's access audit, status, quarantine, tombstones, and retention receipts |

Roles do not imply one another. For example, an operator needs an additional
`reader` role to read normal stored payloads; an auditor can inspect quarantined
submissions as part of investigation. Restrict assignment of both roles. A caller
can have multiple roles when the authentication policy explicitly grants them.

The store checks the supplied Principal on each call. Removed roles in a newly
issued Principal are rejected. The store does not itself refresh sessions, query
an identity provider, or revoke a previously issued in-process Principal; the
authentication boundary must prevent continued use of stale credentials.

Successful access, role/tenant denials, queue-full results, conflicts, holds,
retention actions, and detected protected-body corruption are audited. Audit rows
include subject, tenant, time, action, outcome, and minimal identifiers/counts;
event payloads are not copied into audit rows. User-entered hold/retention reasons
must contain administrative references rather than sensitive evidence content.
Audit retrieval is tenant-scoped and itself audited. No failure-path guarantee is
made when the storage device cannot commit the audit (for example, disk full).

## Durability and delivery semantics

Create one instance per thread/caller connection:

```python
store = EvidenceStore("private/evidence.sqlite", encryption_key, max_pending=1000)
ack = store.enqueue(authenticated_writer, verified_event)
count = store.drain(authenticated_operator, limit=100)
```

The encryption key is an externally supplied 32-byte key. Store configuration,
path ownership, key custody, and authenticated principals are operator-controlled.
All processes opening the same database must use the same pending capacity policy.

Each connection requests WAL, `synchronous=FULL`, foreign keys, and a 5-second
busy timeout. The database must be on a local filesystem with correct SQLite
locking and a storage stack that honors synchronization calls. WAL is not a
multi-host database protocol; network filesystems and distributed writers are
outside this implementation's tested scope.

`enqueue` returns `queued` only after its SQLite transaction commits. The pending
state and encrypted body are in the same transaction as the successful ingestion
audit. `drain` authenticates all selected bodies and changes pending to stored in
one transaction. A corrupt selected body prevents that entire drain batch from
advancing and records a visible integrity error. An operator must investigate;
this implementation does not silently skip a corrupt queue item.

A process can die after the durable commit but before the caller receives the
reply. The caller should retry the same verified event. Identity is
`(tenant_id, source_id, event_id)`; a canonical-content fingerprint includes the
source statement's identity, sequence, source timestamp, and payload. Delivery
metadata (`received_at`, `collector_id`, `key_id`, and `source_proof`) may change
when a verifier authenticates a renewed signature after an outage or key rotation.
Those fields are excluded from the source-content identity. Matching retries
return `duplicate` without inserting another event or replacing its original
acquisition time, collector identity, key identity, or encrypted original proof.
Authentication and authorization of every renewed submission still take place
before this storage call; accepting equal source content does not trust a new key
by itself.

A reused event ID with different content, or a different event ID at an already
occupied source sequence, raises `ConflictError`. The attempted statement is
encrypted in quarantine, an audit record is committed, and the accepted event is
unchanged. Sequence uniqueness also includes pending and pruned event identities.
This rejects structural conflicts; it cannot detect an internally consistent false
statement from an authorized collector.

Capacity is checked inside the insertion transaction, so separate concurrent
connections cannot race past the configured pending count. `QueueFullError`
means no acknowledgement of that event; the caller must retain it and retry.
An identical duplicate remains safe to acknowledge when the queue is full.
Capacity is global to the database, so tenants are not guaranteed separate queue
shares or fair scheduling.

The bound covers the number of pending records, not total storage bytes, request
rate, encrypted-body size, accepted history, quarantine, inventories, or audit
growth. Those require additional admission policies and disk monitoring before
hosting untrusted/high-volume clients. Drain batch size and SQLite writer locking
make this an intentionally bounded local reference, not a throughput claim.

## Confidentiality and integrity

Event bodies, finite-inventory bodies, and quarantined submissions use AES-256-GCM
with a new random 96-bit nonce per encryption. Associated data binds the body to
its durable store identity, kind, tenant, source, item identity, and
canonical-content fingerprint. Even if two independent stores use the same key
and logical event identity, one store's ciphertext cannot replace the other's
retained delivery proof. Source-content deduplication remains independent of
collector key rotation and renewed delivery proofs. Event
reads additionally compare authenticated identity/sequence/time fields with the
lookup row. Wrong-key opens, altered ciphertext, row swaps, and modified event
identity metadata fail closed. The durable random store identity is bound to an
encrypted key check and rechecked before checkpoint export.

The encryption key is never stored in the database. Obtain it from the deployment's
approved key store; do not use a hard-coded example key, command-line literal,
committed configuration, or unprotected log. Backup key custody, key loss,
rotation/re-encryption, access expiry, and compromise recovery are deployment
responsibilities. The reference does not implement KMS integration or online key
rotation. A single store key covers all tenants; API tenant isolation is not
cryptographic tenant separation.

Lookup metadata remains visible: tenant/source/event IDs, source timestamps,
sequences, digests, state, hold/prune timestamps, quarantine reasons, audit
identities, and retention receipts. The database, WAL, shared-memory file,
directory, and backups therefore still require restrictive OS ownership/access,
whole-volume encryption, and an appropriate retention policy. Newly created
database files request mode 0600; the store does not repair permissive existing
files or secure their parent directory on the operator's behalf.

AEAD authenticates protected bodies, not all mutable database metadata or record
existence. A database owner can remove rows, alter unanchored state, remove audit
records, or restore an older consistent database. Authenticated producer identity
does not establish source truth, completeness, authorization of the underlying
operation, human intent, or causality.

## Completeness, delay, and conflicting evidence

Without a registered finite inventory, source status is `UNKNOWN`, even when all
observed sequence numbers are contiguous. A registered inventory lists a finite
set of expected event IDs for one source. The store does not infer a producer's
complete history from timestamps or observed sequence continuity.

`status(principal, source_id, inventory_id=None)` reports the most recently
registered inventory by default. Pass its exact `inventory_id` for an enduring
comparison. Earlier inventories remain available. A retry of an old inventory
does not make it current; a new inventory ID establishes a separate scope. An
inventory ID cannot be reused with different content. Its list order is canonicalized.

For the selected inventory, `COMPLETE` means every expected ID currently has a
stored body whose authentication check passes. Pending, missing, or pruned expected
events yield `INCOMPLETE`. Status returns the inventory ID and scope, expected
count, missing IDs, pending and pruned IDs/counts, known sequence gap ranges,
quarantine count, and the last local ingestion time. Quarantine is exposed but
rejected submissions do not replace the accepted inventory or original event.

Late or reordered events can be accepted; after their durable drain, an incomplete
inventory can become complete. Sequence gaps are represented as ranges to avoid
allocating enormous missing-ID lists. These describe holes between observed
sequence numbers, not unobserved leading/trailing events. An explicitly empty
inventory can be complete for its empty scope; it proves nothing about other
inventories or source activity.

An authorized collector may omit real events from its inventory or issue a new,
smaller inventory. The status reflects that authenticated finite statement, not
independently verified source truth or a monitored time-window completeness SLA.
The reference supplies status and local ingestion timestamps, not an automated
reconciliation scheduler, liveness alarm, or freshness alert service.

## Holds and retention

`set_hold(operator, source_id, event_id, held, reason)` manages a live record's
administrative hold. A hold cannot restore an already pruned record. `prune`
selects pending/stored event payloads by their locally recorded ingestion time
strictly before a UTC cutoff, skips held records, and atomically replaces selected
live encrypted bodies with pruned tombstones and a retention receipt.

The receipt identifies the actor in the audit and lists the source/event IDs
pruned, cutoff, reason, timestamp, and held-record count. Tenant-scoped authorized
APIs retrieve receipts and tombstones. Event IDs, sequences, and fingerprints
remain to prevent silent history replacement or resurrection. Replaying an
identical pruned event returns `pruned`, not a successful retained-body status.
A still-selected inventory containing that event remains `INCOMPLETE`.

This is logical deletion of live event bodies. SQLite old pages, WAL segments,
backups, exports, independent snapshots, and recipients may retain ciphertext.
The same key may still decrypt those copies. No physical secure erase,
all-backup deletion, cryptographic erasure, legal-hold certification, or regulatory
deletion guarantee is claimed. Inventories, quarantine bodies, tombstones,
security audit, and receipts remain retained; deployments must define and
implement separate retention for those data classes.

## Independent checkpoints

`checkpoint_material(operator)` returns deterministic JSON-serializable material
for only that operator's tenant. It contains the store identity, event identities
and states (pending/stored/pruned), sequence/time fields, body fingerprints,
digests of nonce plus ciphertext, hold/prune state, inventories in their recorded
order, quarantine identities/digests, and retention receipts. It authenticates
every surviving encrypted body and checks store identity before returning.

Exporting twice without evidence changes gives identical material. Export access
is audited, but access audit is deliberately excluded from the commitment to
avoid a self-changing read. This means these evidence checkpoints do not protect
or prove completeness of the access audit. Export contains no raw payload bodies.

The integrity module can bind this material to a separately protected checkpoint
and compare a new export against it. Keeping both the database and checkpoint
under the same administrator/key/rollback domain does not establish independent
rollback protection. The checkpoint's trust root, externally retained state, and
expected checkpoint identity must be acquired independently. A consistent earlier
snapshot can only be recognized relative to a trustworthy later commitment.

## Executed local tests

Run the reference tests with the environment that has `cryptography` installed:

```sh
python -m unittest tests.hardening.test_store -v
```

The 16 tests cover matching retries and restart, authenticated re-signing after
collector/key changes without replacing the original proof, queue-full backpressure,
concurrent connections sharing capacity, encrypted conflicting submissions,
sequence collisions, out-of-order/late arrival, finite-inventory selection,
missing-to-complete transitions, unknown completeness, tenant/role denials,
role removal in a newly supplied Principal, absence of payload plaintext in local
database artifacts, wrong keys, corrupted ciphertext, row swaps, metadata and
inventory corruption, holds, retention receipts, no pruned resurrection, stable
tenant-isolated checkpoint material, and state changes affecting that material.

The crash test launches a real subprocess and calls `os._exit` immediately before
SQLite executes COMMIT, then separately after `enqueue` commits without sending a
reply. Reopening the store observes no event in the first case and one recoverable
pending event in the second. This tests abrupt process termination and transactional
recovery; it is not a power-cut test or validation of a particular device's fsync
implementation.
