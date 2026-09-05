# Operability candidate protocol 1 (pre-execution)

Software target: **1.5.0rc1**, branch `eacp-v1.5-operability`. Profile, paper and
resolver semantics remain 1.3. Collection statements and checkpoints remain 1.4.
No new DOI, external review, live provider run, or organizational pilot is implied.
Frozen predecessor: `5067a26ad008db3bc4b4a5554e52c60239142735` (`v1.4.0`).
Original selected static review: `ecfd42d4f54d2d91d18fcdddf676d822001b79f9`.

## Inventory and comparison

Before runtime edits, run `scripts/inventory_v1_5.py`, five existing test suites,
and the frozen 1.4 release gate. Preserve command, exit code, output hashes,
environment and failed invocations. Repeat the same suites and boundary probes
after implementation. New tests are not retroactively baseline results.

## Scope and acceptance

One-host local-filesystem SQLite WAL reference CLI. Trusted OS owner; one tenant
per deployment for backup/restore. No public service, archive code execution,
networked filesystem, cluster failover, cloud costs or customer evidence. Build
and test in disposable directories. No private reviewer identity in the package.

Stage A: install the actual wheel in a new environment; validate config; synthetic
signed ingest, drain, query with missing/ambiguous abstention; export and verify
in another directory/process without source imports. Invalid inputs fail safely.
Stage B: enforce file/JSON limits, full config validation, scoped bounded queries,
checkpoint-bound export, consistent backup/restore, and honest diagnostic states.
Stage C: bounded deterministic experiments, independent manual oracle and actual
mutations in disposable source copies. Compare identities/content, not counts.
Stage D: clean pinned candidate commit, history-preservation check and review
package; leave review findings/conclusions unfilled. No automatic publication.

## Campaign budget and estimands

Protocol version 1, fixed seeds 17, 29, 43. Maximum 2,000 nominal events per seed,
200-event capacity burst, 2 concurrent writers, 30-second short soak (not a
long-duration reliability trial), 120-second deadline per scenario, 256 MiB of
generated files per run. Synthetic payloads <=2 KiB. Cancel if limits are reached
and retain incomplete output. At most 512 MiB declared RSS budget. Record actual
RSS, CPU, disk bytes, offered/queued/duplicate/rejected/pending/stored identities,
enqueue p50/p95/max, recovery times and errors. Local OS/filesystem caches are not
claimed cold. Cases in one process/machine are not independent organizations.

Accept only when every acknowledged ID and content is accounted for after
restart/drain/backup/restore. Missing finite-inventory IDs mean INCOMPLETE;
no trusted inventory means UNKNOWN. Duplicate deliveries must not inflate IDs.
Simulated quota/read-only errors and process exit do not emulate physical power
loss. Backup loss is measured against the declared snapshot, not promised zero
RPO for future arrivals. Export verification must reject bytes/context changes.

Resolver manual oracle: known exact keys; missing and multivalued seed cases;
scope collision; irrelevant additions; permutations; explicit inferred opt-in;
consistent false chain retained as a non-detectable semantic boundary. Do not
report precision 100% when no links are accepted. Mutation success requires a
specific assertion failure, not timeout/import error. Preserve each mutant log.

No changes to thresholds after seeing results. Corrections to this protocol must
be numbered separately with the original retained. A separate ZIP/list of the
208 mentioned scenarios was not attached: only the supplied 26-area brief is
available. Do not claim that 208 individually specified cases were executed.
