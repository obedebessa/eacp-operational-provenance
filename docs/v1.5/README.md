# EACP 1.5.0rc1: bounded operational quickstart

This is an **unpublished software candidate**, not a new paper or Profile.
Profile 1.3, historical experiments, negative cohorts and the 1.4 signed TAR are
unchanged. The old signature does not cover this candidate. No human review,
provider uptime, production reliability or organizational benefit is inferred.

## Install and run without editing code

Use a current patched Python 3.11+ on a local filesystem. The recorded local
execution uses CPython 3.12.14/macOS arm64; other platforms require their own run.
Do not install into a system Python. Review source before installation (builds
execute trusted project code). Obtain the candidate commit/checksum separately.

```sh
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip==26.2.1
.venv/bin/python -m pip install .
.venv/bin/python -m pip check
.venv/bin/python -I -m eacp_hardening demo --output-directory /tmp/eacp-demo-new
```

Choose a destination that does not already exist. The demo uses installed code
outside the checkout, generated synthetic signing/storage keys, two **simulated**
sources and fresh CLI processes. It runs validation, authenticated ingest,
drain, exact/missing/ambiguous queries, anchored offline verification, a tampered
negative, diagnostics, SQLite backup, restore and identity/content comparison.
Read `SUMMARY.json` and individual `.receipt.json`, `.stdout`, `.stderr` files.
The two key roles are simulated locally: this is not independent administration.
Keys disappear when the demo finishes; its synthetic databases cannot thereafter
be reopened without those keys. They are not operational backup examples to keep.

For reproducible development checks (existing destination is rejected):

```sh
.venv/bin/python scripts/verify_candidate_v1_5.py --freeze
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python -O -m unittest discover -s tests/operability -v
.venv/bin/python scripts/mutate_v1_5.py --output /tmp/eacp-mutants-new
.venv/bin/python scripts/campaign_operability_v1_5.py --output /tmp/eacp-campaign-new
```

These are author/operator-executed checks, not a reviewer signature. Compare the
full receipts and source hashes, not merely the printed test total. Failure logs
must be retained. The short campaign is explicitly **not** a long-duration soak.

## Operational contract

Provision one owner-controlled directory (0700) and a local filesystem honoring
fsync. Database/sidecar files must be regular, owner-owned, single-link and 0600;
symlinks, FIFOs and loose permissions are rejected. Parent directories and the
OS owner remain trusted. No service/port is opened. SQLite WAL is not a distributed
store or network-filesystem protocol; its writers serialize.

`config.json` follows the documented 1.4 collector/access format. There must be
at least one collector and one access policy. Full validation rejects unknown
fields, duplicate token fingerprints, invalid role/expiry/key/origin/fixture
flags, freshness outside 1..86400 seconds and queue capacity outside 1..100000.
Run `eacp-hardening validate-config --config config.json` before using it. Store
config outside evidence packages; its canonical SHA-256 is bound into exports.

Supply `EACP_ACCESS_TOKEN` and `EACP_STORAGE_KEY_HEX` from an operator-managed
secret facility. Do not put real values in commands, shell history, Git, README,
logs or a review ZIP. Access roles remain writer, reader, operator and auditor.
The Python API trusts in-process `Principal`/`VerifiedEvent` objects; it is not a
sandbox against hostile code loaded into the same interpreter.

Ingest only minimized, authenticated collector statements. Generic encrypted
payload storage is not automatic public sanitization. Query-compatible payloads
must be exactly `{"profile_record": <valid Profile 1.3 record>}`. Actor roles are
preserved, not inferred from collector identity. Unknown payload formats fail
query rather than being silently omitted. Source timestamps must denote the same
instant in the envelope and the Profile. IDs are exact Unicode strings: no case,
whitespace or normalization folding; visually similar IDs remain distinct.

JSON inputs are capped at 2 MiB by default (32 MiB for transfer material), depth
64 and 250,000 traversed values. Duplicate fields, nonfinite numbers, malformed
UTF-8 and non-string object keys are rejected. Canonical hashing uses UTF-8 JSON,
sorted keys, compact separators, no NaN and no Unicode identity normalization;
this is the project representation, not a claim of universal JSON canonicalization.
Raw acquisition hashes and sanitized representation hashes are different facts.

## Ingestion, queries and transfer

```sh
eacp-hardening ingest --database evidence.sqlite --config config.json --statement event.json
eacp-hardening drain --database evidence.sqlite --config config.json
eacp-hardening query --database evidence.sqlite --config config.json --sources delivery runtime --query query.json --output export.json
eacp-hardening diagnostics --database evidence.sqlite --config config.json --source delivery
```

`query.json` requires source_type, source_id, link_type, scope_type and scope_id;
allow_inferred defaults false. The demo generates examples. Missing seed or link
and ambiguous seed are explicit abstentions. Multiple records with the same key
are a match set, not a one-to-one causal proof. A coherent false source chain can
still resolve. Export is **private by default**, not a publication approval.

Snapshot selection is tenant-scoped, at most 20 explicit sources and 10,000
events (also subject to JSON limits). Exceeding bounds fails, never silently
truncates. `--cutoff` is inclusive persistence time; default is current UTC with
microsecond precision. Source, collector-observed, persisted and captured times
are distinct. The snapshot is current retained state, not reconstruction of past
drain/prune state. Sorting is presentation, not causality. Pruned/pending records
remain unavailable; completeness uses the finite authenticated inventory only.
No inventory means UNKNOWN, including a silent but healthy application.

`ingest-page --source SOURCE --page page.json` accepts expected_cursor,
next_cursor and 1..1000 signed event statements. It atomically commits events and
encrypted cursor before ACK. On stale cursor reread with `cursor`, reconcile,
and retry; never blindly advance. All-or-nothing page rejection keeps no partial
records or cursor. Its audit is retained; individual conflicting submissions
can be sent to `ingest` for encrypted quarantine. No automatic quarantine
promotion or guessed conflict repair exists. Cursor limits are local opaque
progress tokens, not an implemented GitHub/Kubernetes watch recovery guarantee.

A separate trusted authority signs `export.json` using `sign-checkpoint`. It
must deliver the expected checkpoint hash/sequence, public key, tenant/store
identity, query hash and config through a channel independent of the package.
Then use `verify-export --material export.json --checkpoint checkpoint.json
--anchor-policy protected-policy.json --config config.json
--expected-query-sha256 EXPECTED_QUERY_HASH` (one command line). The verifier
checks the anchored bytes/context, collector proofs, actual inventory IDs and
recomputed resolver result. It does not trust a `verified` flag. Offline checks
use supplied policy snapshots; they do not query current revocation/freshness
authorities online or establish their administrative independence.

## Backup, restore and incident handling

```sh
eacp-hardening backup --database evidence.sqlite --config config.json --destination backup-new
eacp-hardening checkpoint-export --database evidence.sqlite --config config.json --output material.json
```

Stop or bound ingestion while obtaining the corresponding checkpoint. Backups
use the SQLite backup API under bounded writer exclusion, not a casual copy of
the main WAL-backed file. Physical backup needs both reader and operator roles
and a single-tenant database. It copies ciphertext and sensitive metadata,
including cursors/retention state; **not** keys, current trust or access config.
Protect those separately and test their availability. Compare the backup's
contained material to the current protected store checkpoint, then have the
separate authority sign the **whole backup manifest**, using `sign-checkpoint
--material backup-new/manifest.json`. The restore anchor must identify that exact
manifest, not only its contained material. This binds the SQLite digest and
config too, so rewriting an adjacent checksum is insufficient. Advance the
protected authority after newer evidence or retention changes; an old backup
anchor must not be presented as current.

`restore --backup backup-new --destination restored-new.sqlite --config config.json
--checkpoint checkpoint.json --anchor-policy protected-policy.json` restores only
to a new path and with a current independently acquired anchor. It checks exact
backup membership, digest, schema restrictions, tenant, key and reconstructed
checkpoint. Older snapshots fail against a newer anchor, including after pruning.
The backup and live destination must be under trusted operator ownership; this
is not a hostile-filesystem sandbox. Deadline/byte limits retain an incomplete
private destination on failure; do not start ingestion from it. Never replace the
live file in place. RPO is only the anchored snapshot; later arrivals require
source replay. RTO is measured by the returned elapsed duration, not a universal
service objective. Test queries and cursor values after recovery before cutover.

The cursor table is an additive schema extension; event ciphertext format is
unchanged. A checkpoint with cursors uses material format 2. An older writer does
not maintain these cursors: **in-place downgrade is unsupported**. Restore the
separately retained pre-upgrade snapshot to a new directory for rollback; no
automated downgrade or interrupted schema-migration guarantee is claimed.

On compromise: stop ingestion/exports, revoke affected collector/token policies,
rotate keys via an authenticated administrative channel, acquire a fresh trusted
anchor, quarantine the suspect interval, restore to a new path, reconcile IDs
with sources, and retain the incident. A compromised anchor or privileged OS
owner is not defeated by local checksums. Retention applies to live payloads;
WAL, backup, exports and metadata need separate approved disposal schedules.

Diagnostics distinguish store checks, source UNKNOWN, application NOT_OBSERVED
and anchor NOT_CHECKED. Silence means "silent or idle; reconcile", not fabricated
evidence loss. Tenant-wide enqueue outcomes and source pending/completeness are
separate. Authentication failures before storage are not counted by store metrics.
Bounded source labels avoid per-event metric cardinality. No alert service runs.

Uninstall with `.venv/bin/python -m pip uninstall eacp-operational-provenance`;
this does not delete operator evidence outside the environment. Do not remove
the database, backups or keys as an uninstall step.

## Real provider and pilot boundary

`collect-github-run --repository OWNER/REPO --run-id ID --attempt N` performs
credential-free HTTPS GETs against the public GitHub API only. It validates run,
repository, attempt, paged job identities, stable reported total and projection.
It refuses partial/rate-limited results; operator retry is required. It creates
no workflow and executes no downloaded artifact. Page fixtures are not live
integration. A live read of retained run 33945266470 is separately recorded;
there is no new Kubernetes run or managed-control-plane test in this upgrade.

The metadata-only audit policy here is an unexecuted pilot template, not the
historical RequestResponse lab policy. Minimal audit data may not contain the
annotations necessary for a join: return missing, do not turn on body capture
silently. Stage/object-incarnation mappings and watch recovery still need an
authorized provider-specific pilot. Existing `docs/v1.4/PILOT_PROTOCOL.json`
remains unstarted and unapproved. An external reviewer LOI is not permission to collect data.

## Sources and maintenance

The SQLite backup API supports consistent copying; WAL retains single-writer and
same-host/filesystem constraints. See [Python SQLite backup](https://docs.python.org/3/library/sqlite3.html#sqlite3.Connection.backup)
and [SQLite WAL](https://www.sqlite.org/wal.html). No backend change is needed to
claim this deliberately bounded local scope.

The [cryptography changelog](https://cryptography.io/en/latest/changelog/) was
checked on 2026-09-05; runtime pin 50.0.1 was retained. The isolated installer's
pip 25.0.1 advisory findings were retained, then the installer was updated to
26.2.1 following the [pip changelog](https://pip.pypa.io/en/stable/news/).
Dependency audit is not a source-code or whole-system security certification.
