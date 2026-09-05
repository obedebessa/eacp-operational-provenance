# EACP 1.4.0: collection security and resilience

Status: **software archival edition**, with a retained verified live signing run.
DOI `10.5281/zenodo.22326718` was reserved at source freeze; consult the Zenodo
record for publication status. Archival finality is not production readiness.
This is not a new normative Profile. Profile 1.3 semantics and the historical paper,
datasets, workflows and result verifiers remain byte-preserved. The versioned
1.3 DOIs do not identify this new source code or these new experiments.

This implementation responds to the technical assessment with executable controls,
negative tests and measured failure behavior. It does not promise freedom from
criticism, establish source truth, or turn author-executed tests into independent
replication. See the [one-pass reviewer packet](REVIEWER_PACKET.md).

## Implemented boundaries

| Area | Implementation | Verification and remaining boundary |
| --- | --- | --- |
| Publication minimization | Explicit Kubernetes/GitHub projections and omission accounting | Canary and malformed-input tests; allowed identifiers still need disclosure review |
| Collector identity | Ed25519 statement verification, pinned source/collector/adapter/origin, validity, revocation, freshness; bounded HTTPS acquisition | Real local signature checks and mocked transport policy tests; a collector can still lie |
| Durable ingestion | SQLite WAL/FULL pending queue, post-commit acknowledgement, immutable source-content idempotency, encrypted conflict quarantine, restart recovery | Actual process-exit and concurrent-connection tests; local filesystem assumptions and no distributed HA |
| Payload protection/access | AES-GCM bodies bound to store and row identity; tenant-scoped writer/reader/operator/auditor roles; audited reads and denials | Cross-tenant, role, corruption and cross-store-transplant tests; metadata/OS/admin access remain deployment responsibilities |
| Completeness | Authenticated finite inventories; explicit UNKNOWN/INCOMPLETE/COMPLETE; missing, pending, pruned and extra IDs | Fault campaign injects loss, reordering, duplicate delivery and late recovery; inventory authority is not universal source completeness |
| Retention | Operator-controlled event-body pruning, preservation holds, tombstones and receipts | Pruned events cannot resurrect or make an inventory complete; backups, quarantine and audit retention require deployment policy |
| Snapshot integrity | Signed checkpoints bound to an independently acquired current digest, sequence floor, tenant/store and freshness policy | Alteration, truncation, replay and consistent-replacement tests; compromise of the external anchor remains outside protection |
| Attestation isolation | Read-only execution job, separate hosted signer with no checkout or archive execution, exact artifact/run binding | Live main run 33945266470 and default/offline CLI verification; PR/branch signing skipped; owners, workflow and hosted platform remain trusted |
| External evaluation | Recorded reproduction runner and gated paired pilot protocol/evaluator | Ready-to-execute tooling; no external reviewer execution or organizational pilot is invented |

The [live signing record](../../results/hardening-v1.4/live-signing-33945266470/README.md)
identifies commit `0bcb038fef930faff3ef19f661bf995f97d605d8` and
[main run 33945266470](https://github.com/obedebessa/eacp-operational-provenance/actions/runs/33945266470),
attempt 1. Execution passed 112 tests and its OIDC-absence check; a distinct
hosted signing runner produced an attestation for the exact TAR. Fresh local
GitHub CLI and policy-wrapper verification succeeded with default trust and
with the separately captured official trust root offline. Six negative checks
rejected five deliberately altered conditions. These are author-operated hosted
execution and local verification, not an independent review or a field evaluation.
The signature covers the identified TAR only, not the entire repository, any PDF,
or a later review ZIP. See [the attestation boundary](ATTESTATION.md) for details.

## Run locally

Python **3.11 or newer**. The hardening extra uses the maintained cryptography
library rather than implementing cryptographic primitives itself. The historical
Profile and old benchmark retain their original dependency boundaries.

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[hardening]'
.venv/bin/python -m unittest discover -s tests/hardening -v
.venv/bin/python -m unittest discover -s spec/tests -v
.venv/bin/python scripts/verify_hardening.py
.venv/bin/python -m eacp_hardening.campaign --output reproduction-output/hardening-new
.venv/bin/python scripts/reprocess_frozen_privacy_v1_4.py --output reproduction-output/privacy-new.json
```

Output destinations must be new. Existing evidence is never silently overwritten.
The campaign uses only conspicuously synthetic public fixture identities and keys,
temporary local databases, five seeded schedules, forty events per schedule and
initial loss rates of 0%, 5% and 20%. Unit tests additionally exercise abrupt
process termination before and after commit, cipher corruption, key rotation,
wrong principals, queue saturation and expected trust-boundary failures.

The reprocessing command applies the new projection to the nine **old** public
confirmatory audit corpora. It is a compatibility check on retained bytes, not
nine new runs, fresh authenticated acquisition or independent reproduction.

For a third party, see [external validation](EXTERNAL_VALIDATION.md):

```bash
python3 scripts/reproduce_hardening_v1_4.py --output reproduction-output/reviewer-new --verify-plan
python3 scripts/reproduce_hardening_v1_4.py --output reproduction-output/reviewer-new
```

## Authenticated local CLI

```bash
python3 -m eacp_hardening --help
python3 -m eacp_hardening project --kind kubernetes --namespace permitted-namespace --input permitted-record.json --output new-public-projection.json
python3 -m eacp_hardening verify-source --config protected-policy.json --statement collector-statement.json
python3 -m eacp_hardening ingest --database protected/evidence.sqlite --config protected-policy.json --statement collector-statement.json
python3 -m eacp_hardening drain --database protected/evidence.sqlite --config protected-policy.json
python3 -m eacp_hardening status --database protected/evidence.sqlite --config protected-policy.json --source approved-source
python3 -m eacp_hardening checkpoint-export --database protected/evidence.sqlite --config protected-policy.json --output new-checkpoint-material.json
```

Store commands authenticate `EACP_ACCESS_TOKEN` against high-entropy token
fingerprints in protected policy and load a separate 32-byte encryption key from
`EACP_STORAGE_KEY_HEX`. Never paste production secrets into source, fixture files
or command arguments. The example paths above are placeholders, not deployed
credentials or an approved data-collection scope. No HTTP server is installed.

The collector signs the exact minimized payload and acquisition metadata. Its
signed statement is preserved inside the encrypted receipt. An unchanged source
event reissued with a renewed signature/key is idempotent; the original accepted
receipt is retained and conflicting source content is quarantined.

The registry, public keys, clock and token policy must come from a protected
operator boundary. A Python caller who constructs `Principal`/`VerifiedEvent`
objects directly is already inside the trusted process; these dataclasses are
not a remote authorization mechanism. The CLI supplies the authenticated entry
point. A future API must establish the same boundary itself.

## Checkpoint authority

Export a tenant-scoped snapshot from the collector. In a **separate authority**,
approve its contents, assign the next monotonic sequence, and sign it:

```bash
python3 -m eacp_hardening sign-checkpoint --material new-checkpoint-material.json --key-id independently-managed-key --sequence 1 --output new-checkpoint.json
python3 -m eacp_hardening verify-checkpoint --material freshly-exported-material.json --checkpoint new-checkpoint.json --anchor-policy independently-acquired-anchor-policy.json
```

The signing process alone receives `EACP_ANCHOR_PRIVATE_KEY_HEX`. The verifier
receives a protected public key, expected checkpoint SHA-256, minimum sequence,
store/tenant identity and freshness limit. Do not obtain these expectations from
the bundle being checked. A second folder on the same administrator-controlled
machine is **not** an independently protected deployment authority.

## Before any real-data pilot

Approve a bounded observation-only scope; establish collection identities,
external anchor ownership, access control, storage encryption, retention and
recovery policy; review all retained identifiers; set loss/lag limits; name an
owner for failures. Start with one organization and an isolated installation,
one service and two or three permitted sources. No application authorization or
inline enforcement is introduced.

Then execute the paired baseline evaluation in [PILOT_PROTOCOL.json](PILOT_PROTOCOL.json).
Its approval gates intentionally start false. A template is not organizational
consent, an agreed pilot, or a result.

## Additional design notes

- [Trust model, key rotation and compromise recovery](TRUST_MODEL.md)
- [Minimization and historical-corpus compatibility](PRIVACY.md)
- [Durability, encryption, access and retention boundaries](STORAGE.md)
- [Isolated attestation, observed live run and remaining limits](ATTESTATION.md)
- [Independent reproduction and pilot evaluation](EXTERNAL_VALIDATION.md)

## Historical preservation

`v1.3.0^{commit}` remains `537799bd2b292ce6e78004de22f4ab6df1b4feda`.
Only current repository presentation/package metadata and current CI/contract
routing are changed by this implementation among old tracked files. A preexisting
documentation-only commit, `e1ee51f050d7bf6e31dbee68560dd781e9b75985`, had already
added the standalone Profile DOI to several release documents and its current
manifest; the verifier accounts for that exact prior baseline. Archived experiment/specification
code, datasets, manifests, PDFs and original verifiers are unchanged.

The old `scripts/verify_repository.py` and `MANIFEST-v1.3.0.sha256` still describe
the old release. Run them in that exact immutable checkout. The new
`scripts/verify_hardening.py` checks version metadata and rejects modifications
to frozen content. Its `--release` gate requires an exact annotated v1.4.0 tag,
a clean checkout, the final manifest and preserved implementation/evidence pins.
It checks local release readiness, not Zenodo publication or human independence.
The live v1.4 signature identifies its own source and archive;
the v1.3 DOIs continue to identify their historical materials.
