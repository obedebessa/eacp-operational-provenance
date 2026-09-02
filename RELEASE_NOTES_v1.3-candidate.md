# EACP operational-provenance artifact v1.3 candidate

Status: reviewer candidate, 2026-09-02. This is not a GitHub or Zenodo release,
has not undergone peer review, and has no v1.3 DOI.

The evidence-and-protocol snapshot used by the candidate manuscript is commit
[`c20d2c06efda105cf6772861dd447413c5e709fa`](https://github.com/obedebessa/eacp-operational-provenance/tree/c20d2c06efda105cf6772861dd447413c5e709fa).

## Candidate claim

EACP 1.3 is a domain-specific operational-provenance profile and materialized
retrieval index for composing independently emitted delivery and runtime-control
evidence at service granularity. It preserves evidence pointers and uses exact,
typed, scoped links; the reference resolver abstains when the selected link is
missing or multivalued.

The candidate does not claim a new general provenance model, causal or
root-cause inference, source truth, tamper-proof storage, production readiness,
or replacement of supply-chain attestation, tracing, SIEM, or authoritative
source systems.

## Additions since v1.2.0

### Implementable EACP Profile 1.3

- Added `spec/EACP_PROFILE_v1.3.md` and Draft 2020-12 schemas for a core record,
  evidence collection, and resolution result.
- Made `(source_type, source_id)` explicit in the normative tuple and unique
  within a collection.
- Separated `initiator`, `triggering_actor`, `execution_principal`, and
  `attester` roles instead of overloading one actor string.
- Added typed, scoped service identities and typed, multivalued links with
  explicit evidence methods.
- Defined optional source-digest coverage and canonicalization without treating
  a digest as authentication or truth.
- Added a standard-library validator, v1.2 CSV migrator, conservative exact-link
  resolver, examples, and 19 deterministic tests.
- Preserved all 13 v1.2 CSV values through an auditable migration representation;
  migration is compatibility at the data boundary, not retroactive v1.3 semantics.

### Adversarial correlation robustness

- Added 25 scenarios covering random and plane-concentrated missing IDs,
  wrong-ID substitution, same- and cross-service reuse, replay, conflicting
  source records, clock skew, late arrival, reordering, and compound disruption.
- Evaluated three reconstruction policies over 30 deterministic seeds, yielding
  2,250 frozen trial rows.
- Added exact-chain, pairwise, false-join, abstention, ambiguity/conflict
  detection, arrival inversion, and time-to-completeness metrics.
- Under the strict service-plus-correlation policy, random missingness reduced exact-chain
  recovery from 94.17% at 1% missing to 26.17% at 20% missing. No false join was
  emitted in those scenarios.
- In the compound scenario, strict mode recorded 47.33% exact-chain accuracy,
  49.82% exact-chain F1, 19.01% abstention, 72.86% pairwise recall, and no false
  joins. This safety result is conditional on the declared synthetic invariants.

### Paired SQLite index ablation

- Added four treatments that retain both lookup indexes, remove either index,
  or remove both while importing the original v1.2 workload implementation.
- Asserted complete projection and per-query row equivalence for all treatments;
  18,000 warm and 1,200 cold-open query cases matched row for row.
- At 100,000 events, removing the targeted index changed warm service-query p95
  by 5.65× and warm correlation-query p95 by 73.91×.
- At the same size, the two lookup indexes occupied 22.776% of the full database;
  removing both reduced median paired ingestion time by 17.900%.
- The results are descriptive local SQLite measurements. Cold-open means a new
  SQLite connection and page cache, not a flushed operating-system disk cache.

### Real GitHub Actions → Kubernetes evidence

- Added a GitHub Actions adapter, minimized source snapshot, compatible
  13-column projection, normative Profile 1.3 records, exact-link report, JSON
  Schemas, checksum verification, and 13 deterministic tests.
- Added an isolated workflow that binds an attempt-specific correlation ID and
  pinned OCI subject across GitHub Actions metadata and Kubernetes resources.
- The workflow deliberately generates that ID and writes it into the positive
  Deployment and Pod-template annotations. This evaluates controlled key
  propagation and exact composition, not identifier discovery.
- Frozen public run
  [`33682116347`](https://github.com/obedebessa/eacp-operational-provenance/actions/runs/33682116347)
  completed successfully in three attempts at commit
  `76b2ed54381ae52cf0f54cd22a20341c3216b77b`.
- Every attempt produced three completed GitHub records, eight source-native
  Kubernetes audit records with the exact ID, one additional exact-target HTTP
  403 record with adapter-explicit correlation, and an unjoined no-ID negative
  control. Deployment, Pod specification, and runtime image ID matched the
  declared OCI subject digest.
- Each attempt includes deterministic archive checksums and an offline Sigstore
  bundle whose DSSE subject names the exact archive digest. All three archives
  were verified offline against the repository, signer workflow, source
  commit, Git ref, and the prohibition on self-hosted runners.
- The three attempts are reruns of one public workflow run in one repository,
  not third-party or cross-site replications. No field deployment or external
  independent reproduction has yet occurred.

### Reviewer-facing presentation

- Added `REVIEWER_GUIDE_v1.3.md` with a short reading path, verification commands,
  result boundaries, and explicit falsification/limitation points.
- Added three 300-dpi PNG figures for the Profile 1.3 architecture, correlation
  robustness, and three-attempt live cross-plane run.

## Compatibility and release separation

The v1.2 13-column CSV remains available as a compatibility projection. The
Profile 1.3 JSON record is normative for the new actor, service, link, and
digest semantics; the flat CSV cannot express all of them.

The v1.2 DOI-backed artifacts are unchanged in status:

- article/preprint DOI: <https://doi.org/10.5281/zenodo.22017662>;
- version-specific software/artifact DOI: <https://doi.org/10.5281/zenodo.21818550>;
- software/artifact Concept DOI: <https://doi.org/10.5281/zenodo.21817376>.

`CITATION.cff`, `MANIFEST.sha256`, and `paper/EACP_preprint.pdf` still identify
the released v1.2 artifact. They must not be used to imply that this candidate
branch is already archived. A v1.3 release would require a separate review,
release manifest, immutable tag, archival deposit, and synchronized citation
metadata.

## Verify the frozen candidate results

```bash
python3 experiments/github_actions/summarize_reference_run.py --verify
python3 experiments/index_ablation/index_ablation.py \
  --verify experiments/index_ablation/results/reference
(cd experiments/correlation_robustness/results/reference && \
  shasum -a 256 -c SHA256SUMS)
```

See [REVIEWER_GUIDE_v1.3.md](REVIEWER_GUIDE_v1.3.md) for the complete review
path and test commands.
