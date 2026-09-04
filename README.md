# EACP operational-provenance artifact

[![Profile DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.22307668.svg)](https://doi.org/10.5281/zenodo.22307668)
[![Preprint DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.22283868.svg)](https://doi.org/10.5281/zenodo.22283868)
[![Reproduce small](https://github.com/obedebessa/eacp-operational-provenance/actions/workflows/reproduce-small.yml/badge.svg)](https://github.com/obedebessa/eacp-operational-provenance/actions/workflows/reproduce-small.yml)

> **Release — EACP 1.3.0, 2026-09-03.** Begin with the
> [reviewer guide](REVIEWER_GUIDE_v1.3.md). The version-specific Zenodo records
> are the standalone [Profile 1.3 specification](https://doi.org/10.5281/zenodo.22307668),
> the [preprint](https://doi.org/10.5281/zenodo.22283868), and the separate
> [software/reproducibility artifact](https://doi.org/10.5281/zenodo.22283852).

This release accompanies:

> Obede Bessa Rocha da Silva, “Cross-Plane Operational Provenance under Identifier Failure: A Reproducible Evaluation of EACP,” version 1.3.0, 2026. <https://doi.org/10.5281/zenodo.22283868>

Version 1.3.0 adds an implementable evidence profile, adversarial
correlation-identifier experiments, a paired SQLite index ablation, and a
controlled public GitHub Actions → Kubernetes evaluation: an earlier
three-attempt run plus separately reported initial and confirmatory 3-by-3
cross-version cohorts. The v1.2 artifact retains its deterministic SQLite
microbenchmark, small single-control-plane Kubernetes evaluation, and bounded
OpenTelemetry preservation comparison. The manuscript is a **preprint /
technical report** and has **not undergone peer review**.

## Review EACP 1.3.0

- [Read the v1.3.0 preprint (PDF)](paper/Cross_Plane_Operational_Provenance_Preprint_v1.3.0.pdf)
- [Open the archived Profile 1.3 specification](https://doi.org/10.5281/zenodo.22307668)
- [Concise evidence brief](EVIDENCE_BRIEF_v1.3.md)
- [Copy-ready expert review request](EXPERT_REVIEW_REQUEST_v1.3.md)
- [Claim-to-evidence and falsification ledger](CLAIMS_AND_EVIDENCE_v1.3.md)
- [Reviewer guide and verification path](REVIEWER_GUIDE_v1.3.md)
- [Release notes](RELEASE_NOTES_v1.3.0.md)
- [Normative EACP Profile 1.3](spec/EACP_PROFILE_v1.3.md)
- [Correlation-robustness experiment](experiments/correlation_robustness/README.md)
- [Live GitHub Actions → Kubernetes experiment](experiments/github_actions/README.md)
- [Prospective external replication protocol](experiments/github_actions/EXTERNAL_REPLICATION_PROTOCOL_v1.3.md)
- [Frozen public run 33682116347](experiments/github_actions/results/reference/run-33682116347/README.md)
- [Preserved initial failed 3-by-3 cohort](experiments/github_actions/results/reference/cross-version-initial-failed-cohort-v1.3/README.md)
- [Confirmatory 3-by-3 cohort](experiments/github_actions/results/reference/cross-version-confirmatory-cohort-v1.3/README.md)
- [SQLite index ablation](experiments/index_ablation/README.md)

The release's bounded contribution is a domain-specific operational-
provenance profile and materialized retrieval index that composes records
separately emitted by delivery and runtime-control systems at service granularity, retains
native evidence pointers, and abstains when explicit cross-plane linkage is
missing or structurally ambiguous.

## Cite EACP 1.3.0

- [Read the searchable v1.3.0 preprint (PDF)](paper/Cross_Plane_Operational_Provenance_Preprint_v1.3.0.pdf)
- [Open the archived Profile 1.3 specification](https://doi.org/10.5281/zenodo.22307668)
- [Open the archived preprint DOI](https://doi.org/10.5281/zenodo.22283868)
- [Open the archived reproducibility artifact](https://doi.org/10.5281/zenodo.22283852)
- Use GitHub's **Cite this repository** control for automatically generated
  citation formats. The preferred citation in `CITATION.cff` points to the
  preprint. The Profile DOI identifies the standalone specification and
  conformance aids; the software Zenodo DOI identifies the separate
  reproducibility artifact. Neither is the preprint DOI.

**APA**

> Rocha da Silva, O. B. (2026). *Cross-Plane Operational Provenance under
> Identifier Failure: A Reproducible Evaluation of EACP* (Version 1.3.0)
> [Preprint]. Zenodo. https://doi.org/10.5281/zenodo.22283868

**BibTeX**

```bibtex
@techreport{rocha_da_silva_eacp_2026,
  author  = {Obede Bessa Rocha da Silva},
  title   = {Cross-Plane Operational Provenance under Identifier Failure: A Reproducible Evaluation of EACP},
  year    = {2026},
  month   = sep,
  version = {1.3.0},
  doi     = {10.5281/zenodo.22283868},
  url     = {https://doi.org/10.5281/zenodo.22283868},
  note    = {Preprint}
}
```

The historical v1.2 preprint and artifact remain available at
<https://doi.org/10.5281/zenodo.22017662> and
<https://doi.org/10.5281/zenodo.21818550>, respectively.

## Artifact boundary

EACP is an append-oriented evidence index for reconstructing operational
transitions across heterogeneous control and observation planes. It retains
normalized metadata and source pointers; it does not replace authoritative
source systems. A source digest can detect change to a defined representation,
and successful live workflows separately attest their in-run TARs. Local
completed-state finalization is not part of those attestations, and neither
mechanism establishes source truth or causation.

Across the v1.2 and v1.3.0 materials, the artifact evaluates five
bounded questions:

1. Can an EACP SQLite index reproduce the same canonical rows as six indexed, fragmented source tables in a deterministic synthetic workload?
2. What coverage, false-join, missed-join, abstention, and latency trade-offs
   appear when identifiers are missing, wrong, reused, duplicated, delayed,
   reordered, or clock-skewed under declared policies?
3. How much lookup performance, storage, and ingestion cost is attributable to
   the EACP service and correlation indexes in the existing SQLite workload?
4. Can GitHub Actions and Kubernetes evidence be composed through exact
   typed/scoped links while a no-ID control remains unjoined, and does that
   controlled procedure repeat across three precisely versioned, digest-bound
   Kubernetes targets?
5. Can a small Kubernetes API-server audit workload be captured off the
   application path, and can a fixed OpenTelemetry Collector pipeline preserve
   its audit bodies for external post-export normalization?

The evaluations do **not** establish production readiness, causal correctness,
source truth, universal performance superiority, tamper-proof evidence,
complete auditability, identifier discovery, field utility, or independent
reproduction.

## EACP 1.3.0 results

All values below are copied from the checked-in machine-readable files. They
are descriptive results for the declared protocols, not projections.

| Evaluation | Frozen design | Descriptive result |
|---|---|---|
| Correlation robustness | 25 scenarios × 3 policies × 30 deterministic seeds; 2,250 trial rows | Under the strict service-plus-correlation policy, randomly removing 1%, 5%, 10%, and 20% of event IDs yielded 94.17%, 73.25%, 53.00%, and 26.17% exact-chain recovery, respectively, with no false joins in those scenarios. At 20% same-service wrong-ID substitution, exact-chain recovery was 7.08% and abstention was 76.53%. The declared strict-policy matrix emitted no false joins, conditional on the synthetic workload invariants. |
| EACP index ablation | 10 seeds × 10k/50k/100k events × four paired index treatments; 300 warm and 20 cold-open queries per type/trial | At 100k events, removing the target index changed warm service-query p95 by 5.65× and warm correlation-query p95 by 73.91×. Removing both lookup indexes reduced full-database bytes by 22.776% and median paired ingestion time by 17.900%. All 18,000 warm and 1,200 cold-open query cases were row-identical across variants. |
| Earlier live GitHub Actions → Kubernetes run | Public run [33682116347](https://github.com/obedebessa/eacp-operational-provenance/actions/runs/33682116347), three successful rerun attempts, one repository and one ephemeral single-node kind cluster per attempt | Every attempt produced three completed GitHub records, eight Kubernetes records with the exact workflow-injected ID, one target-bound HTTP 403 with adapter-explicit correlation, and three no-ID negative-control records that remained unjoined. Archive manifests and attestation subjects verified for all three attempts. These reruns are not pooled with either cross-version cohort. |
| Initial prospectively committed cross-version cohort | Nine distinct first-attempt public runs at commit [`15d72da`](https://github.com/obedebessa/eacp-operational-provenance/tree/15d72da095a0c7640b9318b50b28728e76d68928): three each on Kubernetes v1.34.8, v1.35.5, and v1.36.1 | All nine reached exact client/server/kubelet version validation and then failed at the same premature in-job lifecycle assertion, which requested the completed-run artifact before artifact creation. The failures are preserved; 0/9 satisfied all predeclared criteria. |
| Confirmatory cross-version cohort | Narrow amendment at direct-child commit [`4cbf7d2`](https://github.com/obedebessa/eacp-operational-provenance/tree/4cbf7d2fa0bb44585d258a3f37ce0c0d39ddea43); nine new first-attempt public runs, three per version | 9/9 workflows succeeded and 9/9 satisfied all predeclared criteria. The cohort contains nine distinct run IDs and nine distinct successful correlation IDs. It is descriptive evidence of controlled compatibility and procedural repetition, not an inferential reliability estimate. |

The earlier live-run summary is
`experiments/github_actions/results/reference/run-33682116347/reference_summary.json`.
The two cross-version generations are frozen separately under
`cross-version-initial-failed-cohort-v1.3/` and
`cross-version-confirmatory-cohort-v1.3/`; each has a machine-readable summary
and checksum inventory. See the [evidence brief](EVIDENCE_BRIEF_v1.3.md) for all
18 public cross-version run URLs and the amendment boundary.

## Released v1.2 results

These values remain copied from the machine-readable files in `data/`; the
v1.3.0 release does not relabel them as new v1.3 executions.

| Evaluation | Frozen run and boundary | Descriptive result |
|---|---|---|
| Synthetic SQLite | 10 sequential seeded trials at 10k, 50k, and 100k events; one process; warm-cache indexed queries | At 100k events, EACP ingestion was 5.332 microseconds/event (median), with service-query p95 0.691 ms versus 1.141 ms for the fragmented schema and correlation-query p95 0.0224 ms versus 0.0454 ms. EACP was an additional 413.983 bytes/event database versus 228.393 bytes/event for the fragmented database. Complete canonical projections were asserted equal in every trial. |
| Kubernetes audit | `20260806T031453Z`; one local kind control plane; three workload rounds | 374 sanitized namespace records were normalized to 374 unique rows; 132 carried an explicit `eacp-round-NN` correlation; all three intentional RBAC denials were audited as HTTP 403. Median EACP SQLite persistence was 3.002 ms across 10 sequential trials. |
| OpenTelemetry reference | `20260806T032418Z`; 10 sequential paired replays of the same 374-record corpus | Both paths retained 374/374 events. The Collector preserved the raw Kubernetes audit lines as exported log bodies; the external post-export EACP validator then matched 4,862/4,862 compared values after normalizing those bodies. This establishes shared-corpus preservation through the fixed pipeline, not Collector-native EACP semantics, functional equivalence, or a performance ranking. |

The Kubernetes corpus SHA-256 is `6aa39ee1cf8d3cbf58cb683ed6c7977ce851ab442c7057b7a85e974cb5400e01`. The canonical projection SHA-256 used by the paired comparison is `196d4a1bf8d057d9fe9e6f18062b7c5ac5228642df3098b28c84fb48d7a67da6`.

## Repository map

| Path | Purpose |
|---|---|
| `REVIEWER_GUIDE_v1.3.md` | Release reading order, headline evidence, verification commands, and claim boundaries |
| `spec/` | EACP Profile 1.3, JSON Schemas, reference validator/migrator/resolver, examples, and tests |
| `benchmark/sqlite/` | Standard-library deterministic fragmented-baseline and EACP benchmark |
| `experiments/correlation_robustness/` | Adversarial identifier, duplication, timing, and compound-scenario evaluation |
| `experiments/index_ablation/` | Paired service/correlation lookup-index treatments and frozen results |
| `experiments/github_actions/` | GitHub adapter, live workflow, Kubernetes join, preserved failed and successful cross-version cohorts, the earlier three-attempt run, and tests |
| `experiments/kubernetes/` | Audit policy, kind template, controlled workload, runner, analyzer, and canonical results report |
| `experiments/comparison/opentelemetry/` | Collector Contrib configuration and paired comparison runner |
| `data/sqlite/` | Synthetic trial data, summaries, query plans, and sanitized environment metadata |
| `data/kubernetes/20260806T031453Z/` | Exactly the eight approved public result files from the canonical Kubernetes run |
| `data/comparison/20260806T032418Z/` | Safe comparison summary, trials, environment metadata, and run checksums |
| `figures/` | v1.3.0 PNG generators/results plus the released v1.2 PNG, SVG, and vector-PDF set |
| `paper/` | Released v1.2 and v1.3.0 preprints with file-specific status and rights notes |
| `scripts/` | Reproduction, hygiene, and release-manifest checks |
| `tests/` | Repository-contract tests |

## Exact execution components

- kind `0.32.0` with digest-pinned node images for Kubernetes `v1.34.8`,
  `v1.35.5`, and `v1.36.1` in the cross-version cohorts. The corresponding
  image digests end in `sha256:02722c2dedddcfc00febf5d27fbeb9b7b2c14294c82109ff4a85d89ac9ba3256`,
  `sha256:ce977ae6d65918d0b58a5f8b5e940429c2ce42fa3a5619ec2bbc60b949c0ac95`,
  and `sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5`;
- a checksum-verified kubectl binary for each target; the API server and kubelet come
  from the digest-pinned kind node image and are checked at runtime against the
  exact requested version;
- OpenTelemetry Collector Contrib `0.158.0`, resolved image digest `sha256:c5918f78992ee73b0d6f0e599423ac5ec52dd5d9726733114d6eca53d5a32ed5`;
- CPython `3.11.9` and SQLite `3.51.0` for the frozen runs.

Do not substitute a floating image tag when reproducing an archival release.

## Reproduce

### Requirements

- Python 3.10 or newer (Python 3.11 or newer for the Kubernetes runner);
- Docker Engine for containerized experiments;
- kind and `kubectl` for the Kubernetes evaluation;
- Pillow 10–12 only if regenerating the PNG figures.

### Frozen v1.3.0 result verification

The fast path checks already frozen evidence without rerunning timing
experiments or creating a cluster:

```bash
python3 spec/tools/eacp_profile.py validate \
  spec/examples/valid-record-v1.3.json
python3 experiments/github_actions/summarize_reference_run.py --verify
python3 experiments/github_actions/summarize_cross_version_run_set.py \
  --root experiments/github_actions/results/reference/cross-version-initial-failed-cohort-v1.3 \
  --target-manifest experiments/github_actions/kubernetes_targets_v1.3.json \
  --verify
python3 experiments/github_actions/summarize_cross_version_run_set.py \
  --root experiments/github_actions/results/reference/cross-version-confirmatory-cohort-v1.3 \
  --target-manifest experiments/github_actions/kubernetes_targets_v1.3.json \
  --verify
python3 experiments/index_ablation/index_ablation.py \
  --verify experiments/index_ablation/results/reference
(cd experiments/correlation_robustness/results/reference && \
  shasum -a 256 -c SHA256SUMS)
```

Version 1.3.0-specific tests are listed in
[REVIEWER_GUIDE_v1.3.md](REVIEWER_GUIDE_v1.3.md).

### Repository and small-run checks

```bash
python -m unittest discover -s tests -v
python scripts/verify_repository.py
python scripts/generate_manifest.py --manifest MANIFEST-v1.3.0.sha256 --check
python scripts/verify_repository.py --release --expected-tag v1.3.0
bash scripts/reproduce_small.sh
```

The small run is a smoke test, not a replacement for the full trial matrix.

### Full synthetic benchmark

```bash
python benchmark/sqlite/eacp_benchmark.py \
  --sizes 10000 50000 100000 \
  --trials 10 \
  --services 200 \
  --query-samples 300 \
  --output reproduction-output/sqlite
```

### Kubernetes laboratory evaluation

```bash
cd experiments/kubernetes
./run_experiment.sh
```

The runner refuses to replace an existing cluster with the configured name and deletes only the temporary cluster it created. Its complete local output may contain control-plane material and is ignored by Git; only a reviewed, sanitized subset belongs under `data/kubernetes/`.

### OpenTelemetry reference comparison

```bash
python experiments/comparison/opentelemetry/run_comparison.py run \
  --input data/kubernetes/20260806T031453Z/analysis/public_filtered_audit.jsonl \
  --reference-csv data/kubernetes/20260806T031453Z/analysis/normalized_evidence.csv \
  --output-dir reproduction-output/opentelemetry/replay \
  --trials 10
```

Odd trials run EACP first and even trials run OpenTelemetry first. The Collector retains each raw JSON line as the exported log body; the configured parser also populates attributes, but the post-export EACP validator operates on the retained body. The Collector does **not** natively generate EACP’s 13 fields. After export, the shared validator in `run_comparison.py` maps both outputs to the canonical projection and checks row count, unique source identifiers, field equality, and projection digest.

### Figures

```bash
python3 -m pip install 'Pillow>=10,<13'
python3 figures/generate_v1_3_figures.py
python3 figures/generate_figures.py
```

## Interpretation limits

The fragmented SQLite baseline and EACP index use different physical schemas by design. Query results are checked for canonical row equality, while timings remain host- and cache-dependent. EACP storage is additional storage, not a reduction of the source systems’ storage.

The OpenTelemetry Collector is an existing, vendor-neutral ingest/process/export mechanism. It is included for the overlapping event-preservation scope and is **not functionally equivalent** to EACP’s indexed operational-provenance store. No SQLite-versus-file query comparison was performed, and this artifact **does not present a feature-equivalence** or universal-winner claim. Collector and EACP wall times include different process-isolation and output-format costs.

The released v1.2 Kubernetes evaluation used a single local kind control plane,
one namespace, a compact CRUD workload, and no fault injection. The v1.3
correlation campaign adds synthetic fault scenarios, while the live v1.3
workflow still uses ephemeral single-node kind clusters. Neither result
generalizes to managed services, multi-node behavior, production throughput,
or arbitrary adversaries.

Strict resolver safety is conditional on observable violations of the declared
service/plane/cadence invariants. A complete, internally consistent wrong chain
can evade structural checks. Abstention therefore makes one failure mode visible;
it is not a proof that accepted links are true or causal.

The index ablation isolates the two EACP lookup indexes, not normalization as a
whole. Its warm and cold-open timings are host- and cache-dependent, sequential
SQLite measurements; cold-open does not mean cold disk I/O.

The earlier three successful attempts are reruns under one run ID. They are not
pooled with the two cross-version generations. The initial 3-by-3 generation
preserves nine first-attempt failures and 0/9 runs satisfying all predeclared
criteria; the
direct-child amendment made one scientific acceptance-logic change by moving
the artifact-dependent three-row assertion to completed-run finalization; its
declared capture and verification support did not alter the scientific inputs
or criteria. The nine new first attempts then achieved 9/9 workflow
success and 9/9 runs satisfying all predeclared criteria. Both generations use the
same repository, provider, workflow family, hosted-runner class, and ephemeral
single-node kind design. They support descriptive compatibility and procedural
repetition only—not field or managed-cluster behavior, external or independent-
organization reproduction, cross-provider generalization, inferential
reliability, or production failure rates.

The workflow generated the joining identifier and planted it in the positive
Deployment and Pod-template annotations. “Source-native” means only that a raw
Kubernetes audit record retained that injected annotation; the study does not
evaluate identifier discovery. The present no-ID control remained unjoined.
The HTTP 403 carried no source-native operational key and is linked only by an
adapter-explicit assertion bound to the exact target, principal, and outcome.
The OCI digest is checked separately from correlation.

For each successful confirmatory run, the GitHub build-provenance attestation
names only the in-run TAR as its subject. Completed-state finalization is
performed locally after the run; it is checksum-bound and cross-checkable
against GitHub's public API, but it is not builder-attested. Capture-time
verification through GitHub CLI's built-in trust configuration passed for all
nine TARs. The captured root enables offline re-verification relative to those
captured bytes but is not self-authenticating. Initial-cohort minimized API
metadata and failure-log markers were captured locally and checksum-bound;
neither retained capture is an origin-signed response. None of these
mechanisms proves the semantic truth of GitHub or Kubernetes events.

## Data handling and privacy

Only synthetic data and a sanitized, namespace-scoped Kubernetes audit subset are staged. The public tree excludes complete audit logs, audit `sourceIPs` fields, kubeconfigs, credentials, token values, certificate bodies, private keys, absolute local paths, generated kind configuration, cluster-state snapshots, SQLite QA databases, and unrelated cluster events.

The sanitizer and selection rules are documented in `experiments/kubernetes/PUBLICATION_SCOPE.md` and `data/kubernetes/README.md`. SHA-256 checksums demonstrate integrity after freezing; they do not authenticate an upstream event source.

## Citation and archival status

Tag `v1.3.0` is the immutable source for this release. Its version-specific
software/artifact DOI is <https://doi.org/10.5281/zenodo.22283852>, while
<https://doi.org/10.5281/zenodo.21817376> is the artifact Concept DOI. The
separate v1.3.0 preprint DOI is <https://doi.org/10.5281/zenodo.22283868>, and
<https://doi.org/10.5281/zenodo.22017661> is the preprint Concept DOI. The
standalone Profile 1.3 version DOI is <https://doi.org/10.5281/zenodo.22307668>,
and <https://doi.org/10.5281/zenodo.22307667> is the Profile Concept DOI. A DOI
or Concept DOI for any of these three linked records must not be presented as
the identifier for another, and none implies peer review.

`CITATION.cff` describes software release v1.3.0, references the standalone
Profile, and points its preferred citation to the v1.3.0 preprint.
`MANIFEST-v1.3.0.sha256` covers the tracked release tree; the historical
`MANIFEST.sha256`, `paper/EACP_preprint.pdf`, and `RELEASE_NOTES_v1.2.0.md`
remain the frozen v1.2 materials.

## Licensing

- Code, scripts, tests, CI, container configuration, Kubernetes manifests, and other software configuration: Apache License 2.0 (`LICENSE`).
- Data, documentation, and figures: Creative Commons Attribution 4.0 International (`LICENSES/CC-BY-4.0.txt`).
- `paper/Cross_Plane_Operational_Provenance_Preprint_v1.3.0.pdf`: Creative Commons Attribution 4.0 International; the historical v1.2 PDF retains its own all-rights-reserved notice.
- Third-party components are not relicensed; see `THIRD_PARTY_NOTICES.md`.
