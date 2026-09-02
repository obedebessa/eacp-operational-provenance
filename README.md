# EACP operational-provenance artifact

[![Article DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.22017662.svg)](https://doi.org/10.5281/zenodo.22017662)
[![Reproduce small](https://github.com/obedebessa/eacp-operational-provenance/actions/workflows/reproduce-small.yml/badge.svg)](https://github.com/obedebessa/eacp-operational-provenance/actions/workflows/reproduce-small.yml)

> **Reviewer candidate — EACP 1.3, 2026-09-02.** This branch is not an
> archival release and has no v1.3 DOI. Begin with the
> [reviewer guide](REVIEWER_GUIDE_v1.3.md). The DOI badge and citation metadata
> continue to identify the last released version, v1.2.0.

This branch extends the released reproducibility artifact for:

> Obede Bessa Rocha da Silva, “Cross-Plane Operational Provenance in Cloud-Native Systems: A Reproducible Evaluation of EACP,” version 1.2, 2026.

The v1.3 candidate adds an implementable evidence profile, adversarial
correlation-identifier experiments, a paired SQLite index ablation, and a
three-attempt public GitHub Actions → Kubernetes evaluation. The v1.2 artifact
retains its deterministic SQLite microbenchmark, small single-control-plane
Kubernetes evaluation, and bounded OpenTelemetry preservation comparison. The
manuscript is a **preprint / technical report** and has **not undergone peer review**.

## Review EACP 1.3

- [Reviewer guide and verification path](REVIEWER_GUIDE_v1.3.md)
- [Candidate release notes](RELEASE_NOTES_v1.3-candidate.md)
- [Normative EACP Profile 1.3](spec/EACP_PROFILE_v1.3.md)
- [Correlation-robustness experiment](experiments/correlation_robustness/README.md)
- [Live GitHub Actions → Kubernetes experiment](experiments/github_actions/README.md)
- [Frozen public run 33682116347](experiments/github_actions/results/reference/run-33682116347/README.md)
- [SQLite index ablation](experiments/index_ablation/README.md)

The candidate's bounded contribution is a domain-specific operational-
provenance profile and materialized retrieval index that composes independently
emitted delivery and runtime-control evidence at service granularity, retains
native evidence pointers, and abstains when explicit cross-plane linkage is
missing or structurally ambiguous.

## Read and cite the released v1.2 paper

- [Read the searchable preprint (PDF)](paper/EACP_preprint.pdf)
- [Open the archived preprint and article DOI](https://doi.org/10.5281/zenodo.22017662)
- [Open the archived reproducibility artifact](https://doi.org/10.5281/zenodo.21818550)
- Use GitHub's **Cite this repository** control for automatically generated
  citation formats. The preferred citation in `CITATION.cff` points to the
  preprint. The Zenodo DOI identifies the separate software and reproducibility
  artifact; it is not an article DOI.

**APA**

> Rocha da Silva, O. B. (2026). *Cross-Plane Operational Provenance in
> Cloud-Native Systems: A Reproducible Evaluation of EACP* (Version 1.2)
> [Preprint]. Zenodo. https://doi.org/10.5281/zenodo.22017662

**BibTeX**

```bibtex
@techreport{rocha_da_silva_eacp_2026,
  author  = {Obede Bessa Rocha da Silva},
  title   = {Cross-Plane Operational Provenance in Cloud-Native Systems: A Reproducible Evaluation of EACP},
  year    = {2026},
  month   = aug,
  version = {1.2},
  doi     = {10.5281/zenodo.22017662},
  url     = {https://doi.org/10.5281/zenodo.22017662},
  note    = {Preprint}
}
```

## Artifact boundary

EACP is an append-oriented evidence index for reconstructing operational
transitions across heterogeneous control and observation planes. It retains
normalized metadata and source pointers; it does not replace authoritative
source systems. A source digest can detect change to a defined representation,
and the live experiment separately attests its archive, but neither mechanism
establishes source truth or causation.

Across the released and candidate materials, the artifact evaluates five
bounded questions:

1. Can an EACP SQLite index reproduce the same canonical rows as six indexed, fragmented source tables in a deterministic synthetic workload?
2. What coverage, false-join, missed-join, abstention, and latency trade-offs
   appear when identifiers are missing, wrong, reused, duplicated, delayed,
   reordered, or clock-skewed under declared policies?
3. How much lookup performance, storage, and ingestion cost is attributable to
   the EACP service and correlation indexes in the existing SQLite workload?
4. Can independently emitted GitHub Actions and Kubernetes evidence be composed
   through exact typed/scoped links while a no-ID control remains unjoined?
5. Can a small Kubernetes API-server audit workload be captured off the
   application path, and can a fixed OpenTelemetry Collector pipeline preserve
   its audit bodies for external post-export normalization?

The evaluations do **not** establish production readiness, causal correctness,
source truth, universal performance superiority, tamper-proof evidence, or
complete auditability.

## EACP 1.3 candidate results

All values below are copied from the checked-in machine-readable files. They
are descriptive results for the declared protocols, not projections.

| Evaluation | Frozen design | Descriptive result |
|---|---|---|
| Correlation robustness | 25 scenarios × 3 policies × 30 deterministic seeds; 2,250 trial rows | Under the strict service-plus-correlation policy, randomly removing 1%, 5%, 10%, and 20% of event IDs yielded 94.17%, 73.25%, 53.00%, and 26.17% exact-chain recovery, respectively, with no false joins in those scenarios. At 20% same-service wrong-ID substitution, exact-chain recovery was 7.08% and abstention was 76.53%. The declared strict-policy matrix emitted no false joins, conditional on the synthetic workload invariants. |
| EACP index ablation | 10 seeds × 10k/50k/100k events × four paired index treatments; 300 warm and 20 cold-open queries per type/trial | At 100k events, removing the target index changed warm service-query p95 by 5.65× and warm correlation-query p95 by 73.91×. Removing both lookup indexes reduced full-database bytes by 22.776% and median paired ingestion time by 17.900%. All 18,000 warm and 1,200 cold-open query cases were row-identical across variants. |
| Live GitHub Actions → Kubernetes | Public run [33682116347](https://github.com/obedebessa/eacp-operational-provenance/actions/runs/33682116347), three successful attempts, one GitHub-hosted workflow and one ephemeral single-node kind cluster per attempt | Every attempt produced three completed GitHub records, eight Kubernetes records with a source-native exact ID, one target-bound HTTP 403 with adapter-explicit correlation, and three no-ID negative-control records that remained unjoined. The Deployment, Pod specification, and runtime image ID matched the pinned subject digest. Archive manifests and attestation subjects verified for all three attempts. |

The live reference summary is
`experiments/github_actions/results/reference/run-33682116347/reference_summary.json`;
its 98-entry inventory is bound by `REFERENCE_SHA256SUMS`.

## Released v1.2 results

These values remain copied from the machine-readable files in `data/`; the
candidate does not relabel them as new v1.3 executions.

| Evaluation | Frozen run and boundary | Descriptive result |
|---|---|---|
| Synthetic SQLite | 10 sequential seeded trials at 10k, 50k, and 100k events; one process; warm-cache indexed queries | At 100k events, EACP ingestion was 5.332 microseconds/event (median), with service-query p95 0.691 ms versus 1.141 ms for the fragmented schema and correlation-query p95 0.0224 ms versus 0.0454 ms. EACP was an additional 413.983 bytes/event database versus 228.393 bytes/event for the fragmented database. Complete canonical projections were asserted equal in every trial. |
| Kubernetes audit | `20260806T031453Z`; one local kind control plane; three workload rounds | 374 sanitized namespace records were normalized to 374 unique rows; 132 carried an explicit `eacp-round-NN` correlation; all three intentional RBAC denials were audited as HTTP 403. Median EACP SQLite persistence was 3.002 ms across 10 sequential trials. |
| OpenTelemetry reference | `20260806T032418Z`; 10 sequential paired replays of the same 374-record corpus | Both paths retained 374/374 events. The Collector preserved the raw Kubernetes audit lines as exported log bodies; the external post-export EACP validator then matched 4,862/4,862 compared values after normalizing those bodies. This establishes shared-corpus preservation through the fixed pipeline, not Collector-native EACP semantics, functional equivalence, or a performance ranking. |

The Kubernetes corpus SHA-256 is `6aa39ee1cf8d3cbf58cb683ed6c7977ce851ab442c7057b7a85e974cb5400e01`. The canonical projection SHA-256 used by the paired comparison is `196d4a1bf8d057d9fe9e6f18062b7c5ac5228642df3098b28c84fb48d7a67da6`.

## Repository map

| Path | Purpose |
|---|---|
| `REVIEWER_GUIDE_v1.3.md` | Candidate reading order, headline evidence, verification commands, and claim boundaries |
| `spec/` | EACP Profile 1.3, JSON Schemas, reference validator/migrator/resolver, examples, and tests |
| `benchmark/sqlite/` | Standard-library deterministic fragmented-baseline and EACP benchmark |
| `experiments/correlation_robustness/` | Adversarial identifier, duplication, timing, and compound-scenario evaluation |
| `experiments/index_ablation/` | Paired service/correlation lookup-index treatments and frozen results |
| `experiments/github_actions/` | GitHub adapter, live workflow, Kubernetes join, frozen three-attempt run, and tests |
| `experiments/kubernetes/` | Audit policy, kind template, controlled workload, runner, analyzer, and canonical results report |
| `experiments/comparison/opentelemetry/` | Collector Contrib configuration and paired comparison runner |
| `data/sqlite/` | Synthetic trial data, summaries, query plans, and sanitized environment metadata |
| `data/kubernetes/20260806T031453Z/` | Exactly the eight approved public result files from the canonical Kubernetes run |
| `data/comparison/20260806T032418Z/` | Safe comparison summary, trials, environment metadata, and run checksums |
| `figures/` | v1.3 candidate PNG generators/results plus the released v1.2 PNG, SVG, and vector-PDF set |
| `paper/` | Searchable version 1.2 preprint PDF and its file-specific rights notice |
| `scripts/` | Reproduction, hygiene, and release-manifest checks |
| `tests/` | Repository-contract tests |

## Exact execution components

- kind `0.32.0` with Kubernetes node image `kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5`;
- Kubernetes server `v1.36.1` and kubectl client `v1.36.3`;
- OpenTelemetry Collector Contrib `0.158.0`, resolved image digest `sha256:c5918f78992ee73b0d6f0e599423ac5ec52dd5d9726733114d6eca53d5a32ed5`;
- CPython `3.11.9` and SQLite `3.51.0` for the frozen runs.

Do not substitute a floating image tag when reproducing an archival release.

## Reproduce

### Requirements

- Python 3.10 or newer (Python 3.11 or newer for the Kubernetes runner);
- Docker Engine for containerized experiments;
- kind and `kubectl` for the Kubernetes evaluation;
- Pillow 10–12 only if regenerating the PNG figures.

### Candidate result verification

The fast path checks already frozen evidence without rerunning timing
experiments or creating a cluster:

```bash
python3 spec/tools/eacp_profile.py validate \
  spec/examples/valid-record-v1.3.json
python3 experiments/github_actions/summarize_reference_run.py --verify
python3 experiments/index_ablation/index_ablation.py \
  --verify experiments/index_ablation/results/reference
(cd experiments/correlation_robustness/results/reference && \
  shasum -a 256 -c SHA256SUMS)
```

Candidate-specific tests are listed in
[REVIEWER_GUIDE_v1.3.md](REVIEWER_GUIDE_v1.3.md).

### Repository and small-run checks

```bash
python -m unittest discover -s tests -v
python scripts/verify_repository.py
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

The three live attempts demonstrate repeatability of one controlled workflow.
The HTTP 403 audit record contains no source-native correlation; its link is an
adapter-explicit assertion bound by exact API group, resource, namespace, name,
principal, and outcome. The archive attestation authenticates builder provenance
for archive bytes, not the truth of GitHub or Kubernetes events.

## Data handling and privacy

Only synthetic data and a sanitized, namespace-scoped Kubernetes audit subset are staged. The public tree excludes complete audit logs, audit `sourceIPs` fields, kubeconfigs, credentials, token values, certificate bodies, private keys, absolute local paths, generated kind configuration, cluster-state snapshots, SQLite QA databases, and unrelated cluster events.

The sanitizer and selection rules are documented in `experiments/kubernetes/PUBLICATION_SCOPE.md` and `data/kubernetes/README.md`. SHA-256 checksums demonstrate integrity after freezing; they do not authenticate an upstream event source.

## Citation and archival status

The `eacp-v1.3-candidate` branch is a review surface, not a release. It has no
v1.3 DOI, and the v1.2 DOI must not be cited as though it archived the candidate
changes. See [candidate release notes](RELEASE_NOTES_v1.3-candidate.md).

GitHub can read the released software citation from `CITATION.cff`. The
version-specific identifier for v1.2.0 is the Zenodo software/artifact DOI
<https://doi.org/10.5281/zenodo.21818550>. The Concept DOI
<https://doi.org/10.5281/zenodo.21817376> represents all published artifact
versions and resolves to the latest published version. The separate v1.2
article/preprint DOI is <https://doi.org/10.5281/zenodo.22017662>.

The searchable released preprint is `paper/EACP_preprint.pdf`, and
`MANIFEST.sha256` covers the frozen v1.2 release tree. Release v1.2.0 is valid
only after `python scripts/verify_repository.py --release` passes. Neither file
is silently repurposed as a v1.3 candidate manifest or citation.

## Licensing

- Code, scripts, tests, CI, container configuration, Kubernetes manifests, and other software configuration: Apache License 2.0 (`LICENSE`).
- Data, documentation, and figures: Creative Commons Attribution 4.0 International (`LICENSES/CC-BY-4.0.txt`).
- The preprint PDF is not covered by those path-based grants unless `paper/README.md` or the PDF states otherwise.
- Third-party components are not relicensed; see `THIRD_PARTY_NOTICES.md`.
