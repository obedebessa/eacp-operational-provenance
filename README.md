# EACP operational-provenance artifact

[![Reproduce small](https://github.com/obedebessa/eacp-operational-provenance/actions/workflows/reproduce-small.yml/badge.svg)](https://github.com/obedebessa/eacp-operational-provenance/actions/workflows/reproduce-small.yml)

This repository is the reproducibility artifact for:

> Obede Bessa Rocha da Silva, “Cross-Plane Operational Provenance in Cloud-Native Systems: A Reproducible Evaluation of EACP,” version 1.2, 2026.

It contains a deterministic SQLite microbenchmark, a small single-control-plane Kubernetes laboratory evaluation, and a bounded comparison with an OpenTelemetry Collector reference pipeline. The manuscript is a **preprint / technical report** and has **not undergone peer review**.

## Artifact boundary

EACP is an append-oriented evidence index for reconstructing operational transitions across heterogeneous control and observation planes. It retains normalized metadata and source pointers; it does not replace authoritative source systems or cryptographically preserve the artifacts to which those pointers refer.

This artifact evaluates three bounded questions:

1. Can an EACP SQLite index reproduce the same canonical rows as six indexed, fragmented source tables in a deterministic synthetic workload?
2. Can a small, real Kubernetes API-server audit workload be captured and normalized without putting EACP on the application request path?
3. For the overlapping log-ingestion scope, can a fixed OpenTelemetry Collector pipeline preserve the frozen audit bodies needed by an external post-export validator to reproduce the same canonical projection?

The evaluations do **not** establish production readiness, universal performance superiority, tamper-proof evidence, or complete auditability.

## Frozen results

All values below are copied from the machine-readable files in `data/`; they are not projections or illustrative numbers.

| Evaluation | Frozen run and boundary | Descriptive result |
|---|---|---|
| Synthetic SQLite | 10 sequential seeded trials at 10k, 50k, and 100k events; one process; warm-cache indexed queries | At 100k events, EACP ingestion was 5.332 microseconds/event (median), with service-query p95 0.691 ms versus 1.141 ms for the fragmented schema and correlation-query p95 0.0224 ms versus 0.0454 ms. EACP was an additional 413.983 bytes/event database versus 228.393 bytes/event for the fragmented database. Complete canonical projections were asserted equal in every trial. |
| Kubernetes audit | `20260806T031453Z`; one local kind control plane; three workload rounds | 374 sanitized namespace records were normalized to 374 unique rows; 132 carried an explicit `eacp-round-NN` correlation; all three intentional RBAC denials were audited as HTTP 403. Median EACP SQLite persistence was 3.002 ms across 10 sequential trials. |
| OpenTelemetry reference | `20260806T032418Z`; 10 sequential paired replays of the same 374-record corpus | Both paths retained 374/374 events. The Collector preserved the raw Kubernetes audit lines as exported log bodies; the external post-export EACP validator then matched 4,862/4,862 compared values after normalizing those bodies. This establishes shared-corpus preservation through the fixed pipeline, not Collector-native EACP semantics, functional equivalence, or a performance ranking. |

The Kubernetes corpus SHA-256 is `6aa39ee1cf8d3cbf58cb683ed6c7977ce851ab442c7057b7a85e974cb5400e01`. The canonical projection SHA-256 used by the paired comparison is `196d4a1bf8d057d9fe9e6f18062b7c5ac5228642df3098b28c84fb48d7a67da6`.

## Repository map

| Path | Purpose |
|---|---|
| `benchmark/sqlite/` | Standard-library deterministic fragmented-baseline and EACP benchmark |
| `experiments/kubernetes/` | Audit policy, kind template, controlled workload, runner, analyzer, and canonical results report |
| `experiments/comparison/opentelemetry/` | Collector Contrib configuration and paired comparison runner |
| `data/sqlite/` | Synthetic trial data, summaries, query plans, and sanitized environment metadata |
| `data/kubernetes/20260806T031453Z/` | Exactly the eight approved public result files from the canonical Kubernetes run |
| `data/comparison/20260806T032418Z/` | Safe comparison summary, trials, environment metadata, and run checksums |
| `figures/` | Figure generator plus publication-ready PNG, SVG, and vector-PDF figures |
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
python -m pip install 'Pillow>=10,<13'
python figures/generate_figures.py
```

## Interpretation limits

The fragmented SQLite baseline and EACP index use different physical schemas by design. Query results are checked for canonical row equality, while timings remain host- and cache-dependent. EACP storage is additional storage, not a reduction of the source systems’ storage.

The OpenTelemetry Collector is an existing, vendor-neutral ingest/process/export mechanism. It is included for the overlapping event-preservation scope and is **not functionally equivalent** to EACP’s indexed operational-provenance store. No SQLite-versus-file query comparison was performed, and this artifact **does not present a feature-equivalence** or universal-winner claim. Collector and EACP wall times include different process-isolation and output-format costs.

The Kubernetes evaluation used a single local kind control plane, one namespace, a compact CRUD workload, and no fault injection. It does not generalize to managed services, multi-node behavior, production throughput, or adversarial conditions.

## Data handling and privacy

Only synthetic data and a sanitized, namespace-scoped Kubernetes audit subset are staged. The public tree excludes complete audit logs, audit `sourceIPs` fields, kubeconfigs, credentials, token values, certificate bodies, private keys, absolute local paths, generated kind configuration, cluster-state snapshots, SQLite QA databases, and unrelated cluster events.

The sanitizer and selection rules are documented in `experiments/kubernetes/PUBLICATION_SCOPE.md` and `data/kubernetes/README.md`. SHA-256 checksums demonstrate integrity after freezing; they do not authenticate an upstream event source.

## Citation and archival status

GitHub can read the software citation from `CITATION.cff`. The version-specific identifier for v1.2.0 is the Zenodo software/artifact DOI <https://doi.org/10.5281/zenodo.21818550>. The Concept DOI <https://doi.org/10.5281/zenodo.21817376> represents all artifact versions and always resolves to the latest published version. These identifiers cover the software, configuration, data, documentation, figures, and reproducibility materials; neither is an article DOI for the accompanying preprint.

The searchable preprint is `paper/EACP_preprint.pdf`, and `MANIFEST.sha256` covers the frozen release tree. Release v1.2.0 is valid only after `python scripts/verify_repository.py --release` passes.

## Licensing

- Code, scripts, tests, CI, container configuration, Kubernetes manifests, and other software configuration: Apache License 2.0 (`LICENSE`).
- Data, documentation, and figures: Creative Commons Attribution 4.0 International (`LICENSES/CC-BY-4.0.txt`).
- The preprint PDF is not covered by those path-based grants unless `paper/README.md` or the PDF states otherwise.
- Third-party components are not relicensed; see `THIRD_PARTY_NOTICES.md`.
