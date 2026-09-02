# Reviewer guide — EACP 1.3 candidate

Status: reviewer candidate, 2026-09-02. This branch is not an archival release,
has not undergone peer review, and has no v1.3 DOI. The DOI-backed release
remains v1.2.0; see [archival status](#version-and-archival-status).

The evidence, protocols, frozen public-run bundles, and reviewer documentation
used by the candidate manuscript are pinned at commit
[`c20d2c06efda105cf6772861dd447413c5e709fa`](https://github.com/obedebessa/eacp-operational-provenance/tree/c20d2c06efda105cf6772861dd447413c5e709fa).
That repository snapshot is distinct from the live run's source commit
`76b2ed54381ae52cf0f54cd22a20341c3216b77b`.

## The contribution in one sentence

EACP 1.3 is a domain-specific operational-provenance profile and materialized
retrieval index that composes independently emitted delivery and runtime-control
evidence at service granularity, retains native evidence pointers, and abstains
when an explicit cross-plane link is absent or structurally ambiguous.

This is a deliberately bounded claim. EACP is not presented as a new general
provenance model, a causal-inference engine, an attestation system, a SIEM, or a
replacement for tracing, in-toto/SLSA, Sigstore, Tekton Chains, Grafeas, or the
authoritative systems that emitted the evidence.

![EACP Profile 1.3 evidence path](figures/eacp_architecture_v1_3.png)

## Suggested review path

1. Read the normative [EACP Profile 1.3](spec/EACP_PROFILE_v1.3.md), especially
   actor roles, scoped service identities, typed links, and safe resolution.
2. Inspect the [correlation-robustness protocol and results](experiments/correlation_robustness/README.md).
   This is the primary test of what happens when identifiers fail.
3. Inspect the [live GitHub Actions → Kubernetes protocol](experiments/github_actions/README.md)
   and its [three-attempt frozen run](experiments/github_actions/results/reference/run-33682116347/README.md).
4. Inspect the [SQLite index ablation](experiments/index_ablation/README.md) to
   separate normalization from the lookup indexes' measured benefit and cost.
5. Use the original v1.2 Kubernetes and OpenTelemetry materials only as the
   continuity baseline; they are not substitutes for the v1.3 experiments.

## What changed materially after v1.2

| Review question | v1.3 evidence |
|---|---|
| Is the data model implementable and unambiguous? | A versioned profile, three JSON Schemas, a standard-library validator/migrator/resolver, explicit source identity, actor roles, scoped services, typed multivalued links, precise digest semantics, and machine-readable abstention. |
| What happens when correlation identifiers are missing, wrong, reused, duplicated, delayed, reordered, or clock-skewed? | A deterministic 25-scenario × 3-policy × 30-seed campaign (2,250 trial rows) reports exact-chain, pairwise, false-join, abstention, ambiguity, conflict, and time-to-completeness metrics. |
| Is the indexed lookup result merely an unexplained implementation choice? | A paired four-treatment ablation removes the two lookup indexes independently and together while asserting row-for-row result equivalence. |
| Does “cross-plane” include two real emitters? | Three public attempts combine completed GitHub Actions REST evidence with source-native and explicitly target-bound Kubernetes API-server audit evidence. |
| Can the frozen live archive be independently checked? | Each attempt includes checksums, a completed-state recapture, and an offline attestation bundle; the aggregate verifier checks all frozen invariants and exact archive subjects. |

## Results worth scrutinizing

All percentages below are medians from the checked-in machine-readable files
unless the row describes the three discrete live attempts.

| Result | Observation | Boundary |
|---|---|---|
| Randomly missing IDs | Exact six-event-chain recovery declined from 94.17% at 1% missing to 26.17% at 20% missing; pairwise recall declined from 98.01% to 64.02%. Strict mode abstained on the affected observations and emitted no false joins in these scenarios. | Synthetic six-plane cadence; the result is not a universal missing-data law. |
| Wrong IDs and reuse | At 20% same-service wrong-ID substitution, strict mode recorded 7.08% exact-chain accuracy, 76.53% abstention, 18.66% pairwise recall, and no false joins. At 10% same-service reuse pairs, it recorded 80.00% exact-chain accuracy and 20.00% abstention. | Structural checks detect the declared violations. A complete, internally consistent wrong chain can evade them. |
| Compound disruption | Strict mode recorded 47.33% exact-chain accuracy, 49.82% exact-chain F1, 19.01% abstention, 72.86% pairwise recall, and no false joins. | Safety is conditional on the declared generator and invariants; lower coverage is an explicit cost, not hidden success. |
| Index ablation at 100k events | Removing the target index changed warm service-query p95 by 5.65× and warm correlation-query p95 by 73.91×. Removing both indexes reduced database bytes by 22.776% and median paired ingestion time by 17.900%. | Local, sequential SQLite workload. Ratios compare paired EACP variants, not different products. |
| Live cross-plane execution | Attempts 1–3 of public run [33682116347](https://github.com/obedebessa/eacp-operational-provenance/actions/runs/33682116347) all satisfied the exact-link, no-ID negative-control, target-bound HTTP 403, subject-digest, checksum, and attestation-subject checks. | One repository, one workflow, GitHub-hosted runners, and ephemeral single-node kind clusters. Three repeats are not a production population. |

For each live attempt, the completed view contains three GitHub records, eight
Kubernetes audit records carrying the source-native correlation annotation,
and one additional target-bound HTTP 403 record whose correlation is explicitly
asserted by the adapter. The 403 record did **not** carry a source-native
correlation ID and is therefore labeled `adapter_explicit_exact_target`. Three
audit records for the no-ID negative control remained unjoined. The Deployment,
Pod specification, and runtime image ID matched the pinned OCI subject digest.

![Correlation robustness summary](figures/eacp_correlation_robustness_v1_3.png)

![Three-attempt live cross-plane summary](figures/eacp_live_cross_plane_v1_3.png)

## Fast independent verification

From the repository root, these checks do not rerun timing experiments or
create a cluster:

```bash
python3 spec/tools/eacp_profile.py validate \
  spec/examples/valid-record-v1.3.json

python3 experiments/github_actions/summarize_reference_run.py --verify

python3 experiments/index_ablation/index_ablation.py \
  --verify experiments/index_ablation/results/reference

(cd experiments/correlation_robustness/results/reference && \
  shasum -a 256 -c SHA256SUMS)
```

Run the candidate-specific test suites:

```bash
python3 -m unittest discover -s spec/tests -v
python3 -m unittest discover -s experiments/github_actions/tests -v
python3 -m unittest discover -s experiments/correlation_robustness -p 'test_*.py' -v
python3 -m unittest discover -s experiments/index_ablation -p 'test_*.py' -v
```

The three archive attestations can also be checked cryptographically with the
exact repository, signer workflow, source revision, Git ref, and offline bundle;
the copy-ready command is in the
[frozen-run README](experiments/github_actions/results/reference/run-33682116347/README.md).
That verification authenticates builder provenance for the archive bytes. It
does not certify the semantic truth, completeness, or causality of source events.

## What would falsify or limit the interpretation

- A false join in the declared strict-policy matrix would contradict the
  reported safety result for that matrix.
- A complete but wrong chain that preserves the expected service, planes, and
  cadence is outside the structural detector's guarantees and may be accepted.
- Missing identifiers necessarily reduce reconstructible coverage; EACP does
  not recover absent explicit linkage by silently switching to a temporal join.
- The live experiment establishes observable composition in a controlled case,
  not semantic causation, source truth, managed-cluster behavior, or production
  reliability.
- The SQLite measurements are descriptive for one host, database engine,
  configuration, workload, and cache definition. “Cold-open” resets the SQLite
  connection-local page cache; it does not claim cold disk I/O.
- Checksums detect changes after freezing. They do not authenticate the original
  event source. The separate GitHub attestation covers the generated archive,
  not the truth of its contents.

## Version and archival status

This `eacp-v1.3-candidate` branch is a review surface, not a release. It must not
be cited with the v1.2 DOI as though that DOI archived the candidate changes.
No v1.3 DOI has been minted.

The last archival release is v1.2.0:

- article/preprint DOI: <https://doi.org/10.5281/zenodo.22017662>;
- version-specific software/artifact DOI: <https://doi.org/10.5281/zenodo.21818550>;
- software/artifact Concept DOI: <https://doi.org/10.5281/zenodo.21817376>.

`CITATION.cff`, `MANIFEST.sha256`, the DOI badge, and the released preprint PDF
continue to describe v1.2.0 until a separate candidate review, release decision,
and archival deposit are complete.
