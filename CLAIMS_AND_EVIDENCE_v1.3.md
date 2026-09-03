# EACP 1.3 claims and evidence ledger

Status: release 1.3.0 ledger, 2026-09-03. This document maps each headline
claim to executable or frozen evidence, its falsification condition, and its
interpretive boundary. It is not a substitute for the manuscript.

## Claim ledger

| ID | Bounded claim | Primary evidence | What would contradict it | Boundary |
|---|---|---|---|---|
| C1 | Profile 1.3 records have executable syntax and conservative exact-link resolution semantics. | `spec/EACP_PROFILE_v1.3.md`, JSON Schemas, `spec/tools/eacp_profile.py`, and 19 tests. | A declared-valid example fails validation; a malformed record passes; or the safe resolver silently joins a missing or multivalued selected link. | Reference implementation conformance is not interoperability across independent implementations. |
| C2 | The v1.2 13-column corpus can be migrated without losing any source cell. | Migrator tests and all 374 released Kubernetes rows. | Any source header or cell lacks an auditable representation after migration. | Lossless representation does not grant v1.3 semantics retroactively. |
| C3 | The original EACP SQLite materialization returns the same canonical rows as the indexed six-table synthetic baseline. | `benchmark/sqlite/`, `data/sqlite/`, and repository-contract tests. | Any complete projection or sampled query differs for a frozen trial. | Equality is defined by the declared projection and workload, not all conceivable source semantics. |
| C4 | Identifier failure produces the reported coverage, safety, abstention, and time-to-completeness behavior. | 25 scenarios × 3 policies × 30 seeds in `experiments/correlation_robustness/results/reference/`. | Re-execution from the frozen seeds differs, checksums fail, or metric recomputation disagrees. | Synthetic cadence, planes, rates, and detector invariants are experimental constructs. |
| C5 | The strict policy emitted zero false joins in the declared synthetic matrix. | Trial-level CSV/JSON, checksum manifest, and 16 tests. | One strict-policy trial contains a predicted cross-truth-chain pair. | This is an observation under declared invariants, never a universal guarantee. A complete internally consistent wrong chain can evade structural checks. |
| C6 | The two SQLite lookup indexes account for the reported query benefit, storage share, and ingestion cost in the paired workload. | Four treatments, 10 seeds, three sizes, 18,000 warm and 1,200 cold-open row-equivalence cases in `experiments/index_ablation/`. | Paired query rows differ or recomputed timing/storage summaries disagree. | One local sequential SQLite workload; cold-open is a new connection, not flushed disk cache. |
| C7 | Successful controlled runs contain separately emitted GitHub Actions and Kubernetes records that compose by one exact scoped identifier. | Public run 33682116347 and the confirmatory cohort under `experiments/github_actions/results/reference/cross-version-confirmatory-cohort-v1.3/`. | A positive record lacks the exact scoped value, a near match joins, or completed GitHub and Kubernetes evidence cannot be reproduced from a successful bundle. | The workflow generated and planted the key. This evaluates controlled propagation and composition, not identifier discovery or independent organizational corroboration. |
| C8 | A present no-ID Kubernetes control remains unjoined in each successful controlled run. | Negative-control objects, audit records, join reports, and extractor tests. | The object is absent, its records carry the operational key, or the resolver joins them to the positive chain. | This tests explicit abstention for one controlled object, not every missing-data pattern. |
| C9 | The denied Kubernetes action is not mislabeled as source-native correlation. | HTTP 403 audit records and `adapter_explicit_exact_target` bindings in successful join reports. | A source record contains the operational key or a normalized record labels the link `source_native`. | Exact target/principal/outcome binding is an adapter assertion, not causality. |
| C10 | The declared OCI digest matches Deployment image, Pod specification, and runtime image ID in each successful controlled run. | Deployment/Pod snapshots and join reports. | Any layer reports a different digest. | This is checked separately from operational correlation and does not prove source truth or deployment intent. |
| C11 | Each successful in-run TAR has post-freeze checksum integrity and GitHub-builder provenance under the stated policy. | Nested SHA-256 manifests, downloaded DSSE bundles, captured trusted roots, and verification records. | A checksum changes, the DSSE subject differs, or verification fails under repository/workflow/revision/ref/hosted-runner constraints. | The GitHub build-provenance attestation names only the in-run TAR as its subject. Local completed-state finalization is checksum-bound and public-API-cross-checkable, not builder-attested. Capture-time default-trust verification passed; a captured root enables offline re-verification relative to captured bytes but is not self-authenticating. Neither mechanism proves semantic truth. |
| C12 | The initial prospectively committed 3-by-3 cohort preserves nine first-attempt failures and 0/9 runs satisfying all predeclared criteria, all terminating at the same premature lifecycle assertion after exact version validation. | Commit `15d72da`; `cross-version-initial-failed-cohort-v1.3/`; public run/job/step metadata; checksum inventories; and `cross_version_protocol_amendment_v1.3.1.json`. | A member is not attempt one, uses another commit or target, fails before exact version validation, reaches a different failing step, or is reported as satisfying all predeclared criteria. | The minimized API metadata and failure-log markers were captured locally and checksum-bound; neither retained capture is an origin-signed response. The failures are not evidence that downstream end-to-end criteria passed. |
| C13 | After a prospectively frozen narrow direct-child amendment, the confirmatory 3-by-3 cohort achieved 9/9 first-attempt workflow successes and 9/9 runs satisfying all predeclared criteria, 3/3 for each pinned Kubernetes version. | Direct-child commit `4cbf7d2`; amendment record; nine public run IDs; and `cross-version-confirmatory-cohort-v1.3/` summary, bundles, and manifests. | The commit is not the direct child, a scientific input/control changes beyond the declared amendment, any member is a rerun or duplicate ID, any criterion fails, or recomputation disagrees. | The two generations and earlier run 33682116347 are not pooled. This is descriptive compatibility and procedural repetition in one repo/provider/workflow family on single-node kind—not field, managed-cluster, cross-provider, external, independent-organization, inferential, or reliability evidence. |

## Explicit non-claims

The release does not establish causal inference, root-cause correctness,
source truth, tamper-proof storage, complete auditability, production readiness,
universal performance superiority, managed-cluster behavior, field utility,
national importance, identifier discovery, external reproduction, independent-
organization corroboration, inferential reliability, or production failure
rates. It does not replace
in-toto/SLSA, Sigstore, Tekton Chains, Grafeas, tracing, SIEM, or authoritative
source systems.

## Upgrade rule

A claim may be broadened only when new evidence is checked in with a protocol,
machine-readable result, failure criteria, environment record, source pointers,
and integrity manifest. Repetition by the same author may establish procedural
repeatability; only an external operator can establish independent reproduction.
