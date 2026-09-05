# Findings, changes, execution and residual risks

Scope: software 1.5.0rc1, Profile/paper 1.3, operability protocol 1. This matrix
maps the **26-area brief actually received**, not an unavailable list of 208
individual cases. "Implemented" and "executed" are distinct. Final review ZIP
contains `verification/` receipts; source SHA/commit in each campaign governs
which code was measured. Do not pool development, final or historical cohorts.

Initial review target was ecfd42d4; baseline here was frozen 1.4.0 at 5067a26a.
That baseline already had authenticated collectors, minimization, encrypted
durable ingestion, role checks, retention, checkpoints, signing isolation and
retained live-signature negatives. Those are retested, not claimed as new fixes.
The old artifact-finalization failure and correction are preserved untouched.

## Finding -> change -> test -> execution/artifact -> residual risk

| Brief area | Classification and change | Tests / receipts | Remaining boundary |
|---|---|---|---|
| 1 Inventory/version | Added inventory, before/after probes, preservation gate, candidate metadata | inventory_v1_5; baseline root/Profile/adapter/correlation/index; verify_candidate | No borrowed 1.4 DOI or altered tag; initial adapter discovery error retained |
| 2 End-to-end use | Confirmed install gap: core CLI dependency was optional; Profile utility absent from wheel. Installed query path and demo added | installed-demo; wheel-content audit; full receipts | Synthetic run in new env, not independent person or new Kubernetes integration |
| 3 Schema/IDs | Confirmed unbounded depth acceptance; explicit depth/byte/node limits, no key coercion, full config validation | B01/B02/B05; R07; before/after probes | Profile schema unchanged; no Unicode identity folding; programmatic API trusts caller |
| 4 Correlation | Conservative resolver reused byte-for-byte; manual oracle and generated/order cases added | R01-R08 | False but consistent assertion remains accepted structurally, explicitly demonstrated |
| 5 Test quality | Actual disposable scope/auth/digest mutations added | mutate_v1_5; R03/A02/X05 | Three targeted mutations, not exhaustive mutation coverage or 208 cases |
| 6 Time | Persistence cutoff, source/observed/persisted/captured separation, clock warnings | Q03; O02; installed demo | Current retained state, not historical time travel or cross-system causal clock |
| 7 Adapters | Bounded public GitHub run/attempt/job reader with fail-closed paging | G01-G04 fixture tests; github-live-read receipt | Live read of old run only; retry is operator-driven; no managed K8s/watch integration |
| 8 Source trust | Existing Ed25519/TLS/pinned-collector checks retained; export revalidates signed statements | historical test_trust suite; Q01/X03/X06 | No guarantee source tells truth; no independent key custody or compromise exercise |
| 9 Durable ingest | New all-or-nothing event pages and encrypted cursor CAS | I01-I04; F01; burst campaign | Rejected page rolls back entirely; individual ingest handles quarantine; no auto repair |
| 10 Storage | Same SQLite WAL/FULL backend, bounded snapshots, writer and query equality tests | I05; Q04; F02; nominal campaign | One host/local filesystem; finite tests, no unlimited concurrency/HA |
| 11 Integrity | Export and restored material checked against external expected checkpoint | X01-X06; D01/D02; existing integrity tests | Detect relative to trusted anchor, not prevent deletion; compromised anchor remains outside guarantee |
| 12 Authorization | Scoped queries/cursors/diagnostics; physical backup needs reader+operator and one tenant | Q05; A01/A02; D03 | OS owner/shared key can access data; no SaaS multitenant boundary claimed |
| 13 Privacy | Existing allowlists retained; encrypted cursors; metadata-only pilot template | original privacy suite; I04; D02 | No real sensitive corpus; exports/metadata/backups require policy; template not deployed |
| 14 Input/files | Confirmed loose-permission/symlink DB acceptance fixed; bounded regular-file reads, FIFO rejection; SQL params | B03/B04; Q04; F03; X01/D04 | Trusted parent/OS; no archive importer or web interface; full penetration test not performed |
| 15 Operational config | Full validation, safe errors, no server; deployment/runbook and shutdown boundary | B05; F03; installed config check | Resource interference/audit backend not measured on an application host |
| 16 CI/attestation | Existing isolation preserved; added unprivileged install/optimized-test workflow | historical attestation tests, retained live TAR tests; new workflow definition | New 1.5 workflow not dispatched in this local round; no 1.5 signature or SLSA L3 claim |
| 17 Build/deps | Actual wheel/installed component inventory, dependency audit; vulnerable test installer updated | distribution audit; pip-audit before/after; two builds | Local EACP package unavailable to PyPI advisory lookup; native/OS advisories and full secret scanner not exhaustive |
| 18 Observability | Committed enqueue outcomes, source backlog/silence/completeness, separate health unknowns | O01/O02; burst/soak receipts | No alert transport; auth failures before store are not measured there; no live source-health proof |
| 19 Recovery | Consistent SQLite backup API, new-path restore, cursor recovery, current-anchor check | D01-D04; installed backup/restore | Keys/config external; additive schema only; no automatic downgrade or general migration recovery |
| 20 Load | Predeclared 3x2000 event runs, 200-event burst, 30-second short soak | campaign plan/raw latency CSV/summary | This is not a saturation curve to system limit, long soak or enterprise envelope |
| 21 Combined faults | Process exit at three commit/ACK points, replay/restart; SQLite page quota exhaustion and recovery | F01/F02; D01/D02; campaign burst | Simulated SQLite quota != physical disk failure; no partitions/node/power-loss test |
| 22 Export | Whole material anchor, expected query/config context, event proofs, recomputed result/completeness | Q01; X01-X06; installed offline negative | Offline snapshot trust, no online revocation/current-source truth; private export default |
| 23 Code/usability | Packaged Profile reuse, safe CLI errors, explicit configuration and resource contracts | scoped Ruff F/E9; Python -O tests; installed demo | Four pre-existing unused-code warnings retained in historical campaign/trust modules; no complete type proof |
| 24 Utility/comparator | Existing competent indexed comparison retained; no human-hours claim | historical index and correlation suites; existing pilot evaluator | New comparative organizational utility/cost experiment NOT PERFORMED |
| 25 Pilot | Existing unapproved one-service protocol kept; minimal audit template/runbook added | existing pilot-gate tests | BLOCKED for real collection by missing partner/permissions/data/security agreement |
| 26 Review evidence | New candidate freeze/package/checksums, old target pin, explicit reviewer blanks | candidate gate, fresh Git-bundle clone, package membership/hash checks | No favorable reviewer conclusion filled in or independent human identity certified |

## Claim -> evidence -> version -> conditions -> limits

| Claim allowed | Evidence | Version / conditions / limits |
|---|---|---|
| A new operator can run the documented synthetic CLI path without source edits | installed demo receipts and oracle | Software 1.5.0rc1; author-directed AI-assisted run in a fresh local environment, not another human |
| The three specified weakened checks were caught | actual mutation logs with assertion failures | Three specified mutants, never a universal test-quality score |
| Expected event IDs/content survived the declared replay/recovery cases | I/F/D tests, per-scenario campaign receipts | Synthetic local SQLite/fsync assumptions; no physical power-failure claim |
| Altered export or wrong query/config context is rejected | X tests, offline negative receipt | Exact external checkpoint/policy supplied; does not certify the authority |
| The historical source and negative cohorts remain unchanged | candidate preservation verifier, old tags/bundle | Metadata/runtime paths explicitly allowlisted; old paper/Profile bytes preserved |
| Known dependency advisories were addressed in the tested install | pip-audit JSON before/after | Pip installer update; PyPI did not audit this unpublished local EACP source |
| Public GitHub run/attempt/job mapping was executed against the provider | live read receipt | One pre-existing public run; no new signing run, Kubernetes run or provider reliability study |

Disallowed conclusions: no further criticism is possible; top-tier contribution
established; production-ready; source truth or causality authenticated; SLSA L3;
field utility/national importance/legal sufficiency proven; 208 scenarios passed;
independent external reviewer approved this candidate.

## Status vocabulary and retained failures

PASSED = an identified command/scenario met its declared expectation. Negative
rejection may be a passed test, but the underlying nonzero exit remains recorded.
FAILED = a command/scenario missed its expectation. BLOCKED = required external
authority/resource absent. NOT_PERFORMED = not run, regardless of code existence.
NOT_APPLICABLE = no such surface in this scope (public server/HTML UI, CSV export,
archive execution, cloud failover). None is interchangeable with PASSED.

Development retains: wrong initial adapter test directory (zero tests); invalid
inferred-link fixture rejected by the unchanged schema, then corrected; an
incomplete GitHub test fixture rejected by minimization, then corrected; initial
static findings; initial pip advisory findings. These are development executions,
not erased failures or pooled confirmatory success counts.

## Reviewer worksheet (leave conclusions to the reviewer)

- Historical target: ecfd42d4f54d2d91d18fcdddf676d822001b79f9.
- Pre-upgrade software: 5067a26ad008db3bc4b4a5554e52c60239142735.
- Candidate target: see package CANDIDATE.json exact commit/tree and SHA256SUMS.
- Files personally inspected: **not supplied**.
- Commands personally executed and environment: **not supplied**.
- Findings confirmed, disputed or not tested: **not supplied**.
- Residual limitations/conclusion/signature: **not supplied**.

The reviewer can do a focused assessment within the agreed scope. This is not a
request to endorse a predetermined conclusion or a claim they reran the suite.
