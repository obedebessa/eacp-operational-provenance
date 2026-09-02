# GitHub Actions → Kubernetes operational provenance (EACP v1.3)

This experiment adds GitHub Actions as a real evidence emitter and defines a
controlled, auditable hand-off to Kubernetes. It preserves the original
13-column EACP projection while adding a versioned source snapshot and a link
report for relationships that do not fit in a single evidence row.

The key identifier is deterministic and attempt-specific:

```text
eacp-gha-<repository_id>-<run_id>-<run_attempt>
```

The workflow places that value in GitHub evidence and in the Kubernetes
`eacp.io/correlation-id` annotation. It also links both sides to an immutable
OCI subject:

```text
registry.k8s.io/pause@sha256:ee6521f290b2168b6e0935a181d4cff9be1ac3f505666ef0e3c98fae8199917a
```

Exact identifier equality is the join rule. No time-window or name-based
inference is silently substituted when the identifier is absent.

## What is evidence, and what is not

Two different artifacts live here and must not be conflated:

- `corpus/github-public-run-31075453078/` is a frozen capture of a real,
  completed, public GitHub Actions run. Its summary correctly says
  `patch_generated_not_observed`: the historical run was not part of the new
  Kubernetes experiment.
- `tests/fixtures/` contains invented records solely for deterministic unit
  tests. Fixtures are not empirical observations and are never described as
  real emissions.
- `.github/workflows/eacp-cross-plane-v1.3.yml` is the protocol that creates a
  causal run and a real isolated kind/Kubernetes observation. Its outputs
  become empirical evidence only after that workflow actually executes.

The join report uses three statuses:

- `no_matching_kubernetes_evidence_observed`: no exact Kubernetes match;
- `observed_cross_plane_link`: the identifier was observed on both planes;
- `observed_cross_plane_link_with_subject_digest`: the identifier, OCI subject
  annotations, and the Deployment image reference all match exactly.

Even the strongest status demonstrates an observable, controlled hand-off. It
does not by itself prove semantic causality, authorization correctness outside
the tested operation, or bit-for-bit identity of an arbitrary application
artifact.

## Adapter outputs

Every GitHub bundle is written atomically and contains:

```text
source/github_actions.json              minimized source snapshot
eacp/evidence.csv                       compatible 13-column projection
eacp/evidence.jsonl                     schema-linked projection
kubernetes/annotation_merge_patch.json  hand-off patch, not an observation
summary.json                             scope and claim boundary
SHA256SUMS                              exact bundle manifest
```

The snapshot retains run ID and attempt, repository ID/name, actor and
triggering actor, commit SHA, workflow, jobs, timestamps, source URLs, and
artifact metadata. It deliberately excludes logs, artifact contents, event
payloads, commit messages and author emails, runner identifiers, URL query
parameters, and credential-like fields. Private repositories require the
explicit `--allow-private` acknowledgement and still require manual review
before publication.

The JSON Schemas are under `schema/`. Runtime verification does not require a
third-party JSON Schema package: it checks SHA-256 manifests and regenerates
the CSV, JSONL, summary, and Kubernetes patch from the minimized source.

## Capture a completed public run

Python 3.10 or newer is sufficient. With an authenticated GitHub CLI, the
adapter uses `gh api`; otherwise `--transport public-http` uses GitHub's
unauthenticated public REST endpoint.

```bash
python3 experiments/github_actions/eacp_gha_v1_3.py capture \
  --repo OWNER/REPOSITORY \
  --run-id RUN_ID \
  --output-dir /tmp/eacp-github-run \
  --transport auto

python3 experiments/github_actions/eacp_gha_v1_3.py verify \
  --bundle /tmp/eacp-github-run
```

This operation is read-only. It never dispatches, reruns, cancels, or modifies
a workflow.

## Offline API import and Actions-artifact import

Exported REST responses can be normalized without a network connection:

```bash
python3 experiments/github_actions/eacp_gha_v1_3.py import-api \
  --run-json run.json \
  --jobs-json jobs.json \
  --artifacts-json artifacts.json \
  --output-dir /tmp/eacp-imported-run
```

An import is labeled
`imported_api_metadata_authenticity_not_established_by_adapter`; the adapter
cannot infer that arbitrary input JSON came from GitHub.

To regenerate a bundle from the downloaded workflow artifact ZIP, extracted
artifact directory, or its `source/github_actions.json`:

```bash
python3 experiments/github_actions/eacp_gha_v1_3.py import-artifact \
  --artifact eacp-cross-plane-v1.3-RUN-ATTEMPT.zip \
  --output-dir /tmp/eacp-imported-artifact
```

ZIP paths are validated before extraction and path traversal is rejected.

## Real cross-plane protocol

The v1.3 workflow is intentionally isolated. It runs only on a push to the
`eacp-v1.3-candidate` branch or by manual dispatch after the workflow exists on
the default branch. It does not deploy to an external cluster and needs no
cloud credentials.

The workflow performs the following sequence:

1. Read its own GitHub REST metadata with the job-scoped token.
2. Require the checked-out commit to equal the API-reported `head_sha`.
3. Derive the attempt-specific correlation ID.
4. Start a single-node kind cluster with API-server audit enabled only for the
   controlled namespace and non-secret resource types.
5. Create a Deployment whose metadata, Pod template, and pinned image carry the
   correlation ID, Git commit, run identity, and OCI subject digest.
6. Create `negative-control-no-correlation` without the correlation annotation.
7. Attempt a correlated Deployment patch while impersonating the read-only
   `eacp-observer` service account and require a Kubernetes `Forbidden` result.
8. Sanitize and project Kubernetes audit evidence, then fail closed unless the
   positive match, negative control, and HTTP 403 record all exist.
9. Capture distinct GitHub actor, triggering actor, Kubernetes administrative
   principal, and denied service-account principal.
10. Generate and verify the exact-ID/digest cross-plane link report.
11. Produce stable checksums, a deterministic tar archive, and a GitHub build
    provenance attestation for that archive.

The attestation binds the archive digest to the workflow identity. It protects
artifact integrity and builder provenance; it does not certify the semantic
truth of GitHub or Kubernetes source events.

The workflow pins checkout, Python setup, artifact upload, attestation action,
kind binary checksum, kind node image, and workload image by commit or digest.
The complete API-server audit log remains in transient runner storage. Only the
namespace-filtered, sanitized subset is uploaded.

### Three independent attempts

For the intended evaluation, push the candidate branch once and then use
GitHub's **Re-run all jobs** twice. This produces attempts 1, 2, and 3 under one
run ID, with three distinct correlation IDs because `run_attempt` participates
in the key. Preserve all three artifacts and attestation verification outputs;
do not pool them until each individual bundle validates.

The initial branch run is possible before merging because `push` is restricted
to `eacp-v1.3-candidate`. No workflow has been dispatched by the adapter or by
the preparation of this repository.

### Why post-run finalization exists

A workflow cannot query its own final conclusion or its just-uploaded artifact
before it finishes. The in-run bundle is still valid and is what drove the
Kubernetes chain, but its GitHub status may be `in_progress`. After downloading
and extracting the artifact, close the observation with:

```bash
bash experiments/github_actions/finalize_cross_plane_v1_3.sh \
  /path/to/extracted/eacp-results \
  /tmp/eacp-finalized-attempt
```

The finalizer first verifies every original public checksum. It then performs a
new read-only API capture, requires the same run attempt and correlation ID,
requires GitHub status `completed`, captures the now-visible workflow artifact
metadata, regenerates the join report against the already checksummed
Kubernetes evidence, and writes a separate finalization manifest. It never
rewrites the original runtime evidence.

Verify the GitHub attestation separately against the downloaded tar archive:

```bash
gh attestation verify eacp-cross-plane-v1.3-RUN-ATTEMPT.tar.gz \
  --repo OWNER/REPOSITORY
```

## Run the protocol outside GitHub

The runner also supports a completed historical run when the local checkout is
exactly that run's commit. It requires Docker, kind 0.32.0, kubectl, `gh`,
Python, and `shasum`. It will refuse to replace an existing kind cluster.

```bash
EACP_REPOSITORY=OWNER/REPOSITORY \
EACP_RUN_ID=RUN_ID \
RESULTS_DIR=/tmp/eacp-cross-plane-result \
bash experiments/github_actions/run_cross_plane_v1_3.sh
```

Cluster deletion is limited to the unique cluster created by the runner. Set
`KEEP_CLUSTER=1` to retain it. A caller-supplied `WORK_DIR` is never removed by
the cleanup handler.

## Join against separately captured Kubernetes evidence

The existing Kubernetes normalizer emits compatible correlation IDs. Given its
CSV and an object snapshot:

```bash
python3 experiments/github_actions/eacp_gha_v1_3.py join \
  --bundle /tmp/eacp-github-run \
  --kubernetes-evidence-csv normalized_evidence.csv \
  --kubernetes-object-json deployment.json \
  --negative-control-object-json negative_control.json \
  --kubernetes-pods-json pods.json \
  --output /tmp/cross-plane-join.json
```

The comparison is exact. A near match remains a miss, and a missing ID remains
missing; this command does not invent a join.

## Tests

```bash
python3 -m compileall -q experiments/github_actions
python3 -m unittest discover -s experiments/github_actions/tests -v
```

The committed tests cover deterministic projection, source minimization,
checksum tamper detection, private-source guardrails, ZIP traversal rejection,
non-mutating annotation planning, exact and near-miss joins, subject-digest
linking, the no-ID negative control, and the correlated RBAC denial.

## Current validation boundary

Validated locally in this repository:

- 12 deterministic tests on Python 3.11;
- shell syntax for the runners;
- authenticated, read-only capture and checksum verification of public run
  `31075453078`;
- three EACP rows from that completed run: one workflow and two jobs;
- no tokens, logs, event payloads, artifact contents, commit messages, author
  emails, or runner identities retained in the frozen capture.

Not yet established until the candidate workflow executes externally:

- a real GitHub Actions → Kubernetes observation from the same causal run;
- three successful attempts;
- observed subject-digest equality in the real Deployment and Pod;
- the runtime `status.containerStatuses[].imageID`, reported separately because
  container runtimes may resolve the pinned manifest-list digest to a distinct
  platform-manifest digest;
- a real negative-control audit trace and correlated HTTP 403 trace;
- the archive's GitHub-hosted attestation and completed post-run API capture.

Docker was unavailable in the local preparation environment, so the real kind
portion was not represented as having run. That limitation is explicit rather
than filled with fixture output.
