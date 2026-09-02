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
eacp/profile_records.jsonl              normative eacp.profile/1.3 records
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
Current schema identifiers resolve through the public candidate branch. The
checksum-bound run artifacts retain the prospective `v1.3.0` identifiers that
were emitted at execution time; the verifier accepts those historical values
without rewriting or weakening their manifests.
Normative profile records are also passed through
`spec/tools/eacp_profile.py`. GitHub records distinguish `initiator`,
`triggering_actor`, and the `github-actions` execution principal. Kubernetes
records distinguish the authenticated initiator from an impersonated
service-account execution principal when the audit event supplies both.

Profile records carry scoped, typed `operational_correlation`, `workflow_run`,
`vcs_revision`, and (when configured) `artifact_digest` links. Kubernetes may
also emit `deployment_uid`. The operational link is `explicit` on the GitHub
side because the adapter binds it; it is `source_native` on Kubernetes records
only when the API object/audit body actually carries the annotation. The flat
CSV remains a compatibility projection and is not presented as the normative
multilink representation.

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

python3 spec/tools/eacp_profile.py validate \
  /tmp/eacp-github-run/eacp/profile_records.jsonl
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
7. Attempt a patch against that exact Deployment while impersonating the
   read-only `eacp-observer` service account, and require a Kubernetes
   `Forbidden` result. If authorization rejects before decoding the patch body,
   bind the 403 by exact API group/resource/namespace/name and label the result
   adapter-explicit—not source-native correlation.
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
kind binary checksum, kind node image, matching kubectl binary, and workload
image by commit or digest. For manually selected or evidence-tag-selected
Kubernetes v1.34.8, v1.35.5, or v1.36.1, the runner fails unless kubectl
client, API server, and kubelet all report the exact selected version.
The complete API-server audit log remains in transient runner storage. Only the
namespace-filtered, sanitized subset is uploaded.

### Three controlled rerun attempts

The frozen earlier evaluation pushed the candidate branch once and then used
GitHub's **Re-run all jobs** twice. It produced attempts 1, 2, and 3 under one
run ID, with three distinct correlation IDs because `run_attempt` participates
in the key. All three artifacts and attestation verification outputs were
preserved and validated individually.

These are procedural reruns, not independent replications. They share one
repository, source revision, workflow, GitHub-hosted runner class, and protocol;
each creates a fresh ephemeral single-node kind cluster. A separate manual
dispatch can select checksum-pinned Kubernetes v1.34.8, v1.35.5, or v1.36.1 to
produce a new workflow-run ID. Those separate runs still do not constitute a
field deployment or third-party reproduction.

### Prospective separate-run cross-version cohort

The machine-readable
[`cross_version_protocol_plan_v1.3.json`](cross_version_protocol_plan_v1.3.json)
was added before execution. Branch pushes no longer trigger this evidence
workflow, so committing the protocol cannot create an unplanned preview run. It
predeclares a balanced 3×3 cohort: three exact
evidence tags for each of Kubernetes v1.34.8, v1.35.5, and v1.36.1, all pointing
to the same protocol commit. The tags are triggered in round-robin order by
replicate. Each produces a distinct workflow-run ID while holding the workflow,
kind binary, workload, subject digest, resolver, controls, and hosted-runner
class constant. Exact node images and matching kubectl checksums are centralized
in [`kubernetes_targets_v1.3.json`](kubernetes_targets_v1.3.json).

The first attempt for every tag is retained whether it succeeds or fails. A
failure must not be silently replaced by a rerun. Because GitHub's
`run_attempt=1` means the first attempt of one run ID—not necessarily the first
invocation of a reused tag—the capture also queries the exact workflow/tag pair
and fails unless it finds exactly one invocation at capture time. The minimized
query observation is checksum-bound as `tag_invocation.json`; it is public API
evidence, not a signed API response. After a successful completion, capture the
evidence and fresh cryptographic verification with:

```bash
bash experiments/github_actions/capture_completed_run_v1_3.sh \
  RUN_ID /path/to/cross-version-cohort-v1.3/run-RUN_ID
```

If the first attempt does not succeed or produces no evidence artifact, freeze
its canonical run identity and minimized job/step outcome instead:

```bash
python3 experiments/github_actions/capture_run_outcome_v1_3.py \
  --run-id RUN_ID \
  --protocol-commit EXACT_40_HEX_COMMIT \
  --output-dir /path/to/cross-version-cohort-v1.3/run-RUN_ID
```

The outcome capturer stores no raw logs, tokens, or runner identifiers. It
retains only allowlisted version-validation and lifecycle-failure messages,
plus the SHA-256 and byte count of the complete failed-step log. The diagnostic
explicitly remains an unauthenticated public-log observation and never converts
a failed run into partial success. The exact-tag invocation observation,
minimized failure record, and diagnostic are checksum-bound and included in the
cohort rather than substituting a later run.

The aggregate verifier requires nine distinct run IDs, three first attempts per
version, one shared source commit, one observed exact-tag invocation per member,
exact client/server/kubelet versions, all controls, nested checksums, and fresh
offline attestation verification of each successful in-run TAR. The
three runs per version are descriptive procedural repetitions—not inferential
samples. This remains a compatibility/sensitivity cohort, not a production
reliability estimate, field deployment, cross-provider study, or external
replication.

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
rewrites the original runtime evidence. This completed-state recapture is
checksum-bound and identity-validated, but it is created after the original
workflow and is therefore not part of that workflow's builder-attested TAR.

At capture time, verify the GitHub attestation twice against the downloaded TAR
and exact repository/workflow/source constraints. The first pass uses GitHub
CLI's default trust configuration; the second uses a captured root for later
offline replay:

```bash
gh attestation verify eacp-cross-plane-v1.3-RUN-ATTEMPT.tar.gz \
  --bundle sha256-ARCHIVE_DIGEST.jsonl \
  --repo OWNER/REPOSITORY \
  --signer-workflow OWNER/REPOSITORY/.github/workflows/eacp-cross-plane-v1.3.yml \
  --signer-digest EXACT_COMMIT_SHA \
  --source-digest EXACT_COMMIT_SHA \
  --source-ref refs/tags/EXACT_EVIDENCE_TAG \
  --deny-self-hosted-runners

gh attestation trusted-root --hostname github.com > trusted_root.jsonl
gh attestation verify eacp-cross-plane-v1.3-RUN-ATTEMPT.tar.gz \
  --bundle sha256-ARCHIVE_DIGEST.jsonl \
  --custom-trusted-root trusted_root.jsonl \
  --repo OWNER/REPOSITORY \
  --signer-workflow OWNER/REPOSITORY/.github/workflows/eacp-cross-plane-v1.3.yml \
  --signer-digest EXACT_COMMIT_SHA \
  --source-digest EXACT_COMMIT_SHA \
  --source-ref refs/tags/EXACT_EVIDENCE_TAG \
  --deny-self-hosted-runners
```

The captured root makes later verification reproducible offline relative to
those root bytes; it does not authenticate itself. The default-trust pass is the
capture-time external trust bootstrap, and a reviewer may repeat that pass
online against the current authenticated trust configuration.

## Run the protocol outside GitHub

The runner also supports a completed historical run when the local checkout is
exactly that run's commit. It requires Docker, kind 0.32.0, kubectl, `gh`,
Python, and `shasum`. It will refuse to replace an existing kind cluster.

```bash
EACP_REPOSITORY=OWNER/REPOSITORY \
EACP_RUN_ID=RUN_ID \
EACP_EXPECTED_KUBERNETES_VERSION=v1.36.1 \
KIND_NODE_IMAGE=kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5 \
RESULTS_DIR=/tmp/eacp-cross-plane-result \
bash experiments/github_actions/run_cross_plane_v1_3.sh
```

The local `kubectl` must be the matching checksum-pinned binary in
`kubernetes_targets_v1.3.json`; the runner rejects client, server, or kubelet
version skew and rechecks the requested version/image pair against that
committed allowlist.

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
linking, the no-ID negative control, and the target-bound adapter-explicit RBAC
denial.

## Frozen public validation

Validated locally in this repository:

- 13 deterministic tests on Python 3.11;
- shell syntax for the runners;
- authenticated, read-only capture and checksum verification of public run
  `31075453078`;
- three EACP rows from that completed run: one workflow and two jobs;
- no tokens, logs, event payloads, artifact contents, commit messages, author
  emails, or runner identities retained in the frozen capture.

The live protocol then completed three public attempts under run
[`33682116347`](https://github.com/obedebessa/eacp-operational-provenance/actions/runs/33682116347),
all at commit `76b2ed54381ae52cf0f54cd22a20341c3216b77b`. In every attempt:

- the completed capture produced three GitHub records;
- eight Kubernetes audit records carried the source-native correlation
  annotation, and the normalized projection contained nine matching records
  after one target-bound HTTP 403 was added as an explicit adapter assertion;
- the Deployment, Pod specification, and runtime image ID matched the declared
  OCI subject digest exactly;
- three audit records for the no-ID negative-control object remained unjoined;
- one HTTP 403 from the expected service account targeted the exact correlated
  Deployment; its audit record contained no source-native correlation and is
  labeled `adapter_explicit_exact_target`;
- archive checksums and nested public manifests verified; and
- the downloaded SLSA provenance attestation verified against the repository,
  signer workflow, source revision and Git ref, with self-hosted runners denied.

The namespace corpus varied from 51 to 56 records because controller activity
is asynchronous; the declared controls remained invariant. The exact
downloaded artifacts, completed-state recaptures, offline attestation bundles,
aggregate summary, and 98-entry checksum inventory are frozen under
`results/reference/run-33682116347/`. Run:

```bash
python3 experiments/github_actions/summarize_reference_run.py --verify
```

These executions demonstrate repeatability of one controlled workflow and an
ephemeral single-node cluster. They do not establish causal correctness,
production reliability, managed-cluster behavior, or source truth.
