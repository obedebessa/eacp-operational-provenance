# Prospective external replication protocol — EACP 1.3

Status: prospective protocol, 2026-09-02. No external replication result is
claimed. This protocol is published so an independent operator can report a
success, partial result, or failure without changing the acceptance criteria
after seeing the outcome.

## Replication question

Can an operator other than the author, using a fresh repository fork and a
fresh Kubernetes environment, reproduce the declared exact-link, no-ID
abstention, adapter-explicit denial, OCI-digest, checksum, and attestation
properties without modifying the resolver or expected outcomes?

## Independence tiers

Report exactly one tier; do not collapse them.

| Tier | Minimum separation | What it establishes |
|---|---|---|
| R1 — external operator | Different person/account; fresh fork; GitHub-hosted runner; ephemeral kind cluster | Independent procedural reproduction by another operator. |
| R2 — external environment | R1 plus a different CI provider, managed Kubernetes service, or independently provisioned cluster | Portability across an additional execution environment. |
| R3 — field case | R2 plus naturally occurring delivery/runtime records for an actual service and its governance constraints | Field relevance for that case only. |

The current author-run evidence satisfies none of these tiers.

## Frozen inputs

Before execution, record:

- candidate commit SHA;
- fork URL and workflow path;
- operator identity or a stable pseudonymous identifier;
- selected Kubernetes version and node/cluster implementation;
- whether any source, adapter, schema, resolver, or acceptance criterion changed;
- UTC start time; and
- SHA-256 of a preserved pre-run `replication-report.preregistered.json`.

Use `replication-report.template.json` without deleting fields. Any necessary
change must be declared before the run and makes the result a modified
replication rather than an exact replication.

To avoid a circular self-digest, fill the frozen inputs, leave
`pre_run.preregistered_report_sha256` as `null`, and save that immutable file as
`replication-report.preregistered.json`. Hash its exact bytes into the sidecar
`replication-report.preregistered.json.sha256`. After execution, copy it to
`replication-report.json` and set `pre_run.preregistered_report_sha256` in the
completed copy to the sidecar digest. Preserve all three files. The hash names
the pre-run file; it is not a hash of the completed report containing itself.

## Procedure

1. Fork the repository and create a branch pointing exactly to the pinned
   candidate commit, with no content changes. Because GitHub exposes
   `workflow_dispatch` only for workflows present on the fork's default branch,
   temporarily make that exact branch the fork's default branch before the
   manual dispatch. Record the branch name and confirm its tree and commit SHA
   still equal the pinned candidate.
2. Run all local profile, adapter, correlation, ablation, and repository tests.
3. Enable Actions and manually dispatch `eacp-cross-plane-v1.3.yml` once for the
   predeclared Kubernetes profile. Do not dispatch from a branch whose tree
   differs from the pinned candidate.
4. Do not rerun a failed job until its first-run artifact and logs have been
   retained and the failure classification has been recorded.
5. Download the complete artifact and the attestation bundle.
6. Run `finalize_cross_plane_v1_3.sh` only after GitHub reports the run complete.
7. Verify nested SHA-256 manifests and the attestation offline, constraining the
   fork repository, signer workflow, source digest, source ref, and hosted-runner
   policy.
8. Populate the report with observed counts and Boolean outcomes. Do not replace
   failed or missing values with expected values.
9. Publish the report, manifests, minimized source snapshots, sanitized
   namespace audit subset, and exact commands. Do not publish credentials,
   kubeconfigs, tokens, full unrelated audit logs, or private source payloads.

## Predeclared primary criteria

An exact replication is successful only if all criteria hold:

1. every required test suite passes without source modification;
2. completed GitHub evidence contains the workflow, job, and uploaded artifact;
3. at least one retained raw Kubernetes audit record contains the exact
   workflow-generated annotation and the strict join accepts the positive chain;
4. the present no-ID control has retained audit evidence and remains unjoined;
5. the denied request returns HTTP 403 for the exact declared
   group/resource/namespace/name/principal tuple and is labeled
   `adapter_explicit_exact_target`, never `source_native`;
6. Deployment image, Pod specification, and runtime image ID match the declared
   OCI digest as a separate check;
7. every public and aggregate SHA-256 manifest verifies; and
8. the downloaded SLSA provenance bundle verifies offline for the exact archive
   under the declared identity constraints.

Report partial success when only a subset holds. Report failure when the run
does not complete or evidence is insufficient to evaluate a criterion. A
failure remains a reportable result and must not be silently replaced by a
rerun.

## Interpretation rules

- The correlation key is introduced by the workflow. Passing criterion 3 tests
  propagation and exact composition, not discovery of a naturally occurring
  identifier.
- “Source-native” means the retained raw Kubernetes audit record contains the
  annotation; it does not mean the identifier originated independently.
- Zero false joins in the synthetic matrix is not a live-system guarantee.
- OCI digest agreement is orthogonal corroboration, not the correlation join.
- Attestation verification authenticates a builder statement and archive bytes,
  not the semantic truth or completeness of source events.
- An R1 result is not a field result, and no result from this protocol alone
  establishes production effectiveness or generality.

## Submission

Open a pull request containing the completed report and safe evidence, or send
the report digest and public archive location to the author. The author must
preserve negative findings, identify the replication tier, and obtain explicit
permission before naming or quoting the operator.
