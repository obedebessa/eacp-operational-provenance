# EACP 1.3 evidence brief

Status: reviewer candidate, 2026-09-02. This is a concise audit map, not a
peer-reviewed result or archival release. No v1.3 DOI has been minted.

## Bottom line

EACP 1.3 now contains a preserved failure followed by a prospectively bounded
confirmation. The original cross-version protocol at commit
[`15d72da`](https://github.com/obedebessa/eacp-operational-provenance/tree/15d72da095a0c7640b9318b50b28728e76d68928)
produced nine first-attempt failures and 0/9 runs satisfying all predeclared
criteria. All nine
reached exact Kubernetes client/API-server/kubelet version validation, then
terminated at the same premature lifecycle assertion: it required the
completed-run artifact while the workflow was still executing, before GitHub
could create that artifact.

A narrow amendment was committed prospectively at direct child
[`4cbf7d2`](https://github.com/obedebessa/eacp-operational-provenance/tree/4cbf7d2fa0bb44585d258a3f37ce0c0d39ddea43).
Its sole scientific acceptance-logic change relocated that artifact-dependent
three-row check to completed-run finalization. It also added the predeclared tag
allowlist and capture, summary, test, and verification support without changing
the workload, controls, join semantics, target pins, subject, or scientific
acceptance criteria. It allocated new, separately named tags `run-04` through
`run-06`. At capture time, the
public API returned exactly one matching workflow invocation for each tag; this
is an observation, not a guarantee against later tag mutation. The confirmatory
cohort achieved 9/9 first-attempt workflow successes and 9/9 runs satisfying all
predeclared criteria:
3/3 on each of Kubernetes v1.34.8, v1.35.5, and v1.36.1, across nine distinct
public run IDs and nine distinct successful correlation IDs.

The initial failures remain failures. They were neither rerun nor replaced, and
the two generations are not pooled. Neither is pooled with the earlier three
rerun attempts of public run
[`33682116347`](https://github.com/obedebessa/eacp-operational-provenance/actions/runs/33682116347).

## Evidence progression

| Generation | Frozen design | Outcome | Interpretation |
|---|---|---|---|
| Earlier live run | One run ID, three rerun attempts | 3/3 successful attempts | Controlled pilot only; reported separately. |
| Initial cross-version cohort | Commit `15d72da`; tags `run-01..03`; three first attempts per version | 0/9 runs satisfied all predeclared criteria; nine preserved failures | Harness lifecycle defect after exact version validation; not evidence that end-to-end criteria passed. |
| Prospective amendment | Direct child `4cbf7d2`; tags `run-04..06` | Correction frozen before execution | Artifact-dependent assertion moved to completed-state finalization; scientific inputs, controls, join semantics, target pins, and subject unchanged. |
| Confirmatory cross-version cohort | Commit `4cbf7d2`; three new first attempts per version | 9/9 workflow success; 9/9 runs satisfied all predeclared criteria | Descriptive controlled compatibility and procedural repetition only. |

## Public run matrix

| Kubernetes | Initial first attempts — preserved failures | Confirmatory first attempts — all predeclared criteria satisfied |
|---|---|---|
| v1.34.8 | [33689275761](https://github.com/obedebessa/eacp-operational-provenance/actions/runs/33689275761), [33689284057](https://github.com/obedebessa/eacp-operational-provenance/actions/runs/33689284057), [33689294904](https://github.com/obedebessa/eacp-operational-provenance/actions/runs/33689294904) | [33690426246](https://github.com/obedebessa/eacp-operational-provenance/actions/runs/33690426246), [33690432444](https://github.com/obedebessa/eacp-operational-provenance/actions/runs/33690432444), [33690438222](https://github.com/obedebessa/eacp-operational-provenance/actions/runs/33690438222) |
| v1.35.5 | [33689279446](https://github.com/obedebessa/eacp-operational-provenance/actions/runs/33689279446), [33689287000](https://github.com/obedebessa/eacp-operational-provenance/actions/runs/33689287000), [33689291864](https://github.com/obedebessa/eacp-operational-provenance/actions/runs/33689291864) | [33690427562](https://github.com/obedebessa/eacp-operational-provenance/actions/runs/33690427562), [33690433602](https://github.com/obedebessa/eacp-operational-provenance/actions/runs/33690433602), [33690440169](https://github.com/obedebessa/eacp-operational-provenance/actions/runs/33690440169) |
| v1.36.1 | [33689281853](https://github.com/obedebessa/eacp-operational-provenance/actions/runs/33689281853), [33689288013](https://github.com/obedebessa/eacp-operational-provenance/actions/runs/33689288013), [33689302997](https://github.com/obedebessa/eacp-operational-provenance/actions/runs/33689302997) | [33690429641](https://github.com/obedebessa/eacp-operational-provenance/actions/runs/33690429641), [33690436849](https://github.com/obedebessa/eacp-operational-provenance/actions/runs/33690436849), [33690443082](https://github.com/obedebessa/eacp-operational-provenance/actions/runs/33690443082) |

## What the 9/9 confirmation checks

Each successful member passed the same predeclared controls and completed-state
verification:

- exact requested kubectl client, API-server, and kubelet version;
- positive raw Kubernetes audit evidence retaining the workflow-generated key;
- a present no-ID control remaining unjoined;
- one exact-target HTTP 403 labeled adapter-explicit, with no source-native
  operational correlation;
- Deployment image, Pod specification, and runtime image ID matching the pinned
  OCI digest as a separate check;
- exactly three completed GitHub evidence rows, enforced only after artifact
  creation; and
- nested checksums, TAR/tree parity, and the stated attestation-policy checks.

The joining key was generated by the workflow and planted in the positive
Kubernetes annotations. “Source-native” therefore means the retained raw audit
record contains that injected annotation; it does not mean the identifier arose
independently. The experiment evaluates controlled propagation and exact
composition, not identifier discovery.

## Integrity and trust boundary

The GitHub build-provenance attestation names only the in-run TAR from each
successful workflow as its subject. The local completed-state finalization adds the post-run GitHub artifact row and
other completed metadata; it is checksum-bound and cross-checkable against the
public GitHub API, but it is not builder-attested.

Capture-time verification through GitHub CLI's built-in GitHub/Sigstore trust
configuration passed for all nine TARs. Each successful bundle also retains the
trusted-root bytes used for offline re-verification; that captured copy is not
self-authenticating. Attestation
authenticates the stated builder and archive bytes under the policy; it does not
establish the semantic truth, completeness, or causality of source events.

Because the initial runs failed before artifact creation, their minimized API
metadata and two exact failure-log markers were captured locally and
checksum-bound. Neither retained capture is an origin-signed response; the full
log is represented only by its digest and byte count.

## What this does not establish

Both cross-version generations use the same repository, provider, workflow
family, GitHub-hosted runner class, and ephemeral single-node kind design. They
do not establish field utility, managed-cluster or multi-node behavior,
cross-provider generalization, independent-organization corroboration, external
reproduction, inferential reliability, production failure rates, or discovery
of naturally occurring identifiers. No confidence interval is claimed from
three within-version procedural repetitions.

## Audit path

Start with the [reviewer guide](REVIEWER_GUIDE_v1.3.md) and
[claim ledger](CLAIMS_AND_EVIDENCE_v1.3.md). The frozen generations are under:

- `experiments/github_actions/results/reference/cross-version-initial-failed-cohort-v1.3/`
- `experiments/github_actions/results/reference/cross-version-confirmatory-cohort-v1.3/`

The branch remains a candidate. The v1.2 DOI and citation metadata do not archive
these v1.3 results.
