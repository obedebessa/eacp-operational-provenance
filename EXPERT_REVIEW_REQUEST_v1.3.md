# Expert review request — EACP 1.3 candidate

Status: copy-ready reviewer outreach, 2026-09-02. This candidate has not
undergone peer review and has no v1.3 DOI.

## Suggested subject

Request for critical review and reproduction: EACP 1.3 operational provenance

## Copy-ready message

Dear [Name],

I am seeking a critical technical review of EACP 1.3, a reviewer-candidate
preprint and public artifact about reconstructing operational transitions across
software-delivery and runtime-control planes.

The bounded contribution is a domain-specific evidence profile plus a
materialized retrieval index. The candidate composes GitHub Actions and
Kubernetes records separately emitted by two systems within one deliberately
orchestrated operation through exact typed and scoped links,
retains native evidence pointers, and abstains when the selected link is absent
or structurally ambiguous. It does not claim causal inference, source truth,
production readiness, or replacement of SLSA/in-toto, Sigstore, tracing, SIEM,
or authoritative source systems.

The new evaluation includes:

- 2,250 deterministic adversarial-correlation trials spanning missing, wrong,
  reused, duplicated, delayed, reordered, and clock-skewed identifiers;
- a paired four-treatment SQLite index ablation with 19,200 row-equivalence
  checks across warm and cold-open queries; and
- a preserved failed generation from a prospectively committed cross-version
  protocol, followed by a bounded confirmation across Kubernetes v1.34.8,
  v1.35.5, and v1.36.1.

The initial balanced 3-by-3 cohort at commit `15d72da` preserved nine distinct
first-attempt failures and 0/9 runs satisfying all predeclared criteria. Every run reached exact
client/API-server/kubelet version validation, then stopped at the same premature
lifecycle assertion: the running job requested a completed-run artifact before
GitHub could create it. A narrow amendment was frozen before further execution
at direct-child commit `4cbf7d2`. Its sole scientific acceptance-logic change
relocated that artifact-dependent check to completed-state finalization. It also
added the predeclared tag allowlist and capture, summary, test, and verification
support without changing the workload, controls, join semantics, target pins,
subject, or scientific acceptance criteria. The confirmatory cohort achieved
9/9 first-attempt workflow successes and 9/9 runs satisfying all predeclared
criteria, 3/3 per Kubernetes version, across nine distinct public run
IDs and nine distinct successful correlation IDs. The failed generation remains
separate and is not pooled with the confirmation or with an earlier three-
attempt public run.

The workflow generated the correlation key and planted it in the positive
Kubernetes annotations. The study therefore evaluates controlled propagation
and exact composition, not identifier discovery. “Source-native” means that a
retained raw audit record contains the injected annotation, not that the key
arose independently. The present no-ID control remained unjoined; the HTTP 403
association is adapter-explicit rather than source-native; and OCI digest
verification is separate. Both cross-version generations use the same
repository, provider, workflow family, hosted-runner class, and ephemeral
single-node kind design. No field or managed-cluster deployment, external or
independent-organization reproduction, cross-provider generalization,
inferential reliability, or production failure rate is claimed.

The GitHub build-provenance attestation names only the in-run TAR from each
successful workflow as its subject. Local completed-state finalization is
checksum-bound and cross-checkable against the public GitHub API, but is not
builder-attested. Capture-time verification using GitHub CLI's built-in trust
configuration passed for all nine TARs; the captured root enables offline
re-verification relative to captured bytes but is not self-authenticating.
Initial-cohort minimized API metadata and failure-log markers were locally
captured and checksum-bound; neither retained capture is an origin-signed
response. Zero false joins in the synthetic
campaign remains conditional on the declared invariants.

I would value a skeptical assessment rather than an endorsement. In particular:

1. Does the manuscript distinguish its operational-provenance scope clearly
   enough from supply-chain attestations, tracing, and general provenance?
2. Do the identifier-failure experiment and resolver abstention policy support
   the stated safety and coverage claims without overclaiming?
3. Which limitation or missing comparison most weakens the contribution as
   currently framed?
4. Is the failed-generation preservation and direct-child corrective amendment
   sufficiently narrow and auditable?

A 10–15 minute path is available in the reviewer guide, and all headline claims
map to frozen machine-readable evidence. If you reproduce any check, find a
contradiction, or identify a claim boundary that should be narrower, even a
brief note would be extremely useful. I will not quote or identify you publicly
without separate permission.

Paper:
<https://github.com/obedebessa/eacp-operational-provenance/blob/eacp-v1.3-candidate/paper/EACP_preprint_v1.3_candidate.pdf>

Reviewer guide:
<https://github.com/obedebessa/eacp-operational-provenance/blob/eacp-v1.3-candidate/REVIEWER_GUIDE_v1.3.md>

Evidence brief and complete public run matrix:
<https://github.com/obedebessa/eacp-operational-provenance/blob/eacp-v1.3-candidate/EVIDENCE_BRIEF_v1.3.md>

Initial protocol commit:
<https://github.com/obedebessa/eacp-operational-provenance/tree/15d72da095a0c7640b9318b50b28728e76d68928>

Prospective direct-child amendment:
<https://github.com/obedebessa/eacp-operational-provenance/tree/4cbf7d2fa0bb44585d258a3f37ce0c0d39ddea43>

Earlier public live run, reported separately:
<https://github.com/obedebessa/eacp-operational-provenance/actions/runs/33682116347>

Thank you for considering it,

Obede Bessa Rocha da Silva

## Fast review path for the recipient

1. Read `EVIDENCE_BRIEF_v1.3.md`, then the contribution boundary, empirical
   results, threats to validity, and conclusion in the candidate paper.
2. Read `REVIEWER_GUIDE_v1.3.md`, especially “Results worth scrutinizing” and
   “What would falsify or limit the interpretation.”
3. Run the frozen-evidence commands under “Fast local artifact verification.”
4. If time permits, compare one preserved initial failure with one confirmatory
   run and inspect the direct-parent commit relation and narrow code diff.
