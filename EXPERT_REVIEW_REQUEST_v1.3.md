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
materialized retrieval index. The candidate composes independently emitted
GitHub Actions and Kubernetes evidence through exact typed and scoped links,
retains native evidence pointers, and abstains when the selected link is absent
or structurally ambiguous. It does not claim causal inference, source truth,
production readiness, or replacement of SLSA/in-toto, Sigstore, tracing, SIEM,
or authoritative source systems.

The new evaluation includes:

- 2,250 deterministic adversarial-correlation trials spanning missing, wrong,
  reused, duplicated, delayed, reordered, and clock-skewed identifiers;
- a paired four-treatment SQLite index ablation with 19,200 row-equivalence
  checks across warm and cold-open queries; and
- three successful attempts of a public GitHub Actions to Kubernetes experiment,
  including a no-ID negative control, an exact-target denied action, pinned OCI
  digests, frozen checksums, and offline-verifiable attestations.

All three executions are rerun attempts of the same public workflow run in one
repository, each using a fresh ephemeral single-node kind cluster. The workflow
itself generated the correlation key and wrote it into the positive Kubernetes
annotations; the study therefore evaluates controlled propagation and
composition, not identifier discovery, cross-site replication, or independent
reproduction. “Source-native” means that the retained raw Kubernetes audit
record contains the workflow-injected annotation; it does not mean that the key
arose independently. The present no-ID control remained unjoined, the HTTP 403
association is adapter-explicit rather than source-native, and OCI digest
verification is a separate check. Zero false joins were observed only under the
declared synthetic invariants. No field deployment or third-party reproduction
has yet been performed.

I would value a skeptical assessment rather than an endorsement. In particular:

1. Does the manuscript distinguish its operational-provenance scope clearly
   enough from supply-chain attestations, tracing, and general provenance?
2. Do the identifier-failure experiment and resolver abstention policy support
   the stated safety and coverage claims without overclaiming?
3. Which limitation or missing comparison most weakens the contribution as
   currently framed?

A 10–15 minute path is available in the reviewer guide, and all headline claims
map to frozen machine-readable evidence. If you reproduce any check, find a
contradiction, or identify a claim boundary that should be narrower, even a
brief note would be extremely useful. I will not quote or identify you publicly
without separate permission.

Paper:
<https://github.com/obedebessa/eacp-operational-provenance/blob/eacp-v1.3-candidate/paper/EACP_preprint_v1.3_candidate.pdf>

Reviewer guide:
<https://github.com/obedebessa/eacp-operational-provenance/blob/eacp-v1.3-candidate/REVIEWER_GUIDE_v1.3.md>

Pinned evidence-and-protocol snapshot:
<https://github.com/obedebessa/eacp-operational-provenance/tree/c20d2c06efda105cf6772861dd447413c5e709fa>

Public live run:
<https://github.com/obedebessa/eacp-operational-provenance/actions/runs/33682116347>

Thank you for considering it,

Obede Bessa Rocha da Silva

## Fast review path for the recipient

1. Read the abstract, contribution boundary, Tables 7–9, threats to validity,
   and conclusion in the candidate paper.
2. Read `REVIEWER_GUIDE_v1.3.md`, especially “Results worth scrutinizing” and
   “What would falsify or limit the interpretation.”
3. Run the frozen-evidence commands under “Fast independent verification.”
4. If time permits, inspect one live attempt and verify its archive attestation
   using the copy-ready command in the frozen-run README.

The fixed evidence snapshot intentionally precedes the manuscript commit: it
binds the protocols and results cited by the paper. The branch tip adds the
reviewer manuscript and outreach material without changing that frozen evidence.
