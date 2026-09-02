# EACP v1.3 confirmatory cross-version cohort

This directory freezes the nine first-attempt outcomes predeclared by the
v1.3.1 protocol amendment. The cohort uses tags `run-04` through `run-06`
across Kubernetes v1.34.8, v1.35.5, and v1.36.1. All tags resolve to the
single corrective commit `4cbf7d2fa0bb44585d258a3f37ce0c0d39ddea43`, whose
parent is the original protocol commit.

The initial `run-01` through `run-03` cohort is preserved separately and is
not pooled with these results. Its nine jobs failed at a lifecycle assertion
that requested the completed-run artifact before GitHub had created it. The
amendment removes only that premature in-job assertion; the same three-row
criterion is enforced during completed-run finalization.

Every successful member here contains the downloaded public artifact, the
completed-run finalization, the downloaded SLSA bundle, a captured trusted
root, verification results under both GitHub CLI default trust and the captured
root, the exact policy, one capture-time sole-tag-invocation observation, and
nested SHA-256 manifests. `summarize_cross_version_run_set.py --verify` repeats
the cryptographic verification offline and checks run, tag, commit, workflow,
subject, version, control, and archive identities.

SLSA authenticates the in-run TAR only. The completed-state GitHub recapture
and final three-row join are locally generated, checksum-bound, and constrained
to the attested runtime identity, but they are not builder-attested. The
captured trusted root enables replay relative to those bytes; its authenticity
is bootstrapped separately by the capture-time default-trust verification. The
sole-tag query is a checksum-bound public API observation at capture time, not
a signed API response or a guarantee against future tag mutation.

The result is descriptive controlled procedural repetition. It is not
identifier discovery, independent or cross-organizational corroboration, a
managed-cluster or field deployment, third-party reproduction, inferential
evidence, or a production reliability estimate.
