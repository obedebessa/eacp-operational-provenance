# Frozen three-attempt public cross-plane run

This directory freezes the public artifacts, completed-state recaptures, and
offline attestation bundles for GitHub Actions run
[`33682116347`](https://github.com/obedebessa/eacp-operational-provenance/actions/runs/33682116347).
All three attempts completed successfully against commit
`76b2ed54381ae52cf0f54cd22a20341c3216b77b` on 2026-09-02.

Each attempt has three parts:

- `downloaded-artifact/`: the artifact exactly as downloaded from GitHub,
  including the deterministic archive, portable archive checksum, and expanded
  public results;
- `finalized/`: a read-only post-run API recapture plus a regenerated exact join
  against the already-checksummed Kubernetes evidence; and
- `attestation/`: the Sigstore bundle downloaded for offline verification of
  the archive's SLSA provenance statement.

The three attempt-specific correlation identifiers are distinct. In every
attempt the completed view contains three GitHub records, eight Kubernetes
audit records with the source-native annotation, one additional HTTP 403 record
bound explicitly by exact Deployment target, one digest-matching Pod, and a
correlation-free negative control that remains unjoined. Namespace-filtered
audit-corpus size varies naturally from 51 to 56 records because controller
activity is asynchronous; the asserted controls do not depend on that total.

Validate every checksum, invariant, and attestation-statement subject and
compare the frozen aggregate summary:

```bash
python3 experiments/github_actions/summarize_reference_run.py --verify
```

`REFERENCE_SHA256SUMS` covers the complete frozen inventory, including the
expanded evidence, deterministic archives, completed recaptures, offline
attestation bundles, this README, and the aggregate summary.

Cryptographically verify each downloaded archive against its offline bundle,
repository identity, signer workflow, source commit, and Git ref:

```bash
for attempt in 1 2 3; do
  root="experiments/github_actions/results/reference/run-33682116347/attempt-${attempt}"
  archive="${root}/downloaded-artifact/eacp-cross-plane-v1.3-33682116347-${attempt}.tar.gz"
  bundle=$(find "${root}/attestation" -name '*.jsonl' -print -quit)
  gh attestation verify "${archive}" \
    --bundle "${bundle}" \
    --repo obedebessa/eacp-operational-provenance \
    --signer-workflow obedebessa/eacp-operational-provenance/.github/workflows/eacp-cross-plane-v1.3.yml \
    --source-digest 76b2ed54381ae52cf0f54cd22a20341c3216b77b \
    --source-ref refs/heads/eacp-v1.3-candidate \
    --deny-self-hosted-runners
done
```

The attestation binds archive bytes to the workflow identity and source
revision. It does not certify that GitHub or Kubernetes observations are true,
complete, or causal. The three executions use one public repository, one
workflow design, GitHub-hosted runners, and ephemeral single-node kind clusters;
they are repeated demonstrations, not a production population.
