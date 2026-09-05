# EACP 1.4 candidate: observed GitHub signing and local verification

Privacy derivative: selected unsigned text receipts in this checkout replace
private filesystem prefixes with portable placeholders. The original bytes at
execution reference `e2807efc14209e42ba5ac82f5aa8d44599d22c43` and these derivative
bytes are bound by `docs/v1.5/PRIVACY_REDACTIONS.json`. Descriptions below of raw,
unedited receipts refer to that original record. Signed archives, attestation
bundles, recorded outcomes and cryptographic values remain unchanged.

On 2026-09-05, the real protected-main workflow completed and its exact TAR was
cryptographically verified using GitHub CLI 2.97.0 and the strict EACP wrapper,
both with default trust and offline with a separately captured official trust
root. This is an author-operated hosted execution and local verification, not
independent third-party reproduction, a field pilot or a final archival release.

## Exact object and execution

- [Main run 33945266470, attempt 1](https://github.com/obedebessa/eacp-operational-provenance/actions/runs/33945266470).
- Source commit: `0bcb038fef930faff3ef19f661bf995f97d605d8`, `refs/heads/main`.
- Workflow: `.github/workflows/eacp-hardening-v1.4.yml`.
- [Attestation 45407867](https://github.com/obedebessa/eacp-operational-provenance/attestations/45407867).
- GitHub transport artifact ID: `9963122568`; ZIP SHA-256:
  `3e6a663941d8b0e5102349b8995238084b828c530ad224a1a9f8d804ecebf6d4`.
- Signed subject: `artifact-33945266470/eacp-hardening-v1.4.tar.gz`; SHA-256:
  `b4ee08dc32eb56e568ccc93ba45459642f3844427adab0bd8c044153b5ac3bea`.
- Downloaded attestation bundle SHA-256:
  `be1830f303e89b612fa8fffc849ef4206178fe334ad7d9195a4e2b6e3a0418a8`.
- Captured trusted-root SHA-256:
  `65ca537f6ed8a47fd0e560c421baa1f6c1efb8b25fc200d8c5c02c0e92eb2b9c`.

The signed subject is the campaign TAR, not the GitHub transport ZIP, entire
repository, PDF, these verification receipts or a later reviewer-package ZIP.
The TAR contains `campaign.json`, `ingestion.csv` and `SOURCE_SHA256SUMS`.

## Observed acceptance checks

| Check | Observed result | Evidence |
| --- | --- | --- |
| Producer isolation | Job `101250089036`, hosted runner `1000000152`; read-only permissions and absent OIDC request variables; 112 hardening tests passed | `14-main-jobs/`, `16-main-logs/` |
| Signer isolation | Job `101250192742`, different hosted runner `1000000156`; no checkout, dependency install, cache restore or campaign TAR execution | `14-main-jobs/`, `16-main-logs/` |
| Same-run handoff | Immutable artifact ID/API digest/run/source checks and exact three-file byte checks succeeded | `15-main-artifacts/`, `16-main-logs/` |
| Campaign | 86/86 expectations, including three explicit protection limits; five seeds, forty events, initial loss 0%, 5%, 20%; Python 3.11.16 and cryptography 50.0.1; clean source checkout | Signed `campaign.json` inside the TAR |
| Signature verification | Raw CLI and strict wrapper both succeeded with default trust and captured-root offline verification; verified material matched | `verification-01/receipts/01-*`, `02-*`, `04-*`, `05-*` |
| Negative verification controls | Six checks rejected across five conditions: altered TAR (raw CLI and wrapper), wrong SHA, wrong run, wrong signer and wrong ref | `verification-01/receipts/06-*` through `11-*` |
| PR signing denied | [PR run 33945220787](https://github.com/obedebessa/eacp-operational-provenance/actions/runs/33945220787): execute succeeded, attest skipped | `07-pr-signing-denied-jobs/`, `08-pr-signing-denied-logs/` |
| Branch signing denied | [Branch run 33945267673](https://github.com/obedebessa/eacp-operational-provenance/actions/runs/33945267673): execute succeeded, attest skipped | `17-branch-control-jobs/`, `21-branch-control-logs/` |

The altered copy differs by one bit in byte zero; original inputs and verification
source files were unchanged. All negative processes completed normally with exit
code 1; positive offline controls used the same CLI/root/environment successfully.
The wrong-run error identifies `runInvocationURI`, and the wrong-ref error shows
the expected and actual refs. Other rejection messages are generic CLI/issuer
errors: they do not separately diagnose an internal cryptographic failure cause.
No network, timeout or command-usage failure was observed in those controls.

Offline verification used local bundle/root material and HTTP(S) proxies directed
to inaccessible loopback port 9; this is not a claim of an OS-level network sandbox.
Four successful verification calls and one root-acquisition call are retained;
they are not five independent deployments or independent reviewers.

## Retained limits, warnings and earlier failure

- The first branch-protection API request returned 422 because it supplied both
  `contexts` and `checks`. Record `02-*` preserves that failure. The corrected
  `checks`-only request succeeded in `03-*`; the final settings are in `20-*`.
- Main requires strict `reproduce-small` from GitHub Actions App `15368`, enforces
  administrators, and prohibits force pushes and deletion. No mandatory human
  approving-review rule was configured. Owners, approved workflow code and the
  GitHub platform remain trusted; this is not separation of organizational control.
- The signer log retains a nonfatal Node.js 20 deprecation warning for the pinned
  download action, which GitHub ran under Node.js 24. The action was not silently
  changed after this execution.
- The producer's campaign says it does not establish a live v1.4 attestation:
  that file was generated **before signing**, and cannot verify its own later
  signature. The separate post-signing receipts establish the observed result.
  The signed bytes were not edited to rewrite that pre-signing boundary.
- Failed-producer signing denial and compromised fork/workflow scenarios were
  not injected into this live run; relevant static/fixture checks remain distinct.
- A valid attestation binds bytes and certified workflow identity, not truth of
  upstream operational events, field effectiveness, or automatic SLSA L3 status.
- GitHub source publication is not a new Zenodo version or DOI. Profile 1.3 and
  the archived 1.3 paper, datasets and attestations remain separate records.

## Inspect and repeat verification

Review the source and select the expected commit/run identity from the linked
GitHub record, not solely from an archive-supplied manifest. From the repository:

```sh
python3 scripts/verify_attestation_v1_4.py \
  results/hardening-v1.4/live-signing-33945266470/artifact-33945266470/eacp-hardening-v1.4.tar.gz \
  --bundle results/hardening-v1.4/live-signing-33945266470/attestation-33945266470/sha256-b4ee08dc32eb56e568ccc93ba45459642f3844427adab0bd8c044153b5ac3bea.jsonl \
  --repository obedebessa/eacp-operational-provenance \
  --source-sha 0bcb038fef930faff3ef19f661bf995f97d605d8 \
  --source-ref refs/heads/main --run-id 33945266470 --run-attempt 1
```

For offline verification, add `--trusted-root` pointing to
`verification-01/inputs/trusted_root.jsonl` under this directory, after establishing
that root through an independently trusted channel/default CLI trust. A root next
to a bundle is not self-authenticating. The operator used default verification
before capturing and hashing the official root.

`operator-tools/verify_live_bundle.py --help` describes the complete repeatable
verification and negative-test procedure. It requires a new output directory.
The GitHub CLI originally wrote a colon-containing bundle filename; the retained
public copy uses `sha256-` for portability, with identical bytes and hash. Raw
command receipts retain their actual original paths, stdout, stderr and exit codes;
they were not rewritten to pretend they ran inside this later evidence directory.

`verification-01/SHA256SUMS` and the repository candidate manifest check transfer
integrity. These locally produced receipts and checksums are not signed attestations
of an independent reviewer's identity. No third-party review or letter was fabricated.
