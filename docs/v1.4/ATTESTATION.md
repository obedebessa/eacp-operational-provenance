# Candidate execution and attestation separation

Status: exercised on protected main in
[run 33945266470](https://github.com/obedebessa/eacp-operational-provenance/actions/runs/33945266470),
attempt 1, with separate hosted execution/signing jobs and fresh default-trust
and offline verification of the resulting TAR. This is an author-operated live
run, not external reproduction, a final Zenodo release, a field result or a SLSA
L3 claim. The v1.3.0 workflow, historical cohorts and verification contracts
remain unchanged. See the [retained live record](../../results/hardening-v1.4/live-signing-33945266470/README.md).

## Trust boundary

`.github/workflows/eacp-hardening-v1.4.yml` has two jobs on fresh GitHub-hosted
Ubuntu runners. `execute` receives only `contents: read`, checks out without
persisting credentials, runs the reference tests and a synthetic campaign, and
uploads one archive handoff. It does not receive OIDC request or attestation-write
permission. Its initial check fails if OIDC request environment variables exist.

`attest` runs only for a successful manual dispatch from protected `main` in
`obedebessa/eacp-operational-provenance`. Pull requests and branch/fork dispatches
cannot enter that job under this reviewed workflow. It has the OIDC and
attestation permissions. It does not check out source, install dependencies,
restore caches, execute repository scripts, or unpack the campaign TAR.

The signer downloads the exact immutable artifact ID from the current run. A
fixed inline validator checks the file set, archive SHA-256, handoff identity and
GitHub API artifact metadata (ID, name, upload digest, run ID and commit). The
download action unwraps the GitHub transport artifact into three data files; the
campaign TAR itself remains opaque. The manifest's assertions are compared with
the signer's GitHub context, not accepted as their own proof of origin. The
signing action attests the TAR's bytes only.

The execution job can still produce false synthetic results or arbitrary archive
bytes. This change isolates its code from the signing environment; it does not
independently validate every measurement inside the archive. Repository owners,
reviewers of the authorized workflow, GitHub's hosted platform, and the pinned
actions remain trusted. For this run, `main` required the strict `reproduce-small`
status check from GitHub App `15368`, enforced administrator compliance and
disallowed force pushes and deletion. Mandatory human PR approval was not
configured. Owners still control repository policy and approved workflow changes.
The `github.ref_protected` guard checks that protection exists; it cannot prove
that its review policy is sufficient or that an owner cannot weaken it.
There is no automatic SLSA L3 claim and no proof of upstream event truth.

## Independent verification

Select the expected repository, full commit SHA, run ID and attempt from an
independently reviewed run. Do not derive the expected policy solely from the
downloaded archive or a supplied JSON verification report. Download the exact
archive and bundle, then use a trusted local GitHub CLI:

```sh
gh attestation download eacp-hardening-v1.4.tar.gz \
  --repo obedebessa/eacp-operational-provenance
python scripts/verify_attestation_v1_4.py eacp-hardening-v1.4.tar.gz \
  --bundle PATH_TO_DOWNLOADED_BUNDLE \
  --repository obedebessa/eacp-operational-provenance \
  --source-sha FULL_REVIEWED_COMMIT_SHA --source-ref refs/heads/main \
  --run-id EXPECTED_RUN_ID --run-attempt 1
```

The wrapper always invokes `gh attestation verify` on the actual bytes. A
successful subprocess is necessary before inspecting its output. It enforces
the exact certificate issuer, signer, commit, main ref, hosted runner, manual
trigger and run/attempt URI, then checks the archive subject and predicate. It
also detects input changes across the verification. It does not offer an input
for precomputed JSON success. Local host integrity and the installed CLI are
assumed; subprocess mocking is used only by clearly labeled policy tests.

For offline verification add `--trusted-root PATH_TO_TRUSTED_ROOT`. Establish
that root independently, for example by first verifying with the CLI's default
trust configuration and retaining the root with a separately recorded digest.
Merely finding a root next to a bundle does not authenticate it. Retain the CLI
version, command, stdout/stderr, archive, bundle and trust-root digest with the
review record. The verifier rejects unknown output schemas rather than silently
relaxing certificate checks.

## Observed live verification and remaining limits

The recorded source and signer commit is
`0bcb038fef930faff3ef19f661bf995f97d605d8`. Main run `33945266470`, attempt 1,
passed its execution job with 112 tests and the OIDC-absence check. The signing
job succeeded on a distinct hosted runner. Its immutable GitHub artifact ID is
`9963122568`; the attestation ID is `45407867`. The signed TAR SHA-256 is
`b4ee08dc32eb56e568ccc93ba45459642f3844427adab0bd8c044153b5ac3bea`.
The hosted campaign recorded 86/86 expected outcomes, including three explicit
boundary demonstrations, with five seeds, forty events and 0%/5%/20% initial
loss. Its environment was Python 3.11.16 and cryptography 50.0.1 on the clean
source commit above.

Fresh local verification of those actual bytes succeeded both through raw
GitHub CLI and through the policy wrapper using default trust. After official
trust-root capture, raw CLI and wrapper offline verification also succeeded;
default and offline verification returned the same certificate material. Six
negative checks returned rejection across five altered conditions: TAR tampering
(checked twice), wrong expected source commit, wrong run, wrong signer and wrong
ref. Input binding and checksum verification passed, and the original downloaded
material remained unchanged. This attestation covers the exact TAR only; it does
not attest the whole repository, PDFs, a later review package, or the truth of
every measurement inside the TAR.

The signed campaign still lists `live v1.4 GitHub attestation` under
`not_established`: the producer wrote it before the signing job, and a campaign
does not verify its own later signature. Preserve those signed bytes. The
post-signing `verification-01` receipt in the live record supplies the subsequent
verification result; it does not rewrite the earlier campaign's observation time.

Signing was observed skipped in
[PR run 33945220787](https://github.com/obedebessa/eacp-operational-provenance/actions/runs/33945220787)
and [branch run 33945267673](https://github.com/obedebessa/eacp-operational-provenance/actions/runs/33945267673).
These observations establish the two exercised exclusions. An unsuccessful
producer and a compromised-fork/workflow scenario were not injected live in this
cohort; their handling remains supported by workflow conditions and local tests,
not new live observations. A future failure must be retained in its own record.

The download action emitted a nonfatal Node 20 deprecation/forced-Node-24 warning.
The original run and warning are retained; a future runtime/pin change must have
its own source commit and verification rather than being retroactively applied
to these logs.

The 2026-09-05 live-run preflight found and corrected a GitHub CLI compatibility
bug: `--signer-workflow` and `--cert-identity` are mutually exclusive in CLI 2.97.
The verifier now supplies the exact `--cert-identity` plus pinned signer/source
digests, ref and all existing certificate/subject checks. A real offline CLI
regression test verifies a frozen historical bundle using its captured trust
root and a network-denying proxy; this checks the production flag combination,
not a new 1.4 signature. Environments without the CLI or historical material
explicitly skip that integration test rather than claim it ran. The original
mocked policy tests did not detect the incompatible flag combination.

`python -m unittest discover -s tests/hardening -p test_attestation.py -v`
checks policy rejection for modified subject bytes, wrong run, ref, commit,
signer, repository, trigger and runner; missing verification evidence; CLI
failure; and execution/signing failure classification. Positive JSON fixtures
test policy logic only. Static workflow checks guard permission scope, signing
conditions, archive handling and commit-pinned actions.

Do not retrofit these results into the archived v1.3 cohorts. Any future signing
workflow or signer commit distinct from the source commit requires a separately
reviewed policy that independently binds both identities.

## Pin and design references

The following action references were checked against the primary GitHub API on
2026-09-04; commits are used in the workflow rather than mutable tags:

| Action | Commit |
| --- | --- |
| checkout | `d23441a48e516b6c34aea4fa41551a30e30af803` |
| setup-python | `ece7cb06caefa5fff74198d8649806c4678c61a1` |
| upload-artifact v4.6.2 | `ea165f8d65b6e75b540449e92b4886f43607fa02` |
| download-artifact v5 | `634f93cb2916e3fdff6788551b99b062d0335ce0` |
| attest-build-provenance v4.2.2 | `4d101475d8b20a2381f78447822ac1eab6504dd8` |

The producer pins `cryptography==50.0.1`; this is a version pin, not a lockfile of
all transitive packages or a hermetic build. That dependency is never installed
in the signer. The recorded measurements remain synthetic campaign observations,
including the hosted execution; they are not production or field measurements.

Primary documentation: [GitHub OIDC permissions](https://docs.github.com/en/actions/reference/security/oidc),
[GitHub CLI verification and certificate policy](https://cli.github.com/manual/gh_attestation_verify),
[artifact download inputs](https://github.com/actions/download-artifact/blob/634f93cb2916e3fdff6788551b99b062d0335ce0/action.yml),
[attestation limits](https://docs.github.com/en/actions/concepts/security/artifact-attestations),
and [SLSA build requirements](https://slsa.dev/spec/v1.2/build-requirements).
