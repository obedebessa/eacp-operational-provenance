# Candidate execution and attestation separation

Status: implemented locally for review; a live run of this new workflow has not
yet been observed. Local fixture tests do not demonstrate GitHub runner isolation
or constitute cryptographic verification of a new published artifact. The v1.3.0
workflow, historical cohorts and their verification contracts remain unchanged.

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
actions remain trusted. Repository settings must protect `main` and require
appropriate review of workflow changes. The `github.ref_protected` guard checks
that protection exists; it cannot prove that its review policy is sufficient.
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

## Checks and remaining live acceptance

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

Before reporting the new workflow as exercised, merge the reviewed change through
the repository's normal process and manually dispatch it from protected `main`.
Retain all first-attempt failures. Acceptance requires these observations:

1. Execution sees no OIDC request capability; both jobs run on distinct fresh
   hosted runners; producer artifacts are bound to that run and commit.
2. A successful signing job produces a downloadable attestation for the exact
   TAR, and the fresh local CLI verifies it with the expected policy.
3. A modified TAR and deliberately wrong expected run/commit/signer are rejected.
   A signing-step success without that verification is not a verified artifact.
4. PR and branch dispatch runs do not enter signing. An unsuccessful execution
   leaves signing skipped; a signing failure is recorded separately.

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
in the signer. All produced measurements remain a synthetic local campaign.

Primary documentation: [GitHub OIDC permissions](https://docs.github.com/en/actions/reference/security/oidc),
[GitHub CLI verification and certificate policy](https://cli.github.com/manual/gh_attestation_verify),
[artifact download inputs](https://github.com/actions/download-artifact/blob/634f93cb2916e3fdff6788551b99b062d0335ce0/action.yml),
[attestation limits](https://docs.github.com/en/actions/concepts/security/artifact-attestations),
and [SLSA build requirements](https://slsa.dev/spec/v1.2/build-requirements).
