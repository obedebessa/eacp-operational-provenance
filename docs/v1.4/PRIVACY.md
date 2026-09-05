# Public projection policy for the v1.4 hardening laboratory

The new `eacp_hardening/privacy.py` applies the explicit policy
`eacp.public-projection/1.4.0`. It constructs new public objects from an allowlist;
it does not traverse and redact arbitrary fields using guessed secret patterns.
Unlisted bodies, fields and free text are omitted. Malformed allowlisted values,
missing required identity, contradictory object identity and inconsistent typed
link declarations reject the record. Input objects are not modified.

This policy is a laboratory publication control. It does not certify arbitrary
inputs as secret-free, authenticate a source, establish upstream completeness,
or grant authority to publish retained identities. The caller must approve the
publication scope and manually review the result before uploading or sharing it.
No existing v1.3 file, result or release tag is changed by this implementation.

## APIs and output contract

```python
from eacp_hardening.privacy import (
    project_kubernetes_audit, project_github_metadata,
    project_github_actions, check_oci_digest,
)

result = project_kubernetes_audit(audit_event, namespace="evaluation-namespace")
public_event = result.payload
privacy_report = result.report

run = project_github_metadata(run_response, kind="run")
job = project_github_metadata(job_response, kind="job")
artifact = project_github_metadata(artifact_response, kind="artifact")
bundle = project_github_actions(run_response, job_responses, artifact_responses)
```

Every projection returns `ProjectionResult(payload, report)`. The executable
schemas are the explicit object rules and typed validators in `privacy.py`.
There is no permissive extension passthrough. A rejection raises `HardeningError`
with a fixed diagnostic; input values and unknown field names are not interpolated
into that diagnostic. These functions accept decoded JSON objects; the public
extractor also validates its JSONL input before creating publication files.

The deterministic report contains the policy and source type, the number of
omitted members, sorted omission records (`path`, `reason`, `count`) and a required
manual-review flag. An unknown field is reported under the nearest static
allowlist path with `/*`, not under its raw key. Unknown field names can themselves
contain secrets. The report contains no raw omitted value, source identifier or
hash of an omitted secret. Each unknown subtree counts once; these counts are
not a count of secrets or a disclosure-risk score. They can still reveal coarse
input shape and are part of the reviewed publication output.

## Allowlisted representations

| Input | Retained public representation | Omitted or rejected |
| --- | --- | --- |
| Kubernetes audit identity | `auditID`, stage, UTC timestamps, enumerated verb, `objectRef` resource and namespace, optional group/version/name/UID/subresource | Missing or malformed required identity rejects; `requestURI` is always omitted, including its path, credentials, query and fragment |
| Kubernetes principal | `user.username`, optional `impersonatedUser.username` | Groups, extra identity claims, credential IDs, source IPs and unrelated actor fields omitted |
| Kubernetes response | Integer HTTP status code | Human-readable message, reason, details and status text omitted; unknown or invalid code rejects |
| Kubernetes bodies | Request/response object metadata: name, namespace, UID; only `app.kubernetes.io/name` label and the seven exact EACP annotations listed below | All spec, status, env, ConfigMap data, stringData, arbitrary annotations and unknown metadata omitted; JSON Patch arrays and null bodies yield no public body metadata |
| GitHub run | Numeric run/attempt/repository IDs, repository full name and public flag, SHA, typed state, UTC timestamps, numeric actor ID and login/type; a canonical public run URL reconstructed from repository identity and run ID | Supplied URLs, names, display title, branches, workflow paths, messages, emails, runner data, logs, event payloads and arbitrary extra metadata omitted; private repositories reject |
| GitHub job | Numeric job/run/attempt IDs, typed state and timestamps | Job and step names, labels, runner details, logs and supplied URLs omitted |
| GitHub artifact | Numeric artifact ID and linked run identity, optional SHA-256 digest, expiry boolean and timestamps | Name, content, archive URL and all other fields omitted |

The Kubernetes annotations are `eacp.io/correlation-id`,
`eacp.io/github-repository-id`, `eacp.io/github-run-id`,
`eacp.io/github-run-attempt`, `eacp.io/github-commit-sha`,
`eacp.io/subject-uri` and `eacp.io/subject-digest`. Each has a declared identifier,
decimal, SHA or OCI syntax; subject URI and digest must appear together. OCI
references containing URL credentials, a query, fragment or a URI scheme are
not accepted as public artifact names. The policy does not interpret arbitrary
annotation text as evidence.

`objectRef.name` is optional because collection reads and some creation audit
events omit it. `auditID`, stage, namespace and resource remain mandatory. Names
retained in body metadata must agree with the source reference when both are
present. Request and response declarations must agree for any shared typed-link
key. Missing fields are never manufactured from an API query string. Secret,
token and authorization-review resources are rejected from public projection.

GitHub bundle projection additionally checks the run ID and attempt for each
job, the run/repository/SHA identity declared by each artifact and duplicate
source IDs. It sorts jobs and artifacts by numeric ID. These are internal
consistency checks; input JSON alone cannot establish a GitHub origin.

## Opt-in extractor and cross-plane controls

`experiments/github_actions/extract_kubernetes_audit_v1_4.py` is a new command
using the same required arguments as the historical extractor. It projects all
retained audit input before invoking the existing normalization and Profile 1.3
validation helpers. This is a new adapter, not a new Profile schema. The source
digest identifies the v1.4 public transformation; the operational experiment
scope is labeled v1.4 rather than reusing a v1.3 experiment claim.
Records explicitly outside the requested namespace are dropped and counted.
Non-resource or cluster-scoped audit records without an explicit namespace are
also dropped under a separate `excluded_unscoped_records` count. A namespace
is never reconstructed from a URI. Malformed present scope fields reject;
an omitted scope cannot support a claim that all namespace activity was captured.

The extractor requires all three controls before it returns or writes output:

1. A retained record carrying the exact declared correlation annotation on the
   same API group/resource/namespace/name used for the adapter's denied target.
2. A 403 with the exact expected principal, API group, resource, namespace and
   object name. Only that complete match can receive an adapter-explicit link.
3. A distinct, present negative-control object without a correlation annotation.

Source-native annotation links and adapter-explicit links retain their different
Profile evidence methods. A no-ID record has no operational link and its flat
CSV correlation is empty. The old object-locator fallback is not published as a
correlation assertion by this extractor. A different principal's 403 remains
unjoined even when its target matches a valid denied operation.

The extractor examines compatible metadata from both request and response bodies
when determining linkage and ID absence. A request without annotations cannot
hide a response's native ID. Contradictory body identities or declarations reject.
The expected adapter-explicit 403 must have no native correlation in either body;
a native declaration is rejected instead of being counted or relabeled as an
explicit adapter link. The normalizer's combined view never replaces the published
source record: its digest binds the retained record with separate request and
response bodies.

`--expected-subject-digest` and `--observed-subject-digest` optionally enable a
separate exact SHA-256 comparison. Both must be supplied, the observed digest
must equal the expected digest and positive evidence must consistently declare
that digest. Without these inputs, the summary says the comparison was not
performed. Correlation equality cannot satisfy this check. The caller must
establish where the observed digest came from; matching two supplied strings
does not authenticate a running image or a source. The public projection drops
Pod spec/status bodies and therefore cannot recover a runtime image digest from
those discarded fields. Obtain a separately scoped observation when needed.

Output consists of minimized audit JSONL, normalized CSV, Profile JSONL, a privacy
report, a bounded control summary and SHA-256 checksums. All checks finish before
files are published. A temporary sibling directory contains only minimized
output; the final destination must not already exist. The destination's parent
must be controlled by the operator. This local atomic rename is not an adversarial
filesystem, access-control, durability or external attestation guarantee.

## Verification and scope

```bash
python3 -m unittest discover -s tests/hardening -p test_privacy.py -v
python3 -m unittest discover -s tests/hardening -p test_privacy_reprocessing.py -v
python3 -m unittest discover -s experiments/github_actions/tests -p test_kubernetes_extractor_v1_3.py -v
```

The tests inject synthetic canaries into arbitrary annotations, environment
values, ConfigMap data, query strings, URL credentials/fragments, nested unknown
structures and unknown keys. They check omission from both payload and report;
malformed allowed types and conflicting identities reject. They also check
unchanged inputs, deterministic reports, preserved exact/native and explicit
controls, the no-ID control, independent digest mismatch failure, checksum output
and absence of partially written publication files when validation fails.

Read-only reprocessing of the nine archived confirmatory audit corpora retained
all 457 available namespace records and preserved 69 native-positive records,
nine exact-principal/target adapter-explicit 403s and 27 present unjoined no-ID
control records. This is compatibility testing of already published observations,
not a new live experiment, independent reproduction or evidence that no upstream
events were missing. No replacement of the archived v1.3 corpora is implied.

The compatibility result is rerunnable without writing any audit record:

```bash
python3 scripts/reprocess_frozen_privacy_v1_4.py
# Optionally create a new summary file; an existing path is rejected:
python3 scripts/reprocess_frozen_privacy_v1_4.py --output privacy-reprocessing-v1.4.json
```

The helper exposes `reprocess_frozen_corpus(repository_root=ROOT)`. It verifies the
four source files in each audit directory against their colocated manifest,
projects only in memory, checks the frozen expected counts and emits relative
source filenames, SHA-256 hashes, per-run counts and implementation hashes. Its
method is explicitly `author_reprocessing_frozen_corpus`. It does not claim a new
live run, independent reproduction, source authentication, freshness/rollback
protection or a separate verification of runtime OCI image identity. Colocated
checksums are not independent trust anchors. With `--repository-root`, input files
come from that checkout while implementation hashes still describe the code
actually executing from the helper's checkout.

Remaining limits are explicit:

- An arbitrary secret may be embedded in a syntactically valid allowed actor,
  repository, service, resource or correlation identifier. This policy cannot
  universally recognize it; retained identity is attributable and needs review.
- Dropping a value cannot revoke information already captured or published. The
  source log and the caller's memory/storage need separate access and retention
  controls. This function does not implement secure erasure or anonymization.
- This allowlist trades detail for disclosure control. New source types, CRDs,
  field semantics and publication needs require a reviewed policy extension and
  tests. Unknown free text is not silently promoted into the public contract.
- Canary tests establish behavior for the tested fields and classes only. Manual
  publication review, source-specific threat models and independent execution
  remain necessary before sharing real operational data.
