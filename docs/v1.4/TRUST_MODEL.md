# EACP 1.4 trust and failure model

## Assets and adversaries

Assets: evidence payloads, identities and pointers, accepted/rejected source
history, collector credentials, encryption keys, checkpoint authority keys,
current anchor expectations, read-access logs and published reproducibility data.

The tests model malformed input, a sender lacking an authorized signing key,
signature replay outside its validity window, storage corruption, file/snapshot
replacement relative to an external expectation, duplicate/conflicting delivery,
collector restart, queue saturation, cross-tenant API access and insufficient
roles. Compromised upstream producers, compromised trusted Python code, a hostile
host administrator, a compromised checkpoint authority and malicious changes to
an authorized signing workflow are not made trustworthy by these controls.

## Six distinct statements

1. A TLS client verified the endpoint using its configured CA trust.
2. A pinned collector identity signed a statement about acquired bytes.
3. The statement binds a permitted source, scope, adapter digest and observation.
4. An authenticated user may operate on one tenant through the reference API.
5. A snapshot matches the current independently acquired checkpoint expectation.
6. A hosted workflow attested the digest of an archive.

None of these implies that an upstream claim is true, authorized, complete or
causal. The collector policy's adapter hash is the signed collector declaration
about its implementation; it is not remote execution measurement. The bounded
HTTPS acquisition routine actually checks TLS for its own network call, rejects
redirects/foreign origins and oversized or ambiguous JSON, and never writes the
unminimized response. Its tests mock transport; they are not a live enterprise
source integration. Source-specific native signatures may be verified by an
adapter where the source supplies them; none is fabricated for unsigned APIs.

## Collector and access policy

An operator supplies a protected JSON object with `collectors`, `access`, optional
`max_statement_age_seconds` and optional `max_pending`. Unknown top-level fields
are rejected. An empty policy grants no access.

Collector entries require `key_id`, `public_key_hex` (32-byte Ed25519 public key),
`tenant_id`, `source_id`, `collector_id`, `adapter_sha256`, UTC `valid_from` and
`valid_until`, and an explicit `allowed_origins` array. `allow_fixture` defaults
false and must be a JSON boolean. `revoked` defaults false and must be a boolean.
An origin must be credential-free HTTPS, not a path or query. Source statements
include a raw-representation digest and either `https` or explicitly permitted
`fixture` acquisition. Fixed campaign keys are public test data, never defaults
for the CLI or a deployment.

Access entries require `token_sha256`, `subject`, `tenant_id`, a `roles` array,
`valid_until` and optionally boolean `revoked`. Generate high-entropy tokens
outside the application (at least 32 random bytes); SHA-256 token fingerprints
are not a password database suitable for memorable/low-entropy passwords.

The operating-system clock used by the CLI is trusted. Tests inject a clearly
identified fixed fixture time; an untrusted request cannot set the CLI clock.
Verification copies the signed payload and preserves its complete signed source
statement, so subsequent mutation of the original input does not rewrite the
verified receipt. A new source session must have its own source-stream identity
if its monotonic sequence can restart.

## Key ownership, rotation and revocation

Keep collector signing keys, the store encryption key, access tokens and the
checkpoint authority private key in separate controlled roles. The verifier
needs public collector/anchor keys, not their signing secrets. Files and
environment variables are local reference integration mechanisms, not a KMS.

Collector rotation: register a new key ID/public key with bounded validity, test
that it is accepted only for its intended source, stop old signing, revoke the
old key and preserve its historical public identity for explicitly historical
analysis. Normal ingestion rejects currently revoked/expired keys. Reissuing
unchanged content through an authorized new key deduplicates without replacing
the original receipt. A historical verification policy must not be confused with
current ingestion authorization.

Token rotation: provision a new high-entropy token fingerprint, verify its scope,
revoke the old fingerprint and observe denied use. CLI configuration is reloaded
for each invocation. Long-lived applications must reload policies or terminate
sessions themselves; an in-memory Principal is not automatically revocable.

Storage-key rotation: stop ingestion, export under authorized access into a
separately controlled migration process, re-encrypt into a new isolated store,
compare authenticated inventories/content, issue a new store-bound independent
checkpoint, and update access/recovery policy before resuming. No in-place KMS
rotation command or physical erasure guarantee is claimed by this candidate.

Anchor rotation: independently distribute the new trusted public key and current
checkpoint digest/floor. Do not trust a key change announced only by the store
being audited. Never reset the freshness/sequence expectation based on an old
bundle supplied by that store.

## Compromise recovery

1. Suspend acceptance and publication for affected identities/scopes; retain
   negative outcomes and identify the last independently trusted checkpoint.
2. Revoke compromised credentials through the protected policy owner. Preserve
   investigation material according to the approved retention/hold policy.
3. Restore or re-collect from independently trusted sources/backups; label gaps
   and uncertain intervals instead of filling them with inferred successful joins.
4. Reconcile finite source inventories, verify encryption and checkpoint state,
   introduce new identities/keys through independent channels and review access.
5. Resume only after the named operator accepts the remaining uncertainty.

These are documented deployment procedures, not evidence that a real organization
has exercised disaster recovery. The automated campaign tests the selected
primitives and explicitly retains the compromised-source/anchor boundaries.

## Retention and integrity trade-off

An evidence checkpoint commits to a particular state. A legitimate prune or hold
change changes that state and requires a new checkpoint; silently matching an old
checkpoint would be wrong. Event tombstones prevent forgotten deletions from
looking like complete retained evidence. Pruning does not erase filesystem
backups/WAL history, and index identifiers, inventories, quarantines and access
audit each need a separate approved retention schedule. Access audit is excluded
from the evidence snapshot to avoid self-changing reads; protect/export that log
independently if it is an assurance requirement.

## Publication and attestation

Minimize before publication. The public projection retains a selected operational
identity vocabulary and can omit business context; measure that loss. A valid
identifier can still contain confidential information. No syntactic sanitizer
certifies that all text is safe. Require source-owner/publication review.

The 1.4 workflow isolates project execution from signing credentials and binds
the downloaded artifact to its producer. Its authority is still the authorized
workflow and hosting environment. Protect changes to that workflow. A signed
archive can faithfully contain false data; cryptographic verification is not a
replacement for a source/experiment/organizational review.
