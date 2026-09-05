# One-pass reviewer packet: EACP 1.4.0-rc1

Prepared in response to the technical assessment of the Profile 1.3 candidate.
This is new author-produced engineering evidence, not a revised opinion issued
by TytoNyx, an independent reproduction, a new paper claim or an agreed pilot.
The old review target and the published 1.3.0 release remain separate records.
The candidate is now publicly available on GitHub and has an author-operated
live signing run. It has no final v1.4 Zenodo DOI or external-review outcome.

## What changed and what to inspect

| Assessment concern | Implemented response | Direct evidence | Remaining limitation |
| --- | --- | --- | --- |
| Broad laboratory sanitization | Allowlisted public projections and no raw unknown-field reporting | `tests/hardening/test_privacy.py`; historical-corpus reprocessing | Retained identifiers require human disclosure review |
| Execution and attestation share privileges | Separate clean signer job, no experiment checkout or TAR execution, bound artifact/run identity | `test_attestation.py`; live main run 33945266470 and default/offline CLI verification | Owners, workflow and hosted platform remain trusted; live failed-producer behavior was not injected |
| Weakly specified collection identity | Pinned Ed25519 collector policy, source/adapter/origin binding, freshness, rotation/revocation, actual bounded HTTPS client | `test_trust.py`, `test_cli.py` | Collector authentication is not source semantic truth |
| Privileged replacement and rollback | Signed exact-state checkpoints against external digest/floor/freshness | `test_integrity.py`, integrated fault campaign | Deployment requires independently protected authority |
| Silent evidence loss | Durable queue, post-commit ACK, conflict quarantine, retries, finite-inventory reconciliation | `test_store.py`, seeded ingestion CSV | Local fsync assumptions; unknown source denominator remains UNKNOWN |
| Privacy/access/retention | AES-GCM bodies, tenant roles, access audit, event pruning/holds/tombstones | Store and CLI tests, STORAGE.md | Metadata, audit/backup policy and host administration need deployment controls |
| No independent experimental rerun | Recorded end-to-end reproduction runner | `scripts/reproduce_hardening_v1_4.py` | A third party must actually execute and identify its method |
| Practical benefit unproven | Gated paired pilot protocol and strict result evaluator | PILOT_PROTOCOL.json and evaluation tests | No organization has executed this new protocol yet |

The profile/resolver's conservative link semantics are preserved. The new
extractor checks both request and response metadata, rejects native-correlated
403s from the explicit-link control, and requires a native positive on the exact
target. It does not reinterpret the historical 0/9 and 9/9 cohorts.

## Evidence package

The retained local verification outputs are under
`results/hardening-v1.4/` when generated. `campaign.json` records its exact
parameters, environment, code commit/working-tree state, control outcomes and
explicitly expected boundaries. `ingestion.csv` contains every seeded schedule.
`privacy-reprocessing.json` binds the old inputs and new implementation by hashes.
`SOURCE_SHA256SUMS` binds the actual campaign source rather than relying only on
the human-readable version label. Unit-test/verification logs must be retained
alongside the summary; no unavailable hosted or external result is filled in.

Use a clean checkout of the supplied source commit, not a moving branch. A source
commit and a later results-only commit may differ; consult the report's source
hashes and commit rather than silently substituting one for the other.

The [live signing record](../../results/hardening-v1.4/live-signing-33945266470/README.md)
separately binds main run `33945266470`, attempt 1, to source/signing commit
`0bcb038fef930faff3ef19f661bf995f97d605d8`. The execution job passed 112 tests
and its OIDC-absence check; a separate hosted signer produced the exact TAR's
attestation. Fresh default-trust and offline verification succeeded, and six
negative checks rejected five altered conditions. The attestation covers that
TAR, not this reviewer packet or a later ZIP. PR and branch signing were observed
skipped; producer-failure skipping was not exercised by a new live fault injection.

## A limited review request, not a requested conclusion

> Thank you for the actionable assessment. The attached 1.4.0-rc1 candidate
> addresses the identified implementation boundaries with source changes,
> negative tests and a finite fault campaign. The table maps each concern to its
> change, verification and remaining limitation. Before we finalize the scope,
> please confirm whether you are willing to include inspection of this bounded
> package in your assessment. We do not ask you to remove criticism or describe
> our runs as independently reproduced. If you execute any check yourself,
> please identify the exact commit, command, environment, result and limitations.
> Otherwise, please retain the static-review label. Any letter should reflect
> only the contributions and organizational interest you can personally support.

No message has been sent by preparing this packet. Any additional reviewer work,
signature or organizational commitment requires that person's agreement. A
reviewer's execution is not guaranteed by a runnable package.

## Release and study boundaries

- Software candidate: 1.4.0-rc1; Profile semantics: 1.3.
- Public GitHub source and live TAR attestation; no final v1.4 Zenodo release.
- Existing Profile DOI: https://doi.org/10.5281/zenodo.22307668.
- Existing preprint DOI: https://doi.org/10.5281/zenodo.22283868.
- Existing artifact DOI: https://doi.org/10.5281/zenodo.22283852.
- These DOIs identify historical published materials, not this candidate.
- Immutable historical source: `537799bd2b292ce6e78004de22f4ab6df1b4feda`.
- No production, compliance, causality, universal false-join safety, field benefit
  or SLSA L3 claim is added by this engineering work.
