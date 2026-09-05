# EACP 1.4.0-rc1: retained local verification

Executed against clean source commit
`e4716e82b9cd86058288ce59744aefb88632fec8` on macOS 26.6.2 arm64,
Python 3.12.14 and cryptography 50.0.1. The before/after source-tree SHA-256 was
`ca2331d84fa242616325966f127140df884f4b6817206ae0694a820ab25e460e`.
The tree was clean and did not change during the recorded reproduction.

Classification: **author-executed local validation**, not independent review or
organizational evidence. Later results/packaging commits package these records;
they do not change the collection/storage code that produced them. A packaging-only
filename correction appends `.zip` without discarding the dotted candidate version.
Final transfer QA also found that a shallow local Git history produced a bundle
that passed verification in the producer repository but could not be cloned by
a recipient. Missing public history was fetched without changing remote state.
The packager now rejects shallow sources and requires a fresh standalone clone,
exact candidate/historical identities and candidate manifest verification before
creating its ZIP. Five real disposable-Git regression tests cover this boundary;
the later complete root suite passed 126 tests. See
`additional-checks/package-transfer-regression.md`. Together with the unchanged
historical suites, the candidate now has 218 distinct cases; the original 213-case
measurement below is preserved, not silently rewritten or counted twice.

## Results

| Check | Observed outcome | Retained record |
| --- | --- | --- |
| Current repository tests | 121 passed, including 111 hardening tests and 10 repository contracts | additional-checks/repository-tests.txt |
| Historical Profile tests | 19 passed | reproduction/profile_tests.stderr.txt |
| Historical GitHub adapter tests | 51 passed | additional-checks/historical-adapter-tests.txt |
| Historical correlation tests | 16 passed | additional-checks/correlation-tests.txt |
| Historical index tests | 6 passed | additional-checks/index-tests.txt |
| Integrated finite fault campaign | 86/86 checks matched expectations, including 3 explicitly demonstrated protection limits | campaign.json |
| Recorded reproduction plan | 8/8 steps passed; source unchanged | reproduction/summary.json |
| Public-privacy compatibility | 9 corpora; 457/457 records; 69 native positives; 9 explicit403 records; 27 present unjoined no-ID records | privacy-reprocessing.json |
| Historical input checksum checks | 36/36 colocated checks matched; exact inputs/implementation separately hashed | privacy-reprocessing.json |
| Candidate preservation verifier | 657 historical files preserved under the pinned archive/documentation baselines | additional-checks/candidate-verifier.txt |
| Workflow syntax/static checks | actionlint returned0 for both current workflows | additional-checks/workflow-lint.txt |

There are **213 distinct unittest cases** in the five suites above. Repeated
executions inside the reproduction runner are not added again to that total.
Passing test assertions and simulated attacks are not 213 independent system
deployments, evidence of a zero production failure rate, or external replication.

## Ingestion fault design

Five seeded delivery schedules, each with forty expected events and initial loss
rates of 0%, 5%, 20%: fifteen schedules total. Deliveries are reordered; selected
events are retried; storage is closed/reopened; missing events then arrive late.

| Initial missing events | Initial distinct records | Initial status | After late recovery |
| --- | --- | --- | --- |
| 0/40 | 40 | COMPLETE relative to the signed finite inventory | 40, COMPLETE |
| 2/40 | 38 | INCOMPLETE | 40, COMPLETE |
| 8/40 | 32 | INCOMPLETE | 40, COMPLETE |

All five schedules at each loss level produced the stated result. `ingestion.csv`
retains each individual observation, including duplicate attempts. These are
finite deterministic fault checks, not estimates of failure rates in the field.
Separate store unit tests terminate a real subprocess immediately before a
transaction commit and after committed enqueue but before acknowledgement;
restart observes zero and one pending event respectively.

## Deliberately retained limits

- A correctly signed false collector statement is accepted as a statement; its
  semantic truth is not authenticated.
- Without a trusted source denominator, completeness remains UNKNOWN.
- Without an independently protected current anchor, snapshot freshness/rollback
  status remains UNKNOWN. A compromised anchor authority defeats this boundary.
- Colocated source hashes prove consistency with those hashes, not source origin
  authenticity or latest-state freshness.
- Reprocessing the old public corpora is not a new live Kubernetes/GitHub run.
- New attestation tests exercise policy and isolated workflow structure. No
  hosted 1.4 dispatch or newly signed1.4 archive has been verified.
- A read-only GitHub preflight found `main` at the old documentation commit with
  `protected: false` (`deployment-preflight.json`). The new signing job explicitly
  requires protected main and approved source publication. Neither branch
  protection nor remote source state was changed during this task.
- No external reviewer or organization has executed this package on our behalf.
  No pilot CSV is supplied as if it were real observations; the protocol remains
  not_started and permission gates remain false.

## Reproduction and inspection

Use the reviewed code commit and a new output directory:

```sh
python3 scripts/reproduce_hardening_v1_4.py --output reproduction-output/independent-new
python3 -m eacp_hardening.campaign --output reproduction-output/campaign-new
python3 scripts/reprocess_frozen_privacy_v1_4.py --output reproduction-output/privacy-new.json
```

For the results-bearing checkout, verify the complete candidate transfer manifest:

```sh
python3 scripts/generate_manifest.py --manifest MANIFEST-v1.4.0-rc1.sha256 --check
```

Generated CSV files retain their original CRLF bytes; their directory attributes
prevent newline normalization from invalidating recorded hashes. They are not
hand-edited or reformatted after execution.

The first command records actual commands, environment, stdout/stderr, exit
codes, source fingerprints, failures and timeouts. Its successful exit cannot
establish the executor's identity. The executor must document their own role,
method and deviations separately.

Small correlation/index outputs in `reproduction/` are smoke executions. They
are not replacements for the published benchmark, and their timings must not be
used as a new performance claim; other local validation also ran on this host.

The logs are retained verbatim and may contain local filesystem paths. They
contain no ambient environment-variable dump. Review before sharing. The local
package's checksum is a transfer-integrity aid, not a self-authenticating trust
anchor.
