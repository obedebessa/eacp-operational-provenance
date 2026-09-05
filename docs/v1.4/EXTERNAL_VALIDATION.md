# Bounded reproduction and observation-only pilot

These tools make external review concrete. They do not contact reviewers, secure
organizational permission, reproduce the work independently by themselves, or
create field evidence. The pilot protocol is **not started** and all approval
gates default to false. Synthetic test fixtures are not pilot observations.

## Reproduction from an identified checkout

Use Python 3.11 or newer, Git, the pinned optional hardening dependency, and a
trusted GitHub CLI for the frozen cohort's offline bundle verification. Clone the
reviewed repository and select the exact intended commit. Keep local source
changes visible; the runner records the commit, committed tree, dirty status and
SHA-256 of the checked-out tracked/nonignored candidate files. It does not dump
environment variables, remote URLs or credentials.

Inspect the commands without running tests or creating output:

```sh
python3 scripts/reproduce_hardening_v1_4.py --output NEW_DIR --verify-plan
```

`--dry-run` has the same nonexecuting behavior. Then use a fresh output directory:

```sh
python3 scripts/reproduce_hardening_v1_4.py --output NEW_DIR
```

The fixed plan runs hardening tests, Profile tests, one small correlation matrix,
one small paired index run, and frozen index/reference/cohort verification. It
creates no cluster and dispatches no GitHub workflow. Small timings are local
smoke observations and do not replace the published matrix. The earlier
reference verifier checks frozen consistency; the cohort verifier additionally
calls GitHub CLI cryptographic verification for its successful archived runs.

Every command gets its actual argument vector, working directory, elapsed time,
exit code, stdout/stderr and their hashes. Failures and timeouts remain in the
output, later independent checks still run, and overall failure returns nonzero.
The default per-command timeout is 300 seconds; `--timeout-seconds` permits an
explicit change. Do not rerun into an existing directory. Preserve the first
failed attempt alongside any corrected rerun, with the intervention explained.
The executor's environment and source tree before/after are retained. Results are
automatically labeled `executor_self_run`, with `independently_reproduced: false`.

A reviewer who executes this themselves should write a separate dated account
identifying their role, relationship to the author, chosen commit, environment,
commands, results and deviations. The author may attach that statement as a
separate source. A successful runner exit cannot establish who operated it.
Review logs before sharing: credentials are not passed from ambient EACP key/token
variables, but subprocess output and local paths still require ordinary review.
This is a runner for reviewed code, not a sandbox for malicious repositories.

## One service, two or three approved sources

Copy `PILOT_PROTOCOL.json` into a controlled project record and fill in the actual
service, source scopes, operators, dates, versions and data handling. Obtain the
service owner's permission, data-handling approval and security review **before**
collecting organizational records. All three approval records must identify an
approver, time and scope. Approval to collect is not approval to export publicly.
Use observation-only, scoped read access; this template grants no authority to
modify production, request more credentials or widen collection.

Freeze the populated protocol before seeing results. Record its SHA-256 outside
the protocol file; use a detached receipt rather than attempting a self-referential
file hash. The default plan is 12 consecutive
eligible cases, a fixed observation window, a 20-minute budget per method and
counterbalanced method order. Change these choices before starting if they do
not fit the service, and retain the reason. Both methods receive the same source
snapshot and task. Baseline includes its normal native indexing/search. Count
EACP adapter development, validation, access setup, training, maintenance and
manual recovery separately; a faster query alone does not establish lower cost.

An identified adjudicator establishes distinct expected links without using
EACP output as the definition of correctness. Score both methods against that
same record. Retain failures, timeouts and disagreements. If the expected links
or correctness cannot be established, use `truth_status=unknown`; the evaluator
does not manufacture a denominator or zero false joins.

## Input and descriptive evaluation

The CSV requires these headers:

```text
case_id,method,truth_status,duration_seconds,expected_links,coverage,correct_accepted_links,false_accepted_links,abstentions,operational_cost_minutes
```

`operational_cost_minutes` is optional. Every case needs exactly one `baseline`
and one `eacp` row. Case IDs must be pseudonymous alphanumeric identifiers with
optional dots, underscores and hyphens. Integers and nonnegative decimals are
accepted; blanks, NaN, infinities and negative measurements are rejected except
for the expressly unknown/optional fields below.

For `truth_status=adjudicated`, `expected_links` is a positive shared denominator,
`coverage` is `correct_accepted_links / expected_links` (absolute rounding tolerance
0.000001), and link/abstention counts are nonnegative integers. For
`truth_status=unknown`, leave `expected_links`, `coverage`, `correct_accepted_links`
and `false_accepted_links` blank in both rows. Record duration and abstentions as
observed. Optional per-case costs must be present for both methods or neither.
One-time setup costs belong in the protocol's cost record, not silently in a
per-case comparison.

Evaluate only an existing file containing actual supplied observations:

```sh
python3 scripts/evaluate_pilot_v1_4.py --input OBSERVATIONS.csv --output NEW_ASSESSMENT.json
```

There is no generated sample pilot CSV. The output records input SHA-256, all
paired cases, descriptive mean/median EACP-minus-baseline differences, denominators
and unknown-truth exclusions. Negative duration/cost differences mean less
measured time. Zero accepted links yield an undefined false-acceptance fraction,
not a perfect score. The program validates arithmetic and pairing; it cannot
authenticate the CSV, adjudicator, approvals or independence, and never labels a
pilot successful automatically. Include the populated protocol, detached hash,
adjudication record, real costs, limitations and executor's statement with any
review request.

## Tooling checks

```sh
python3 -m unittest discover -s tests/hardening -p test_external_validation.py -v
```

Tests use clearly synthetic in-memory CSV fixtures, plan inspection, and tiny
local child processes to verify log/failure retention. They never invoke the full
reproduction plan recursively or present fixtures as organizational observations.
