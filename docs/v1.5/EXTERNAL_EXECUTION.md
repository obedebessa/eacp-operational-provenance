# Supplied external execution: bounded evidence record

Original candidate: `e2807efc14209e42ba5ac82f5aa8d44599d22c43`.
Original source tree: `8026f080f7beeedfd97fcd7b7e61303cbb200ae9`.
Original candidate ZIP SHA-256:
`0f67dd872f666758221027ed8952e0081e07831323e98f6e3340562419d91bb5`.
Execution date recorded: 2026-09-05. Public executor identifier: External Executor E1.

These records were supplied to the project. The project maintainer attributes the
execution to an external person; public copies suppress the person's name. The
logs and hashes do not authenticate a human identity or prove independence from
the development team. The separate identifying declaration governs what the
person states they performed. Do not infer absence of assistance from edited
names or from hardcoded `external_human_execution`/`operator` fields.

## Recorded outcomes

| Execution phase | Result |
|---|---|
| Initial five suites | 276 discovered: 275 passed, one skipped, no failures/errors |
| Optimized-mode repeat | 52 passed; a repeat, not 52 new distinct tests |
| Installed demo | 17 commands met expected exits, including tampering rejection |
| Mutation sentinels | Three specified weakened checks detected by assertions |
| Campaign | Three 2,000-event scenarios, a 200-event burst, a 600-event short soak |
| Cryptographic follow-up | Previously skipped historical 1.3 test passed; hardening suite 112 passed with no skips |

The nominal scenarios recovered all expected events. Burst admission initially
queued 64 and rejected 136, then recovered all 200 after retry. The short soak
lasted about 30 seconds. This is neither long-term endurance nor a deployment study.
Completeness without a finite source inventory remains UNKNOWN.

The addendum verifies historical run 33690440169, attempt 1, source
`4cbf7d2fa0bb44585d258a3f37ce0c0d39ddea43`, workflow
`eacp-cross-plane-v1.3.yml`. It does not authenticate a new 1.5 tree. The recorded
TAR digest is `26b609cdec31f26aec7f721114274794940d3e1fcb76665c9f3cd1ebb59dda3b`.

## Handling of the submissions

The latest `SUMMARY_updated.md` is the authoritative supplied summary for this
delivery. Superseded summaries are not presented as current. The original
submitted ZIPs remain retained separately; the delivery is a privacy projection
with its own hashes, not a claim that an old internal checksum matches edited
Markdown. Count successful tests across the recorded phases without summing
repeated suites into a new coverage figure.

Raw logs, generated JSON and result codes remain attached in the review package;
path redactions are traceable by original/derivative hashes. No missing bootstrap
logs, no new expert conclusion and no independently designed adversarial cases
are invented. This closes the recorded CLI-availability skip, not every remaining
research, adoption or security question.
