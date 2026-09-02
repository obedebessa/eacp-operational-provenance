# Limitations and next protocol

This file separates what the current experiment establishes from follow-on
work that should not be improvised after inspecting the results.

## Claims supported by this experiment

For the declared synthetic generator, fixed fault matrix, and 30 predetermined
seeds, the result files support quantitative statements about:

- exact and pairwise reconstruction degradation under random and plane-
  concentrated missing identifiers;
- wrong-ID substitution and identifier reuse within or across services;
- exact replay suppression and same-source-ID/different-payload detection;
- constant clock offsets, transport jitter, and late arrivals as separately
  controlled perturbations; and
- the measured coverage cost of a strict policy that abstains rather than
  silently emitting observably contradictory candidate groups.

The results do not support claims about production fault prevalence, external
validity, statistical population parameters, causal inference, adversarial
security, cryptographic integrity, or end-to-end completeness of source logs.

## Known limitations

1. **Synthetic cadence is unusually legible.** The strict detector can compare
   source-plane timestamps against an exact 250 ms cadence. A real deployment
   would need independently specified causal or timing invariants. Reusing this
   synthetic rule in production would be unjustified.
2. **Complete-looking semantic substitution remains possible.** An attacker or
   fault that replaces an entire internally consistent chain, including service
   and identifiers, may evade structure-only checks. Source authentication and
   signed attestations are outside this experiment.
3. **Only one temporal window is reported.** The 1,500 ms comparator is an
   illustrative ablation. It is not tuned and is not a proxy for any named
   observability or security product.
4. **No online watermark or eviction exists.** The evaluator retains all late
   evidence. A bounded online store could turn long delay into effective loss.
5. **Clock faults are fixed offsets.** Drift, clock steps, leap behavior, NTP
   correction, and inconsistent timezone parsing are not modeled.
6. **Duplicates are local source-key cases.** Replay storms, duplicated batches,
   hash collision, canonicalization differences, and concurrent updates are not
   modeled.
7. **The six planes are symmetric.** Plane-specific reliability, fan-out,
   optional events, multiple events per plane, and chains of unequal length are
   not represented.
8. **Seeded trials are not production samples.** Quartiles summarize variation
   in deterministic selections and controlled overlap schedules. They do not
   justify population confidence intervals or hypothesis-test p-values.
9. **Time-to-completeness is conditionally observed.** It is defined only for
   exact, uncontaminated reconstructions. Always report its observation count;
   comparing latency alone can hide coverage loss.
10. **The strict composite policy is a candidate v1.3 policy.** The archived
    v1.2 SQLite query remains correlation-ID-only. This directory does not
    retroactively change that implementation.

## Preregistered next-stage protocol

The next evaluation should freeze the following choices before inspecting new
results.

### A. Temporal sensitivity frontier

- Sweep anchored windows of 250, 500, 750, 1,000, 1,250, 1,500, 2,000, 3,000,
  5,000, and 10,000 ms.
- Report pairwise precision/recall, exact-chain F1, and abstention where used.
- Select no “best” window after looking at the test corpus. If tuning is needed,
  partition seeds or corpora into tuning and locked evaluation sets.

### B. Structural generalization

- Vary chain length and allow 0–3 legitimate events per plane.
- Draw per-plane delays from predeclared distributions rather than a fixed
  cadence.
- Include overlapping chains from the same actor and service with identical
  action types.
- Evaluate detector rules specified without access to test truth labels.

### C. Stronger corruption

- Corrupt service labels independently of correlation IDs.
- Include full, internally consistent chain substitution as an expected-
  undetectable negative control.
- Add partial source-ID conflict, replay bursts, hash/canonicalization mismatch,
  and delayed conflict resolution.
- Report alert precision as well as recall; a detector that abstains on all
  traffic is not useful.

### D. Online delivery behavior

- Predeclare watermarks and retention limits.
- Replay the same canonical records in arrival order.
- Report provisional-chain revisions, time to first correct chain, time to
  stable chain, late-drop rate, and coverage censored by the watermark.
- Separate clock drift from network/collector delay throughout.

### E. Two-emitter external validation

- Use a sanitized, non-secret corpus emitted independently by a CI system and
  Kubernetes.
- Freeze a mapping from native record fields to service, source ID, timestamp,
  and correlation ID before scoring.
- Have a second person label a subset and report agreement and adjudication.
- Keep raw authoritative records outside the normalized index and bind the
  released subset with checksums.
- Run the strict composite, correlation-only ablation, and temporal frontier on
  the same locked corpus.

## Reporting guardrails

- Publish all configured conditions, including unfavorable results.
- Report raw counts beside rates and medians with Q1/Q3; do not report a latency
  percentile without its exact-chain observation count.
- Call undefined zero-denominator detection metrics “not evaluable,” not 100%.
- Distinguish candidate groups, detected contradictions, abstained records, and
  accepted groups in every table.
- Do not describe abstention as successful reconstruction.
- Do not describe the temporal comparator as a SIEM, trace system, or industry
  baseline.
- Do not generalize synthetic rates to operational deployments.
