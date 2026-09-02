# Adversarial correlation-robustness experiment

This standard-library-only experiment measures what happens when the metadata
needed to reconstruct an operational chain is incomplete, ambiguous, or late.
It supplies the fault-injection result that the v1.2 pilot intentionally did
not claim: reconstruction quality under broken correlation assumptions.

The experiment is deterministic, fully synthetic, and contains no user,
credential, repository, or production data. It is a bounded robustness study,
not evidence of production-scale reliability.

## Why this is separate from the v1.2 benchmark

An audit of `benchmark/sqlite/eacp_benchmark.py` found four design facts that
matter for interpreting this experiment:

1. Every six consecutive generated events form one truth chain, with one event
   from each of deployment, identity, policy, telemetry, incident, and recovery.
2. The raw source schemas and the normalized `evidence` schema declare their
   correlation columns `NOT NULL`.
3. The v1.2 reconstruction query uses `correlation_id` alone, through the
   `ev_correlation` index.
4. The v1.2 synthetic ingestion assigns source time as observation time and
   therefore does not model missing IDs, late arrival, or event reordering.

Changing those assumptions inside the archived benchmark would silently alter
the v1.2 artifact. This experiment instead keeps evaluation-only fields outside
the reconstructors and models a candidate strict policy in which an event joins
a chain only when both `service` and `correlation_id` are present. Missing IDs,
same-source payload conflicts, and observable candidate-group contradictions
cause abstention: the evidence is retained as an individual record but is not
silently unioned into a multi-event chain. No imputation is performed.

The experiment does **not** claim that the v1.2 database already implements the
composite key. The correlation-ID-only ablation is included specifically to
show the consequence of the v1.2 lookup-key shape under cross-service reuse.

## Research questions

- **RQ-R1 — Missingness:** How quickly do exact-chain coverage and pairwise join
  recall degrade when 1%, 5%, 10%, or 20% of identifiers are absent?
- **RQ-R2 — Mislabeling:** Does substituting a plausible but wrong same-service
  identifier produce a detectable contradiction or a silent union?
- **RQ-R3 — Concentration:** Is losing one complete source plane different from
  random missingness at a similar aggregate rate?
- **RQ-R4 — Reuse:** Which failures result from identifier reuse within a
  service, and does service scoping contain reuse across services?
- **RQ-R5 — Record integrity:** Can exact replays be suppressed while a
  same-source-ID/different-payload observation triggers safe abstention?
- **RQ-R6 — Time:** Do clock skew, late arrival, and out-of-order delivery affect
  final membership, evidence-availability latency, or both?
- **RQ-R7 — Safety trade-off:** What precision is lost when a temporal-only
  heuristic recovers chains without identifiers?

## Synthetic workload and controlled overlap

Each truth chain has exactly six events and spans 1,250 ms. Services receive
chains in paired rounds. In a deterministic 25% of pairs, the second chain for
the same service begins 800 ms after the first and therefore overlaps it. Other
pairs are separated by 10 seconds. This mixture prevents a temporal heuristic
from being either trivially perfect or uniformly impossible.

The reference matrix uses 600 truth chains (3,600 canonical events), 24
services, and 30 predetermined seeds. This is repeated seeded sensitivity
analysis, not a sample from a claimed production population:

```text
9238 9339 9440 9541 9642 9743 9844 9945 10046 10147
10248 10349 10450 10551 10652 10753 10854 10955 11056 11157
11258 11359 11460 11561 11662 11763 11864 11965 12066 12167
```

Exact hash-ranked selection is used for every percentage. Thus “10% missing”
means exactly 360 of 3,600 events per seed, not an expected Bernoulli count.

## Reconstruction policies

### Strict service + correlation

The candidate safety-first policy groups only on the complete composite key
`(service, correlation_id)`. It suppresses exact source replays. It abstains
when an ID is missing, when one `(source_type, source_id)` has conflicting
payload hashes, or when a candidate group violates observable workload
invariants (duplicate plane, excessive time span, or inconsistent six-plane
cadence). Abstained records remain individually visible. This avoids silent
contamination at the cost of explicitly measured coverage and abstention.

### Correlation-ID-only ablation

This non-abstaining ablation removes service scoping and groups on
`correlation_id`, matching
the key shape of the v1.2 reconstruction query. It is not presented as a
separate tool or industry baseline. Its purpose is to isolate the effect of the
composite key.

### Naive temporal window

The comparator ignores identifiers, sorts post hoc by source timestamp within
each service, and greedily groups events within a 1,500 ms window anchored at
the first event of each episode. It receives the favorable benefit of offline
source-time sorting: arrival reordering affects its time-to-completeness but not
its final grouping.

This comparator is scientifically useful only as an illustrative safety-
coverage boundary. It is **not** a proxy for a SIEM, tracing backend, causal
inference system, or production correlation engine.

## Fault matrix

| Family | Scenarios | Exact perturbation |
|---|---|---|
| Control | `control` | Complete IDs; 25 ms natural observation delay |
| Random missingness | `missing_random_{1,5,10,20}pct` | Remove exactly the named fraction of event IDs |
| Wrong-ID substitution | `wrong_id_same_service_{1,5,10,20}pct` | Replace exactly the named fraction with an ID from another chain of the same service |
| Plane-concentrated missingness | six `missing_plane_*` scenarios | Remove every ID from one plane (1/6 of events) |
| Same-service reuse | `collision_same_service_{1,5,10}pct` | Create `round(rate × chains)` disjoint donor/victim pairs; both chains are exposed |
| Cross-service reuse | `collision_cross_service_5pct` | Same construction, with donor and victim services required to differ |
| Exact replay | `duplicate_exact_10pct` | Add an exact second observation for 10% of canonical source records |
| Source conflict | `duplicate_source_conflict_5pct` | Add a different payload hash under the same source plane and source ID for 5% of records |
| Clock skew | `clock_skew_random_10pct_5s` | Shift logged source time by deterministic +5 s or −5 s for exactly 10% of events; arrival is unchanged |
| Late arrival | `late_arrival_10pct_30s` | Add 30 seconds to exactly 10% of arrivals |
| Reordering | `out_of_order_jitter_3s` | Add deterministic independent 0–3 second jitter |
| Compound | `compound_adversarial` | 10% missing + 5% same-service reuse + 10% 30-second delay + 0–3 second jitter |

“A 5% collision rate” denotes 5% as many reuse pairs as truth chains. Because
each pair has one donor and one victim, up to 10% of chains are exposed. The
counts are written into every trial row.

## Metrics

Ground truth is used only for scoring, never for reconstruction or warning
generation.

- **Complete-chain coverage:** fraction of truth chains recovered as one group
  containing all and only that chain's events.
- **Exact-chain accuracy / recall:** the same closed-set fraction, emitted under
  an explicit name so it cannot be confused with pairwise recall.
- **Exact-chain precision:** exact, uncontaminated chain groups divided by all
  emitted groups containing at least two distinct canonical events. **Exact-
  chain F1** is its harmonic mean with exact-chain recall.
- **Mean chain-member coverage:** mean fraction of each truth chain found in its
  best reconstructed group; foreign contamination does not lower this metric.
- **Missed joins:** truth same-chain event pairs that were not joined. The rate
  divides by all truth same-chain pairs.
- **False joins:** predicted event pairs drawn from different truth chains. The
  rate divides by all predicted pairs.
- **Join precision / recall:** pairwise clustering precision and recall.
- **Ambiguous candidate group:** a pre-policy key group containing more than one
  truth chain. **Accepted ambiguous groups** count those still emitted after
  policy handling and therefore expose silent union.
- **Ambiguity detection:** precision and recall of warnings generated without
  truth labels. A warning fires when a group repeats a modeled source plane or
  violates the canonical 1,250 ms span/cadence. The strict policy splits a
  warned candidate into individually retained, abstained records.
- **Source-conflict detection:** precision and recall for observable
  same-source-ID/different-payload conflicts.
- **Abstention rate:** retained observations withheld from multi-event joins,
  divided by all input observations. **Deduplication rate** is reported
  separately for exact replays suppressed before reconstruction.
- Zero-denominator detection precision or recall is emitted as JSON `null` / a
  blank CSV cell, not as a perfect score.
- **Time-to-completeness:** for exactly recovered, uncontaminated chains only,
  last evidence arrival minus first physical source event. This deliberately
  does not use a clock-skewed logged timestamp. The observation count is always
  reported; if no chain qualifies, percentiles are undefined.
- **Arrival inversions:** exact inversion count between physical source order
  and arrival order, plus its normalization over canonical-event pairs.

Pairwise metrics are computed over unordered event pairs. With six events per
truth chain, each intact chain contributes `C(6,2) = 15` true joins.

## Reproduce

From the repository root, run the tests:

```bash
python3 -m unittest discover \
  -s experiments/correlation_robustness \
  -p 'test_*.py' -v
```

Run the frozen reference matrix:

```bash
python3 experiments/correlation_robustness/correlation_robustness.py \
  --chains 600 \
  --services 24 \
  --missing-rates 0.01 0.05 0.10 0.20 \
  --collision-rates 0.01 0.05 0.10 \
  --overlap-fraction 0.25 \
  --temporal-window-ms 1500 \
  --output experiments/correlation_robustness/results/reference
```

Verify the emitted artifacts:

```bash
cd experiments/correlation_robustness/results/reference
shasum -a 256 -c SHA256SUMS
```

No network access, external packages, containers, or credentials are required.
The omitted `--seeds` option deliberately selects the 30 frozen defaults listed
above. The deterministic result files are `trial_results.csv`,
`trial_results.json`, `summary_results.csv`, `summary_results.json`, and the
generated `figure_correlation_robustness.svg`. `environment.json` records the
local runtime and generation time, so that file is expected to differ across
reproductions. `SHA256SUMS` binds every emitted file. The figure can be
regenerated independently with `python3
experiments/correlation_robustness/generate_figure.py`.

## Reference-run results

The following values are medians across the 30 declared seeds. Percentages
are rounded for readability; machine-readable files retain full precision.

### Missing identifiers: strict composite policy

| Missing IDs | Exact-chain accuracy | Exact-chain F1 | Abstention | Missed joins | False joins | Pairwise recall |
|---:|---:|---:|---:|---:|---:|---:|
| 0% | 100.00% | 100.00% | 0.00% | 0.00% | 0.00% | 100.00% |
| 1% | 94.17% | 94.17% | 1.00% | 1.99% | 0.00% | 98.01% |
| 5% | 73.25% | 73.25% | 5.00% | 9.77% | 0.00% | 90.23% |
| 10% | 53.00% | 53.00% | 10.00% | 19.00% | 0.00% | 81.00% |
| 20% | 26.17% | 26.18% | 20.00% | 35.98% | 0.00% | 64.02% |

The curve is consistent with the structure of a six-event chain: random event
loss makes exact recovery decline much faster than the raw missing-ID rate.
The important safety result is bounded: the strict policy makes fewer joins but
does not fabricate a join in these missing-only scenarios.

Removing all IDs from any one plane (16.67% aggregate missingness) yielded 0%
exact-chain accuracy/F1, 16.67% abstention, 33.33% missed joins, 0% false joins,
and 66.67% pairwise recall. This is worse for exact recovery than similarly
sized random missingness because every chain is affected.

### Wrong-ID substitution: strict composite policy

| Wrong event IDs | Exact-chain accuracy | Exact-chain F1 | Abstention | False joins | Pairwise recall | Detection recall |
|---:|---:|---:|---:|---:|---:|---:|
| 1% | 88.67% | 91.33% | 6.86% | 0.00% | 92.23% | 100.00% |
| 5% | 54.25% | 62.13% | 29.47% | 0.00% | 66.99% | 100.00% |
| 10% | 28.83% | 37.34% | 50.96% | 0.00% | 44.14% | 100.00% |
| 20% | 7.08% | 10.92% | 76.53% | 0.00% | 18.66% | 100.00% |

A wrong identifier has a larger blast radius than an absent identifier because
it can contaminate the otherwise valid donor candidate. In this synthetic
protocol the cadence/duplicate-plane checks detected every mixed candidate and
strict mode accepted none of them. The cost is deliberately visible: abstention
can exceed the injected-event rate because the whole ambiguous candidate is
withheld from joining.

### Identifier reuse

| Scenario | Policy | Exact-chain accuracy | Abstention | False joins | Join precision | Accepted ambiguous groups | Detection recall |
|---|---|---:|---:|---:|---:|---:|---:|
| Same service, 1% pairs | Strict composite | 98.00% | 2.00% | 0.00% | 100.00% | 0 | 100.00% |
| Same service, 5% pairs | Strict composite | 90.00% | 10.00% | 0.00% | 100.00% | 0 | 100.00% |
| Same service, 10% pairs | Strict composite | 80.00% | 20.00% | 0.00% | 100.00% | 0 | 100.00% |
| Cross service, 5% pairs | Strict composite | 100.00% | 0.00% | 0.00% | 100.00% | 0 | n/a |
| Cross service, 5% pairs | ID-only ablation | 90.00% | 0.00% | 10.71% | 89.29% | 30 | 100.00% |

Service scoping contains cross-service reuse in this model. For same-service
reuse, the strict policy detected every mixed candidate in these seeded trials
and abstained instead of emitting the union. The ID-only ablation shows what
would have been silently accepted without the guard. Detection does not repair
a chain and is not proof of universal collision detection.

### Duplicate records and clock skew

- Replaying exact copies for 10% of canonical events produced a 9.09% input-
  observation deduplication rate and left strict exact-chain accuracy,
  precision, and recall at 100%.
- Adding conflicting payloads under 5% of source IDs yielded 100% source-
  conflict detection, 9.52% observation abstention, 73.42% exact-chain
  accuracy, 0% false joins, and 100% pairwise precision in strict mode.
- Skewing 10% of logged source timestamps by ±5 seconds did not create arrival
  inversions, because physical source and arrival time were unchanged. The
  strict cadence guard conservatively abstained on affected candidates: median
  exact-chain accuracy was 53.00%, abstention 47.00%, and false joins 0%.
  The correlation-ID-only ablation retained 100% membership because it ignores
  time; this contrast isolates the safety/availability cost of the cadence rule.

### Temporal comparator and delivery disorder

In the control scenario, the temporal comparator reached 75.33% exact-chain
accuracy and 92.60% pairwise recall, but its false-join rate was 13.78% (86.22%
precision). Its grouping is unchanged by missing or reused IDs because it does
not inspect them. This demonstrates the intended trade-off, not a superiority
claim: higher coverage under missingness can be purchased by accepting silent
cross-chain joins.

For the strict policy, neither 30-second late arrivals nor 0–3 second jitter
changed final membership: coverage, precision, and recall remained 100% in
their isolated scenarios. They did change availability. Median-across-seeds
p95 time-to-completeness increased from 1,275 ms in control to 4,125.7 ms with
jitter and 31,275 ms with 10% late arrivals.

Under the compound scenario, the strict policy recorded 47.33% exact-chain
accuracy, 49.82% exact-chain F1, 19.01% abstention, 27.14% missed joins, 0%
false joins, 100% pairwise precision, 72.86% pairwise recall, no accepted mixed
group, and 100% ambiguity-detection recall for the mixed candidates that
occurred. These values are a property of this fixed synthetic design and must
not be generalized to production prevalence or performance.

## Interpretation limits

- This is a controlled sensitivity analysis, not a field evaluation.
- Synthetic truth makes exact error counting possible but cannot reproduce the
  dependencies, clock pathologies, retention gaps, or actor behavior of a real
  multi-system deployment.
- The temporal comparator has one fixed window. A window sweep would be needed
  to characterize its full precision-recall frontier.
- The collision detector relies on the modeled invariant of at most one event
  per plane and an exact synthetic cadence/span. Other workloads need learned
  or declared domain invariants, and semantically plausible complete-chain
  substitution can evade structural checks.
- Late evidence is never dropped in this offline experiment. A production
  watermark or retention cutoff could convert delay into missingness.
- Results establish behavior of the evaluated policies under declared faults;
  they do not establish causality, cryptographic integrity, or completeness of
  the underlying source systems.

The deliberately unclaimed extensions and a preregistration-style next-stage
plan are recorded in [`LIMITATIONS_AND_NEXT_PROTOCOL.md`](LIMITATIONS_AND_NEXT_PROTOCOL.md).
