# EACP SQLite index ablation

This experiment answers a narrow threat to interpretation in the v1.2 pilot:
**how much of the EACP lookup result and cost is attributable to its two lookup
indexes?** It is an ablation of the EACP implementation, not a new comparison
against an unindexed source-system baseline.

The experiment imports `benchmark/sqlite/eacp_benchmark.py` directly. It does
not copy or reimplement the workload. The imported generator, normalizer,
content-hash path, SQLite settings, evidence table, queries, full-projection
digest, and original seed schedule remain unchanged. The frozen run anchors
that source file as SHA-256
`a4c372526a6ce9641f22b0cdf9f1642d8474fbd5f1bfc925d513f04ecce7d4ee`.
The driver hash is also recorded in the frozen machine-readable results and
checked by the verification command; for this run it is
`cad9cf302ea1083c86039803422942fad7b0607a4ee917b49f987f93762b28d1`.

## Treatments

All four databases in a paired trial receive the same events and queries:

| Variant | `(service, source_ts)` | `(correlation_id, source_ts)` | `(source_type, source_ts)` | UNIQUE + triggers |
| --- | ---: | ---: | ---: | ---: |
| `full_indexes` | kept | kept | kept | kept |
| `no_service_index` | removed | kept | kept | kept |
| `no_correlation_index` | kept | removed | kept | kept |
| `no_lookup_indexes` | removed | removed | kept | kept |

The code removes only the two exact `CREATE INDEX` statements from the
published schema. It asserts the realized index inventory before measurement.
`EXPLAIN QUERY PLAN` independently confirms that removing a target index changes
the corresponding lookup from `SEARCH ... USING INDEX` to `SCAN evidence` at
all three data sizes.

## Frozen design

- 10 original-schedule seeds at each of 10,000, 50,000, and 100,000 events;
- 200 services and deterministic six-plane chains;
- 300 service and 300 correlation queries per trial, matching the original
  benchmark and paired by exact key across all variants;
- one untimed pass over every measured key immediately before the warm-cache
  pass;
- 20 service and 20 correlation cold-open samples per trial;
- deterministically rotated database-build and per-query variant order;
- `ANALYZE` plus `VACUUM` before file-size measurement; and
- complete projection and per-query equivalence checks that abort the run on
  the first mismatch.

The cold-open measure includes `sqlite3.connect`, the first execute/fetch, and
close. Each sample therefore starts with a new connection-local SQLite page
cache. It **does not** flush or claim control over the operating-system page
cache. “Cold-open” must not be reported as cold disk I/O.

The trial—not an individual query—is the analysis unit. Each p95 is calculated
within a trial, then the summary reports the median, Q1, Q3, minimum, and maximum
of the 10 trial values. These are descriptive measurements of this host and
workload. No population, independence, normality, confidence interval, p-value,
or statistical-significance claim is made.

## Frozen results

The table reports medians across the 10 trials. The latency ratio is calculated
within each paired trial and then summarized. The targeted one-index ablation is
used for each lookup, so the service factor compares `no_service_index` with
`full_indexes`, and the correlation factor compares `no_correlation_index` with
`full_indexes`.

| Events | Full service p95 (ms) | No service index (ms) | Ratio | Full correlation p95 (ms) | No correlation index (ms) | Ratio |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 10,000 | 0.073 | 0.363 | 5.08× | 0.023 | 0.370 | 15.94× |
| 50,000 | 0.362 | 1.943 | 5.36× | 0.048 | 2.099 | 44.62× |
| 100,000 | 0.691 | 3.884 | 5.65× | 0.056 | 4.182 | 73.91× |

The correlation query returns approximately six rows regardless of data size,
whereas the service query returns progressively more rows. Ratios across these
two query families therefore should not be compared as if their selectivity or
result-materialization cost were the same.

The separate cold-open results show the same directional effect while including
connection setup and first-touch work:

| Events | Full service (ms) | No service index (ms) | Ratio | Full correlation (ms) | No correlation index (ms) | Ratio |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 10,000 | 0.203 | 0.959 | 4.70× | 0.139 | 0.955 | 6.99× |
| 50,000 | 0.546 | 4.513 | 8.14× | 0.273 | 4.444 | 15.87× |
| 100,000 | 0.912 | 8.085 | 8.84× | 0.295 | 7.886 | 27.24× |

The storage and ingestion tradeoff is similarly consistent. “Reduction” is the
median paired-trial reduction after removing the named index or indexes. The
single-index ingestion reductions need not add to the joint reduction because
elapsed time includes shared normalization, hashing, transaction, and storage
work, as well as host noise.

| Events | Full ingest (µs/event) | Remove service | Remove correlation | Remove both | Full bytes/event | Service-index share | Correlation-index share | Both shares |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 10,000 | 4.587 | −8.08% | −6.96% | −14.36% | 414.925 | 10.267% | 12.537% | 22.804% |
| 50,000 | 4.775 | −10.05% | −7.51% | −17.59% | 412.795 | 10.141% | 12.562% | 22.703% |
| 100,000 | 4.815 | −11.57% | −6.56% | −17.90% | 413.983 | 10.161% | 12.615% | 22.776% |

At 100,000 events:

- the full-index database was 41,398,272 bytes (413.983 bytes/event);
- the service index occupied 4,206,592 bytes, or 10.161% of the full file;
- the correlation index occupied 5,222,400 bytes, or 12.615% of the full file;
- together the lookup indexes occupied 9,428,992 bytes, exactly matching the
  22.776% file-size reduction in `no_lookup_indexes` on this SQLite build;
- full-index ingestion was 4.815 microseconds/event; removing both lookup
  indexes reduced paired trial ingestion time by a median 17.900%; and
- in the cold-open measure, removing the target index changed service p95 from
  0.912 to 8.085 ms (8.84×) and correlation p95 from 0.295 to 7.886 ms
  (27.24×).

All 30 workload trials passed SQLite integrity checks. Across the campaign,
1,600,000 generated rows were projected in each variant (6,400,000 projected
rows in total), and all four variants had an identical full-projection row count
and SHA-256 within every trial. The 18,000 warm query cases and 1,200 cold-open
query cases were also identical row for row across variants; no mismatch was
observed.

### Interpretation

The ablation shows that the two B-tree lookup indexes are responsible for a
material fraction of EACP's database bytes and insertion cost—and are necessary
for its observed lookup latency at these sizes. This bounds the v1.2 result more
precisely: it is a result for an intentionally indexed evidence store. It does
not imply that normalization alone makes an unindexed EACP store fast.

This does not invalidate the original indexed comparison. The six fragmented
source tables in that benchmark also have service/time and correlation/time
indexes. The original result therefore compared indexed alternatives; this
ablation separately exposes the cost and necessity of the EACP-side indexes.

The experiment does not establish production latency, concurrency behavior,
write contention, durability cost under other PRAGMAs, or performance on a
different database engine. The synthetic workload and local SQLite limitations
of the original benchmark continue to apply.

## Reproduce and verify

Run from the repository root with Python 3.10 or newer:

```bash
python3 experiments/index_ablation/index_ablation.py \
  --sizes 10000 50000 100000 \
  --trials 10 \
  --services 200 \
  --query-samples 300 \
  --cold-open-samples 20 \
  --output experiments/index_ablation/results/reference
```

Verify the frozen files without rerunning the timings:

```bash
python3 experiments/index_ablation/index_ablation.py \
  --verify experiments/index_ablation/results/reference
```

Run the experiment-specific tests:

```bash
python3 -m unittest discover \
  -s experiments/index_ablation \
  -p 'test_*.py' -v
```

## Result files

- `method.json`: machine-readable design, treatments, pairing, and claims
  boundary;
- `environment.json`: runtime, SQLite build, source checksum, and cold-open
  definition;
- `trial_results.csv` and `.json`: one row per event-count/seed/variant trial;
- `query_measurements.csv`: wide paired warm timings for every query key;
- `cold_open_measurements.csv`: wide paired new-connection timings;
- `summary_results.csv` and `.json`: descriptive trial-level summaries;
- `query_plans.json`: index inventory and plans for every size and variant; and
- `SHA256SUMS`: integrity inventory for every frozen result file.
