# Frozen synthetic SQLite results

The files in this directory were produced by 10 sequential seeded trials at 10,000, 50,000, and 100,000 events, with 200 services and 300 samples per query class.

| File | Contents |
|---|---|
| `trial_results.csv` | One row per trial, including seed, timings, sizes, verification counts, and complete-projection digest |
| `summary_results.csv` | Median, quartiles, minimum, and maximum for every reported metric |
| `summary_results.json` | JSON rendering of the aggregate CSV |
| `query_plans.json` | Representative SQLite query plans showing the fragmented and EACP indexes used |
| `environment.json` | Sanitized host metadata and repository-relative reproduction command |

At 100,000 events, median EACP ingestion was 5.3319 microseconds/event (187,549.7 events/s). Median service-query p95 was 1.1414 ms for the fragmented schema and 0.6909 ms for EACP; median correlation-query p95 was 0.04538 ms and 0.02245 ms, respectively. The separate databases occupied 228.393 and 413.983 bytes/event. These are local warm-cache microbenchmark observations, not production estimates.

The source environment record contained an absolute interpreter path and an output path. `environment.json` replaces only those paths with the portable repository command; the recorded numeric environment values are unchanged.

