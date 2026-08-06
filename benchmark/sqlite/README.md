# Synthetic SQLite benchmark

`eacp_benchmark.py` is the standard-library-only benchmark used to compare an append-oriented EACP evidence index with six heterogeneous, indexed SQLite source tables.

For each seeded trial, it:

- generates deterministic events for deployment, identity, policy, telemetry, incident, and recovery planes;
- writes the fragmented and normalized alternatives on the same host and SQLite configuration;
- checks sampled reconstruction results row for row;
- checks equal row count and SHA-256 digest for the complete canonical projection;
- reports medians, quartiles, minima, and maxima across sequential trials; and
- removes temporary databases unless `--keep-databases` is requested.

The frozen command and environment are recorded in `data/sqlite/environment.json`. Run the full matrix from the repository root:

```bash
python benchmark/sqlite/eacp_benchmark.py \
  --sizes 10000 50000 100000 \
  --trials 10 \
  --services 200 \
  --query-samples 300 \
  --output reproduction-output/sqlite
```

“Ingestion” is local amortized bulk processing from generated Python dictionaries through one SQLite commit. The benchmark excludes collection transport, concurrent writers, network delay, Kubernetes, and production traffic. EACP is an additional evidence index; its database bytes must not be described as a reduction in source-system storage.

