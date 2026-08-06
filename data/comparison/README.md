# Frozen OpenTelemetry comparison data

The canonical run is `20260806T032418Z` and contains:

| File | Contents |
|---|---|
| `summary.json` | Method, scope, descriptive statistics, immutable image metadata, and validation results |
| `trials.csv` | Ten paired sequential trials per pipeline in alternating order |
| `environment.json` | Safe host and fixed Collector metadata |
| `SHA256SUMS` | Checksums for those three run files |

The shared input is the 374-record sanitized Kubernetes JSONL with SHA-256 `6aa39ee1cf8d3cbf58cb683ed6c7977ce851ab442c7057b7a85e974cb5400e01`. The Collector Contrib 0.158.0 image resolved to `sha256:c5918f78992ee73b0d6f0e599423ac5ec52dd5d9726733114d6eca53d5a32ed5`.

The Collector retained each raw Kubernetes audit line as an exported OpenTelemetry log body. Its configured parser also populated attributes, but the post-export EACP validator operated on the retained body; the Collector did not natively generate the EACP 13-field schema. Outside the timed interval, the external validator extracted and normalized those bodies, matched 4,862/4,862 compared values, and reproduced canonical projection digest `196d4a1bf8d057d9fe9e6f18062b7c5ac5228642df3098b28c84fb48d7a67da6`.

Median observed time to validated output was 60.659 ms for the fresh EACP Python process and 622.477 ms for the fresh Collector container. The Collector boundary includes host-side reading and JSON decoding of the complete export; EACP projection reading occurs later during validation. Process startup, isolation, validation placement, and output formats differ, and output sizes compare indexed SQLite with unindexed OTLP/JSON. The derived event/s values are amortized completion rates, not ingestion throughput; none of these measurements establishes that either implementation is universally faster or more storage-efficient.
