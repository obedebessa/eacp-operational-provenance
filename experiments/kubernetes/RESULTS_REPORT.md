# Kubernetes evaluation results

Canonical run: `results/20260806T031453Z` (2026-08-06 UTC).

## Environment and workload

- Apple arm64 host, 16 logical CPUs, 51,539,607,552 bytes RAM.
- Docker client/server 29.1.3 and kind 0.32.0.
- Kubernetes server v1.36.1 from the digest-pinned node image; kubectl
  v1.36.3.
- One control-plane node and one namespace.
- Three sequential workload rounds and 228 recorded client operations.
- Three intentionally unauthorized patch commands under the read-only
  `eacp-observer` identity; all returned HTTP 403. The audit records captured
  two preliminary Deployment GET denials and one ConfigMap PATCH denial.

The API server emitted 1,819 total audit records. After namespace filtering
and exclusion of one token-subresource record, the public corpus contains 374
records representing 373 audit IDs. One audit ID had both `ResponseStarted`
and `ResponseComplete` stages; the EACP source identifier `auditID:stage`
therefore preserved 374 unique rows without collision.

## Descriptive results

| Measure | Result |
|---|---:|
| Public namespace audit records | 374 |
| Normalized EACP rows | 374 |
| Rows with explicit `eacp-round-NN` correlation | 132 |
| Audited RBAC denials | 3 |
| Parse, sanitize, filter, and normalize time | 32.449 ms |
| Amortized normalization time per retained record | 86.763 microseconds |
| EACP SQLite persistence median, 10 sequential trials | 3.002 ms |
| EACP persistence median per event | 8.026 microseconds |
| Raw SQLite persistence median, 10 sequential trials | 3.629 ms |
| Service query median / p95, 300 samples | 0.0061 / 0.0116 ms |
| Correlation query median / p95, 300 samples | 0.0062 / 0.0114 ms |
| Public filtered JSONL size | 975,250 bytes |
| Normalized CSV size | 146,001 bytes |
| EACP SQLite size | 290,816 bytes |

Both query plans used their intended SQLite indexes. The stored row count
matched the filtered input, all 374 hashes of sanitized canonical tuples were distinct, and attempts
to update or delete evidence rows were rejected by the append-only triggers.

These timings are local microbenchmarks over one captured dataset. The raw and
EACP persistence numbers use different schemas and should be reported as
descriptive costs, not as evidence that one system is universally faster.

## Privacy and release status

The publication-safe JSONL contains no certificate bodies, `ca.crt` keys,
authentication credential identifiers, issued credential identifiers,
`sourceIPs`, JWT prefixes, or local host paths. Service-account token
projection metadata is replaced with a redaction marker, and token-subresource
records are excluded. The complete audit log remains under `audit-host/` for
local QA and must not be published.

`PUBLIC_SHA256SUMS` verifies the eight approved public result files. The
all-files `SHA256SUMS` also verifies the preserved local QA artifacts.

## Limits

This experiment used one local single-node cluster, a small CRUD-oriented
workload, one namespace, and no fault injection. It evaluates Kubernetes API
audit ingestion only. It does not estimate production throughput, managed
control-plane behavior, multi-node availability, or cross-plane collection
from telemetry, identity providers, incident systems, and recovery platforms.
