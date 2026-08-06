# Kubernetes API-server audit evaluation

This experiment captures API-server audit records from a real, single-node Kubernetes cluster and normalizes the records into the EACP evidence schema. It is deliberately small: the purpose is to test executable ingestion, indexed reconstruction, and append-only enforcement, not production-scale performance.

## Design

- Runtime: Docker and kind 0.32.0 with `kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5`.
- Cluster: one control-plane node named `eacp-eval` by default.
- Audit: `RequestResponse` level for selected non-secret resources in namespace `eacp-k8s-eval`.
- Workload: three rounds by default. Each creates, labels, reads, lists, and deletes ConfigMaps and patches one Deployment. Workload annotations carry `eacp.io/correlation-id=eacp-round-NN`.
- Policy check: each round makes one unauthorized operation as the read-only `eacp-observer` service account. The runner requires `Forbidden`, and the analyzer requires one audited HTTP 403 per round.
- Analysis: one normalization pass; 10 sequential raw/EACP persistence trials; 300 indexed service queries and 300 indexed correlation queries.

The audit policy excludes Secrets, TokenReviews, and authorization-review resources. The publication sanitizer removes `sourceIPs` and credential identifiers and redacts filesystem paths and certificate material. Complete API-server logs remain local QA artifacts.

## Run

Requirements: Docker, kubectl, kind, and Python 3.11 or newer.

```bash
./run_experiment.sh
```

To change the controlled workload without editing the script:

```bash
WORKLOAD_ROUNDS=3 OBJECTS_PER_ROUND=20 LISTS_PER_ROUND=10 ./run_experiment.sh
```

The script refuses to replace an existing cluster with the same name. It deletes only the cluster it created; set `KEEP_CLUSTER=1` to retain it for local inspection. Outputs are written under `results/<UTC-RUN>/`, which is ignored because it includes private QA material.

## Canonical result

The reviewed public subset from `20260806T031453Z` is frozen under `data/kubernetes/20260806T031453Z/`. The full descriptive report is `RESULTS_REPORT.md`.

That run captured 1,819 audit records in total and retained 374 sanitized namespace records, normalized to 374 unique EACP rows. It included 132 rows with explicit workload correlation and three audited HTTP 403 denials. Median EACP persistence was 3.002 ms across 10 sequential trials. These are local observations from one cluster, namespace, and CRUD-oriented workload.

## Limits

This evaluation does not cover multi-node scheduling, managed control planes, sustained production load, fault injection, identity-provider logs, observability signals, incident systems, or recovery platforms. Kubernetes audit data covers the API plane only.

