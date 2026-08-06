# Kubernetes publication scope

The canonical public run directory `data/kubernetes/20260806T031453Z/` contains exactly these eight reviewed result files:

1. `analysis/public_filtered_audit.jsonl`
2. `analysis/normalized_evidence.csv`
3. `analysis/summary.json`
4. `operations.csv`
5. `policy-denials.txt`
6. `kubernetes-version.json`
7. `nodes.txt`
8. `environment.txt`

The source-run `PUBLIC_SHA256SUMS` was used to verify those eight files before staging. The final repository-wide `MANIFEST.sha256` will cover the frozen copies after the paper and DOI metadata are complete.

Do not publish `audit-host/audit.log`, generated `kind-config.yaml`, `cluster-state.yaml`, namespace-event dumps, analysis-console output, SQLite databases, pre-privacy output, or the all-files source-run checksum manifest without a separate disclosure review. Those files are local QA material.

`analyze_audit.py` deterministically selects records associated with `eacp-k8s-eval`, excludes the token subresource, removes `sourceIPs` and credential identifiers, and redacts certificates and absolute filesystem paths while retaining Kubernetes API request URIs.

