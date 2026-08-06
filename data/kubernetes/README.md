# Sanitized Kubernetes laboratory data

The canonical public run is `20260806T031453Z`. Its run directory contains exactly the eight files approved by the experiment’s publication-scope review:

1. `analysis/public_filtered_audit.jsonl`
2. `analysis/normalized_evidence.csv`
3. `analysis/summary.json`
4. `operations.csv`
5. `policy-denials.txt`
6. `kubernetes-version.json`
7. `nodes.txt`
8. `environment.txt`

## Selection and sanitization

The API server used `RequestResponse` auditing for selected non-secret resources. `analyze_audit.py` retained records associated with namespace `eacp-k8s-eval`, excluded one token-subresource record, removed `sourceIPs` and credential identifiers, redacted certificates and absolute filesystem paths, and replaced service-account token-projection metadata with a redaction marker. The complete 1,819-record API-server log is local QA material and is not in this repository.

The public JSONL contains 374 audit records representing 373 audit IDs. Because one request produced both `ResponseStarted` and `ResponseComplete`, the canonical source key is `auditID:stage`, yielding 374 unique rows. Workload objects annotated with `eacp.io/correlation-id=eacp-round-NN` provide the explicit correlation key for 132 records. `operations.csv` is the client-side workload log; `policy-denials.txt` records the three intended forbidden operations.

Key checksums:

- `public_filtered_audit.jsonl`: `6aa39ee1cf8d3cbf58cb683ed6c7977ce851ab442c7057b7a85e974cb5400e01`
- `normalized_evidence.csv`: `ff03698e83a764651aec912fc806a50464374567ae862936fe32251523d796b5`
- `summary.json`: `b565042468c895620ea8284c928f43bb9c1767a74d82c0cebf8ea62ae7a11cad`

The final repository-wide `MANIFEST.sha256` will cover every published file. Sanitization reduces disclosure risk; it does not make the corpus representative of production Kubernetes activity or prove authenticity of the upstream API-server source.
