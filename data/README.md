# Frozen data

This directory contains the machine-readable inputs and outputs used to audit the reported results.

| Directory | Contents |
|---|---|
| `sqlite/` | Deterministic synthetic trial data, summaries, environment metadata, and query plans |
| `kubernetes/20260806T031453Z/` | Exactly eight reviewed files: sanitized namespace corpus, canonical projection, ground truth, versions, and measurements |
| `comparison/20260806T032418Z/` | Collector/EACP paired-trial data, validation summary, environment metadata, and run checksums |

Data and accompanying documentation are licensed under CC BY 4.0. Paths are repository-relative, the producing commands are documented in the adjacent READMEs, and the final repository manifest will cover all archival files.

This tree must not contain kubeconfigs, credentials, token values, certificate bodies, private keys, audit `sourceIPs` fields, host usernames, absolute local paths, or complete Kubernetes audit logs. Redaction markers and descriptions of those excluded fields may remain where they document the sanitization procedure.

