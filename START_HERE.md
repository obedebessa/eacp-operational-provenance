# EACP review card: software 1.5.0rc1

| Item | Exact scope |
|---|---|
| Software | 1.5.0rc1, still a release candidate; cite the package source commit |
| Security boundary | 1.4 collector, integrity, authorization and signing controls |
| Profile / paper | 1.3; unchanged research contribution and resolver semantics |
| Research DOI | Paper: 10.5281/zenodo.22283868; Profile: 10.5281/zenodo.22307668 |
| Software DOI | No 1.5 DOI; do not borrow an older version-specific DOI |
| Historical signature | Runs 33690440169 (1.3) and 33945266470 (1.4) attest their exact historical TARs, **not this tree or ZIP** |
| New software | Installable query/export/verification, atomic ingestion pages, diagnostics, backup/restore |
| Supplied reexecution | Original candidate e2807efc: 275 passed + one initially skipped test later passed; 17-command demo, three sentinels and five bounded scenarios |
| Current change | Privacy-screened distribution and consolidated review documentation, not a new experiment or protocol |
| Status | Review candidate; no field pilot, expert approval, new Kubernetes run or production claim |

Read [release notes](RELEASE_NOTES_v1.5.0rc1.md),
[the external execution record](docs/v1.5/EXTERNAL_EXECUTION.md) and
[the evidence matrix](docs/v1.5/EVIDENCE_MATRIX.md). The reviewer should record
what they personally inspected or executed, findings, and limits; a favorable
conclusion is neither filled in nor required.

**Central semantic limit:** a false but internally consistent chain can pass
structural correlation checks. Hashes and signatures do not make its source
assertions true. Three deliberate sentinel mutations are not mutation coverage.
The received brief described 26 areas, not an available or completed 208-case suite.

## Reproduce the original measurements or inspect this delivery

The private-path-screened review ZIP is a source snapshot without `.git` or a Git
bundle. Its top-level SHA256SUMS checks the supplied bytes, not the truth of a
run or a human identity. Its reproduction instructions distinguish snapshot
checks from Git-history-dependent checks. Original-run and redacted-copy hashes
are kept separate; historical manifests apply only to their original checkouts.

Use a new disposable environment with Python 3.11+, Git and GitHub CLI. A full
checkout at the recorded commit is needed for historical Git-preservation checks
and the original campaign script. It can be obtained from the official repository,
but contains historical metadata outside the screened ZIP. Never execute supplied
evidence as code, use production secrets, or infer collection permission from a
letter of intent. See [privacy scope](docs/v1.5/RELEASE_PRIVACY.md).

For installation, suite commands, demo and targeted mutation instructions, use
the [operational quickstart](docs/v1.5/README.md). Record every return code and skip.
If `venv` is unavailable because the platform omitted `ensurepip`, install the
platform's venv support in the disposable environment and record that prerequisite;
the project source does not need editing to resolve it.
