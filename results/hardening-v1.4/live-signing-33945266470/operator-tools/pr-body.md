## Purpose

Publish the EACP 1.4.0-rc1 engineering candidate so its isolated signing workflow can be exercised on GitHub-hosted runners after CI passes. This is not a final 1.4 release, a new normative Profile, or a Zenodo publication.

## Changes

- Minimized public projections, authenticated collectors, encrypted durable ingestion, finite-inventory completeness and externally anchored snapshot checks.
- Separate execution and signing jobs with same-run artifact identity and digest gates.
- Exact certificate/subject verifier, including a real offline regression for GitHub CLI flag compatibility.
- Retained local experiments, replayable reviewer package and gated external pilot protocol.

## Validation and limits

The latest local root suite passed 127 tests; workflow actionlint passed. The historical Profile, datasets, experiments, PDFs and v1.3.0 tag remain preserved. The retained older source measurements remain identified by their original commits; the added CLI regression verifies historical evidence, not a new 1.4 signature.

This pull request is expected to exercise unsigned execution only. A protected-main manual dispatch and fresh cryptographic verification are still required. No independent external reproduction, production pilot, SLSA L3 classification or source-event truth is claimed. The repository owner authorized publication and main protection requiring CI, including for administrators, and prohibiting force pushes and deletion.
