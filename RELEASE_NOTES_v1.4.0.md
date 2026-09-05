# EACP 1.4.0 — collection security and resilience

Software archival edition, 2026-09-05. DOI: **10.5281/zenodo.22326718**.
The DOI was reserved before source freeze; the public Zenodo record, not a
local test or this document, establishes whether publication has completed.

## What this version means

This freezes the 1.4 hardening implementation for reproducible inspection.
There is no new paper or normative Profile: the paper and Profile remain 1.3.
Final archival packaging does not mean production certification, peer review,
SLSA L3, source truth, independent human validation or field effectiveness.
No organizational pilot has been performed; its protocol remains not started.

The implementation adds allowlisted public projections, collector authentication,
encrypted durable ingestion with explicit completeness states, tenant-scoped
access, retention controls, externally anchored snapshot verification and
separate hosted execution/signing. See docs/v1.4/README.md for the claim boundaries.

## Source and measurement identity

- Historical release v1.3.0: 537799bd2b292ce6e78004de22f4ab6df1b4feda.
- Original hardening campaign: e4716e82b9cd86058288ce59744aefb88632fec8.
- Live signing source: 0bcb038fef930faff3ef19f661bf995f97d605d8.
- Candidate reviewer-package source: ae8729c2038c51de43f0dddbc12f24a7d8fdc943.
- Pre-freeze main: 01c81d50c9142a3166eb793fc9c3c35adf2c223d.
- Final source: resolve the annotated v1.4.0 tag or read the distribution's
  RELEASE.json. Never substitute a floating branch for the frozen source.

Runtime modules match the live signing source byte-for-byte except the
__version__ constant in __init__.py. Finalization changes release metadata,
documentation, release verification and packaging tests, not runtime behavior.
Old measurements retain their original source identities and environments.
The final author-operated verification receipts are delivered separately in
the distribution and do not overwrite earlier runs.

## Signing boundary

Retained run 33945266470, attempt 1, signed only eacp-hardening-v1.4.tar.gz,
SHA-256 b4ee08dc32eb56e568ccc93ba45459642f3844427adab0bd8c044153b5ac3bea.
The bundle, captured trust root, positive verification and six negative checks
remain under results/hardening-v1.4/live-signing-33945266470.
That signature does not sign the final source, Git bundle, release ZIP, PDF or
these notes. The final ZIP has a separate transfer checksum, not a new attestation.

## Reproduce and verify

The distribution includes a complete Git bundle and a source export. Follow
START_HERE.md, clone the bundle, detach at the recorded final commit, install
the pinned dependency, verify the final manifest, then run the fixed reproduction
plan. It needs Python 3.11+, Git and a trusted GitHub CLI. Do not execute unreviewed
code in a sensitive environment; this runner is not a sandbox.

python scripts/verify_hardening.py --release checks the exact annotated tag,
clean checkout, preserved historical files, unchanged runtime implementation,
retained evidence and MANIFEST-v1.4.0.sha256. It is a local readiness gate, not
an online publication or human-identity verifier.

The old MANIFEST-v1.4.0-rc1.sha256 and candidate packaging utility are historical.
Run them only at their corresponding candidate commit; do not regenerate them
over the final tree. The old 1.3 manifest/verifier likewise belong to v1.3.0.

## External material

Private reviewer correspondence, identity declarations and supplied external
execution ZIPs are not included in this public software deposit. This edition
does not certify who operated an external execution or independently adjudicate
attribution corrections. A runner's independently_reproduced field remains
false by design: code cannot authenticate its human operator.

Licensing remains file-scoped; see LICENSES/README.md. The unchanged historical
PDFs are preserved with their original notices and versions.
