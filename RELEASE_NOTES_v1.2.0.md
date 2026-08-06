# EACP operational-provenance artifact v1.2.0

This release synchronizes the public reproducibility artifact with manuscript version 1.2.

## What changed

- Replaced the archived preprint with manuscript version 1.2 and synchronized all artifact metadata.
- Added the version-specific Zenodo DOI `10.5281/zenodo.21818550` and retained Concept DOI `10.5281/zenodo.21817376` for the complete version history.
- Reframed the OpenTelemetry exercise around shared-corpus preservation and interoperability, without presenting unlike pipeline timings as a performance ranking.
- Replaced the earlier comparison graphic with a preservation-focused Figure 3.
- Added editable SVG masters and vector-PDF exports for all three figures.
- Corrected the authorship of NIST SP 800-92 in manuscript reference [26].
- Updated `CITATION.cff`, README files, version assertions, release verification, and checksums.

## Frozen empirical boundary

The SQLite, Kubernetes, and OpenTelemetry run data are unchanged from v1.1.0. This release changes the manuscript, interpretation, figures, and archival metadata; it does not add a new experiment or alter the frozen trial results.

The Kubernetes evaluation remains a small, single-control-plane kind exercise. The OpenTelemetry result demonstrates retention of the frozen corpus through the fixed reference pipeline and equality after external post-export normalization; it does not demonstrate Collector-native EACP semantics, functional equivalence, production effectiveness, or platform superiority.

## Citation

- Exact artifact version: <https://doi.org/10.5281/zenodo.21818550>
- All artifact versions: <https://doi.org/10.5281/zenodo.21817376>

These are software/artifact identifiers, not an article DOI for the accompanying preprint.
