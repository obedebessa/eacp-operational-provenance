# Figures

The directory contains two deliberately separated figure sets: the released
v1.2 figures and the v1.3 reviewer-candidate figures. The candidate PNGs do not
change the archival status of the v1.2 vector exports.

## EACP 1.3 reviewer-candidate figures

`generate_v1_3_figures.py` produces three 300-dpi RGB PNGs:

- `eacp_architecture_v1_3.png` — Profile 1.3 evidence flow, typed/scoped exact
  resolution, missing/ambiguous abstention, and the separate application path;
- `eacp_correlation_robustness_v1_3.png` — missing-ID degradation and selected
  adversarial outcomes for the strict policy, read from the checked-in
  correlation summary; and
- `eacp_live_cross_plane_v1_3.png` — the three completed attempts of public
  GitHub Actions run `33682116347`, including exact links, negative controls,
  target-bound HTTP 403 evidence, subject-digest checks, and archive-attestation
  subject checks.

The architecture is explanatory. The robustness and live figures are generated
from these machine-readable files:

- `experiments/correlation_robustness/results/reference/summary_results.csv`;
- `experiments/github_actions/results/reference/run-33682116347/reference_summary.json`.

Regenerate them from the repository root with Pillow 10–12:

```bash
python3 -m pip install 'Pillow>=10,<13'
python3 figures/generate_v1_3_figures.py
```

The v1.3 figures are candidate raster assets. They are not described as
archival vector masters, and no v1.3 release or DOI is implied by their presence.

## Released v1.2 figures

`generate_figures.py` reads the v1.2 checked-in machine results and produces:

- `eacp_architecture.png` — conceptual evidence-path architecture;
- `eacp_benchmark_results.png` — medians and interquartile ranges across 10
  sequential synthetic trials; and
- `eacp_kubernetes_preservation_results_v1_2.png` — the 374-event Kubernetes
  corpus, event preservation, and external post-export validation across 10
  paired replays, intentionally without a performance ranking.

Publication-ready vector companions are provided as SVG and vector PDF:

- `figure_1_eacp_architecture_v1_2.{svg,pdf}`;
- `figure_2_reproducible_pilot_benchmark_v1_2.{svg,pdf}`; and
- `figure_3_kubernetes_preservation_v1_2.{svg,pdf}`.

The SVG files are the editable masters; the PDFs are journal-submission exports.
Each PDF contains vector paths and embedded fonts with no raster image objects.
Their visual content is matched to the corresponding PNG.

Regenerate the v1.2 set from the repository root:

```bash
python3 -m pip install 'Pillow>=10,<13'
python3 figures/generate_figures.py
python3 figures/generate_vector_figures.py
```

The vector generator requires only Python's standard library and regenerates
the SVG masters. The checked-in PDFs were exported from those SVG files with
CairoSVG 2.8.2.

The preservation figure labels the 4,862-value equality check as post-export
validation. The Collector preserved raw audit bodies; the shared external
validator, not the Collector configuration, produced the canonical EACP
projection. It therefore communicates interoperability and preservation, not
feature equivalence or comparative performance.
