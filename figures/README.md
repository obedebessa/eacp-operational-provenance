# Figures

`generate_figures.py` reads the checked-in machine results and produces the PNG figures used in the preprint:

- `eacp_architecture.png` — conceptual evidence-path architecture;
- `eacp_benchmark_results.png` — medians and interquartile ranges across 10 sequential synthetic trials; and
- `eacp_kubernetes_preservation_results_v1_2.png` — 374-event Kubernetes corpus, event preservation, and external post-export validation across 10 paired replays, intentionally without a performance ranking.

Publication-ready vector companions are provided as SVG and vector PDF for each figure:

- `figure_1_eacp_architecture_v1_2.{svg,pdf}`;
- `figure_2_reproducible_pilot_benchmark_v1_2.{svg,pdf}`; and
- `figure_3_kubernetes_preservation_v1_2.{svg,pdf}`.

The SVG files are the editable masters; the PDFs are journal-submission exports. Each PDF contains vector paths and embedded fonts with no raster image objects. Their visual content is matched to the corresponding PNG.

Regenerate from the repository root with Pillow 10–12:

```bash
python -m pip install 'Pillow>=10,<13'
python figures/generate_figures.py
python figures/generate_vector_figures.py
```

The vector generator requires only Python's standard library and regenerates the SVG masters. The checked-in PDFs were exported from those SVG files with CairoSVG 2.8.2.

The preservation figure labels the 4,862-value equality check as post-export validation. The Collector preserved raw audit bodies; the shared external validator, not the Collector configuration, produced the canonical EACP projection. It therefore communicates interoperability and preservation, not feature equivalence or comparative performance.
