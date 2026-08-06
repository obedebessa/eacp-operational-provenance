# Figures

`generate_figures.py` reads the checked-in machine results and produces:

- `eacp_architecture.png` — conceptual evidence-path architecture;
- `eacp_benchmark_results.png` — medians and interquartile ranges across 10 sequential synthetic trials; and
- `eacp_kubernetes_otel_results.png` — 374-event Kubernetes corpus, post-export validation, and median/IQR wall-time observations across 10 paired replays.

Regenerate from the repository root with Pillow 10–12:

```bash
python -m pip install 'Pillow>=10,<13'
python figures/generate_figures.py
```

The comparison figure labels the 4,862-value equality check as post-export validation. The Collector preserved raw audit bodies; the shared external validator, not the Collector configuration, produced the canonical EACP projection.

