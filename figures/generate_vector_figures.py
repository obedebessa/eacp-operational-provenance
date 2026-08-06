#!/usr/bin/env python3
"""Generate publication-ready vector versions of EACP Figures 1-3.

The script reads the same archived CSV and JSON inputs as generate_figures.py.
It writes editable SVG masters beside the raster figures and does not replace
the PNG files used by the manuscript.
"""

from __future__ import annotations

import csv
import json
from html import escape
from pathlib import Path


OUT = Path(__file__).resolve().parent
ROOT = OUT.parent
RESULTS = ROOT / "data" / "sqlite" / "summary_results.csv"
OUT.mkdir(parents=True, exist_ok=True)

NAVY = "#14324B"
BLUE = "#1E5A7A"
TEAL = "#167C80"
LIGHT_TEAL = "#DCEFF0"
LIGHT_BLUE = "#E8F1F7"
GOLD = "#D7A62A"
PALE_GOLD = "#FAF2D6"
INK = "#24313A"
MID = "#6B7B86"
GRID = "#D8E0E5"
WHITE = "#FFFFFF"
PAPER = "#F8FAFB"


class SVG:
    """Small SVG writer with deterministic, text-preserving output."""

    def __init__(self, width: int, height: int, title: str, description: str) -> None:
        self.width = width
        self.height = height
        self.parts = [
            '<?xml version="1.0" encoding="UTF-8"?>',
            f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
            f'viewBox="0 0 {width} {height}" role="img" aria-labelledby="title desc">',
            f"<title id=\"title\">{escape(title)}</title>",
            f"<desc id=\"desc\">{escape(description)}</desc>",
            "<metadata>Generated from the archived EACP v1.2 experiment inputs; all elements are vector-native.</metadata>",
            """<defs>
  <marker id="arrow-teal" markerWidth="28" markerHeight="28" refX="24" refY="14" orient="auto" markerUnits="userSpaceOnUse">
    <path d="M0,0 L28,14 L0,28 Z" fill="#167C80"/>
  </marker>
  <marker id="arrow-blue" markerWidth="28" markerHeight="28" refX="24" refY="14" orient="auto" markerUnits="userSpaceOnUse">
    <path d="M0,0 L28,14 L0,28 Z" fill="#1E5A7A"/>
  </marker>
  <marker id="arrow-gold" markerWidth="28" markerHeight="28" refX="24" refY="14" orient="auto" markerUnits="userSpaceOnUse">
    <path d="M0,0 L28,14 L0,28 Z" fill="#D7A62A"/>
  </marker>
  <marker id="arrow-mid" markerWidth="28" markerHeight="28" refX="24" refY="14" orient="auto" markerUnits="userSpaceOnUse">
    <path d="M0,0 L28,14 L0,28 Z" fill="#6B7B86"/>
  </marker>
  <style>
    text { font-family: Arial, Helvetica, sans-serif; }
    .navy { fill: #14324B; }
    .ink { fill: #24313A; }
    .mid { fill: #6B7B86; }
    .blue { fill: #1E5A7A; }
    .teal { fill: #167C80; }
    .gold { fill: #D7A62A; }
    .bold { font-weight: 700; }
  </style>
</defs>""",
        ]

    def add(self, content: str) -> None:
        self.parts.append(content)

    def rect(
        self,
        x: float,
        y: float,
        width: float,
        height: float,
        *,
        fill: str = WHITE,
        stroke: str = "none",
        stroke_width: float = 0,
        radius: float = 0,
    ) -> None:
        self.add(
            f'<rect x="{x:g}" y="{y:g}" width="{width:g}" height="{height:g}" '
            f'rx="{radius:g}" fill="{fill}" stroke="{stroke}" stroke-width="{stroke_width:g}"/>'
        )

    def line(
        self,
        x1: float,
        y1: float,
        x2: float,
        y2: float,
        *,
        stroke: str,
        width: float = 3,
        dash: str | None = None,
        marker: str | None = None,
    ) -> None:
        dash_attr = f' stroke-dasharray="{dash}"' if dash else ""
        marker_attr = f' marker-end="url(#{marker})"' if marker else ""
        self.add(
            f'<line x1="{x1:g}" y1="{y1:g}" x2="{x2:g}" y2="{y2:g}" '
            f'stroke="{stroke}" stroke-width="{width:g}" stroke-linecap="round"'
            f'{dash_attr}{marker_attr}/>'
        )

    def path(
        self,
        d: str,
        *,
        stroke: str,
        width: float = 3,
        fill: str = "none",
        marker: str | None = None,
    ) -> None:
        marker_attr = f' marker-end="url(#{marker})"' if marker else ""
        self.add(
            f'<path d="{d}" fill="{fill}" stroke="{stroke}" stroke-width="{width:g}" '
            f'stroke-linecap="round" stroke-linejoin="round"{marker_attr}/>'
        )

    def text(
        self,
        x: float,
        y: float,
        value: str,
        *,
        size: float,
        fill: str = INK,
        weight: int = 400,
        anchor: str = "start",
        baseline: str | None = None,
        letter_spacing: float | None = None,
    ) -> None:
        baseline_attr = f' dominant-baseline="{baseline}"' if baseline else ""
        spacing_attr = f' letter-spacing="{letter_spacing:g}"' if letter_spacing is not None else ""
        self.add(
            f'<text x="{x:g}" y="{y:g}" font-size="{size:g}" fill="{fill}" '
            f'font-weight="{weight}" text-anchor="{anchor}"{baseline_attr}{spacing_attr}>'
            f"{escape(value)}</text>"
        )

    def multiline(
        self,
        x: float,
        y: float,
        lines: list[str],
        *,
        size: float,
        fill: str = INK,
        weight: int = 400,
        anchor: str = "start",
        line_height: float | None = None,
    ) -> None:
        gap = line_height or size * 1.2
        spans = "".join(
            f'<tspan x="{x:g}" dy="{0 if index == 0 else gap:g}">{escape(line)}</tspan>'
            for index, line in enumerate(lines)
        )
        self.add(
            f'<text x="{x:g}" y="{y:g}" font-size="{size:g}" fill="{fill}" '
            f'font-weight="{weight}" text-anchor="{anchor}">{spans}</text>'
        )

    def write(self, path: Path) -> None:
        self.parts.append("</svg>")
        path.write_text("\n".join(self.parts) + "\n", encoding="utf-8")


def panel(svg: SVG, x: float, y: float, width: float, height: float) -> None:
    svg.rect(x, y, width, height, fill=WHITE, stroke=GRID, stroke_width=3, radius=22)


def arrow(svg: SVG, x1: float, y1: float, x2: float, y2: float, color: str, marker: str, width: float = 5) -> None:
    svg.line(x1, y1, x2, y2, stroke=color, width=width, marker=marker)


def figure_1_architecture() -> Path:
    path = OUT / "figure_1_eacp_architecture_v1_2.svg"
    svg = SVG(
        2400,
        1400,
        "Figure 1. Evidence-Aware Control Plane architecture",
        "Heterogeneous source planes feed an asynchronous EACP evidence path, which supports operational uses while remaining separate from the application data path.",
    )
    svg.rect(0, 0, 2400, 1400, fill=WHITE)
    svg.text(100, 105, "Evidence-Aware Control Plane (EACP)", size=58, fill=NAVY, weight=700)
    svg.text(
        100,
        160,
        "Asynchronous cross-plane operational provenance with a separate application data path",
        size=30,
        fill=MID,
    )

    svg.text(100, 230, "HETEROGENEOUS SOURCE PLANES", size=27, fill=BLUE, weight=700)
    sources = [
        (255, "CI/CD records"),
        (365, "Identity / IAM events"),
        (475, "Orchestration / audit events"),
        (585, "Policy decisions"),
        (695, "Telemetry signals"),
        (805, "Incident / recovery records"),
    ]
    for y, label in sources:
        svg.rect(100, y, 510, 90, fill=LIGHT_BLUE, stroke=BLUE, stroke_width=4, radius=20)
        svg.text(355, y + 49, label, size=29, fill=NAVY, weight=700, anchor="middle", baseline="middle")

    # Shared asynchronous ingestion bus.
    svg.line(685, 300, 685, 850, stroke=TEAL, width=6)
    for y, _ in sources:
        arrow(svg, 620, y + 45, 677, y + 45, TEAL, "arrow-teal", width=5)
    arrow(svg, 685, 375, 835, 375, TEAL, "arrow-teal", width=7)
    svg.text(392, 930, "asynchronous observation", size=22, fill=TEAL, weight=700, anchor="middle")

    svg.rect(780, 215, 1015, 765, fill=PAPER, stroke=TEAL, stroke_width=6, radius=28)
    svg.text(835, 275, "EACP EVIDENCE PATH", size=32, fill=TEAL, weight=700)
    components = [
        (850, 325, 875, 110, "1  Source adapters", "Map native identifiers and retain source pointers"),
        (850, 480, 875, 110, "2  Normalizer and correlation engine", "Bind service, intent, policy, action, outcome, and correlation"),
        (850, 635, 875, 140, "3  Append-only evidence index", "Idempotent source key - indexed queries - SHA-256 content hash"),
        (850, 820, 875, 110, "4  Query and evidence-package API", "State timeline - cross-plane chain - source-artifact links"),
    ]
    for index, (x, y, w, h, title, subtitle) in enumerate(components):
        svg.rect(x, y, w, h, fill=WHITE if index % 2 == 0 else LIGHT_TEAL, stroke=TEAL, stroke_width=3, radius=18)
        svg.text(x + 28, y + 42, title, size=28, fill=NAVY, weight=700)
        svg.text(x + 28, y + 82, subtitle, size=22, fill=INK)
        if index < len(components) - 1:
            next_y = components[index + 1][1]
            arrow(svg, x + w / 2, y + h + 8, x + w / 2, next_y - 12, TEAL, "arrow-teal", width=6)

    svg.text(1900, 230, "OPERATIONAL USES", size=27, fill=BLUE, weight=700)
    uses = [
        (290, ["Service-state", "reconstruction"]),
        (500, ["Policy-drift investigation"]),
        (710, ["Incident evidence", "package"]),
    ]
    for y, lines in uses:
        svg.rect(1900, y, 405, 145, fill=PALE_GOLD, stroke=GOLD, stroke_width=4, radius=22)
        text_y = y + 64 if len(lines) == 1 else y + 55
        svg.multiline(2102.5, text_y, lines, size=30, fill=NAVY, weight=700, anchor="middle", line_height=34)
        arrow(svg, 1805, y + 72.5, 1886, y + 72.5, GOLD, "arrow-gold", width=7)

    svg.line(780, 1015, 1795, 1015, stroke=TEAL, width=4, dash="18 16")
    svg.text(
        1287.5,
        1045,
        "separate evidence path; no request-path dependency",
        size=22,
        fill=TEAL,
        weight=700,
        anchor="middle",
    )

    svg.rect(100, 1080, 2205, 235, fill="#F3F5F7", stroke=GRID, stroke_width=4, radius=28)
    svg.text(150, 1135, "APPLICATION DATA PATH - UNCHANGED BY DEFAULT", size=28, fill=MID, weight=700)
    path_boxes = [
        (230, 1190, 340, "User request"),
        (825, 1190, 400, "Application service"),
        (1510, 1190, 400, "Data / downstream API"),
    ]
    for x, y, w, label in path_boxes:
        svg.rect(x, y, w, 80, fill=WHITE, stroke=MID, stroke_width=3, radius=15)
        svg.text(x + w / 2, y + 43, label, size=25, fill=INK, weight=700, anchor="middle", baseline="middle")
    arrow(svg, 580, 1230, 810, 1230, MID, "arrow-mid", width=6)
    arrow(svg, 1235, 1230, 1495, 1230, MID, "arrow-mid", width=6)
    svg.write(path)
    return path


def load_benchmark_rows() -> list[dict[str, float]]:
    rows: list[dict[str, float]] = []
    with RESULTS.open(encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            rows.append({key: float(value) for key, value in row.items()})
    return rows


def draw_legend(svg: SVG, x: float, y: float, series: list[tuple[str, str]]) -> None:
    cursor = x
    for label, color in series:
        svg.rect(cursor, y - 17, 24, 24, fill=color, radius=4)
        svg.text(cursor + 34, y + 2, label, size=18, fill=INK, weight=700)
        cursor += 175


def draw_chart(
    svg: SVG,
    box: tuple[float, float, float, float],
    title: str,
    subtitle: str,
    categories: list[str],
    series: list[tuple[str, list[float], list[float], list[float], str]],
    y_max: float,
    decimals: int,
) -> None:
    x, y, width, height = box
    panel(svg, x, y, width, height)
    svg.text(x + 34, y + 55, title, size=30, fill=NAVY, weight=700)
    svg.text(x + 34, y + 92, subtitle, size=20, fill=MID)

    left = x + 115
    right = x + width - 42
    top = y + 125
    bottom = y + height - 82
    plot_width = right - left
    plot_height = bottom - top
    for tick in range(5):
        value = y_max * tick / 4
        yy = bottom - plot_height * tick / 4
        svg.line(left, yy, right, yy, stroke=GRID, width=2)
        if decimals == 0:
            label = f"{value:,.0f}"
        else:
            label = f"{value:,.{decimals}f}"
        svg.text(left - 12, yy + 7, label, size=18, fill=MID, anchor="end")
    svg.line(left, top, left, bottom, stroke=INK, width=3)
    svg.line(left, bottom, right, bottom, stroke=INK, width=3)

    group_width = plot_width / len(categories)
    slot = min(80.0, group_width / (len(series) + 1))
    for cat_index, category in enumerate(categories):
        center = left + group_width * (cat_index + 0.5)
        total = slot * len(series)
        for series_index, (_, values, q1, q3, color) in enumerate(series):
            center_x = center - total / 2 + slot * (series_index + 0.5)
            value = min(values[cat_index], y_max)
            bar_height = plot_height * value / y_max
            bar_width = slot * 0.68
            svg.rect(center_x - bar_width / 2, bottom - bar_height, bar_width, bar_height, fill=color, radius=6)
            low_y = bottom - plot_height * min(q1[cat_index], y_max) / y_max
            high_y = bottom - plot_height * min(q3[cat_index], y_max) / y_max
            svg.line(center_x, low_y, center_x, high_y, stroke=INK, width=3)
            svg.line(center_x - 9, low_y, center_x + 9, low_y, stroke=INK, width=3)
            svg.line(center_x - 9, high_y, center_x + 9, high_y, stroke=INK, width=3)
        svg.text(center, bottom + 42, category, size=20, fill=INK, weight=700, anchor="middle")
    legend_width = 175 * len(series)
    draw_legend(svg, right - legend_width, y + 96, [(name, color) for name, *_rest, color in series])


def figure_2_benchmark() -> Path:
    path = OUT / "figure_2_reproducible_pilot_benchmark_v1_2.svg"
    rows = load_benchmark_rows()
    categories = [f"{int(row['event_count']) // 1000}k" for row in rows]

    def values(metric: str) -> tuple[list[float], list[float], list[float]]:
        return (
            [row[f"{metric}_median"] for row in rows],
            [row[f"{metric}_q1"] for row in rows],
            [row[f"{metric}_q3"] for row in rows],
        )

    bsvc = values("service_baseline_p95_ms")
    esvc = values("service_eacp_p95_ms")
    bcorr = values("correlation_baseline_p95_ms")
    ecorr = values("correlation_eacp_p95_ms")
    ingest = values("ingest_events_per_second")
    bstore = values("baseline_bytes_per_event")
    estore = values("eacp_bytes_per_event")

    svg = SVG(
        2400,
        1550,
        "Figure 2. Reproducible pilot benchmark",
        "Four bar charts report service-state reconstruction, cross-plane correlation, evidence ingestion, and physical SQLite storage for 10k, 50k, and 100k event workloads. Bars show medians and whiskers show interquartile ranges across ten sequential seeded trials.",
    )
    svg.rect(0, 0, 2400, 1550, fill=PAPER)
    svg.text(100, 105, "Reproducible Pilot Benchmark", size=56, fill=NAVY, weight=700)
    svg.text(100, 158, "Median of 10 sequential seeded trials; whiskers show the interquartile range", size=28, fill=MID)
    draw_chart(
        svg,
        (100, 200, 1070, 605),
        "A. Service-state reconstruction",
        "Indexed warm-cache p95 by service (milliseconds)",
        categories,
        [("Fragmented", *bsvc, BLUE), ("EACP", *esvc, TEAL)],
        1.5,
        2,
    )
    draw_chart(
        svg,
        (1230, 200, 1070, 605),
        "B. Cross-plane correlation",
        "Indexed warm-cache p95 by correlation ID (milliseconds)",
        categories,
        [("Fragmented", *bcorr, BLUE), ("EACP", *ecorr, TEAL)],
        0.06,
        3,
    )
    draw_chart(
        svg,
        (100, 850, 1070, 605),
        "C. Evidence ingestion",
        "Amortized bulk normalization, SHA-256, three indexes, and one commit (events / second)",
        categories,
        [("EACP", *ingest, GOLD)],
        230000,
        0,
    )
    draw_chart(
        svg,
        (1230, 850, 1070, 605),
        "D. Physical SQLite storage",
        "Separate database size after VACUUM (bytes / event)",
        categories,
        [("Fragmented", *bstore, BLUE), ("EACP", *estore, TEAL)],
        500,
        0,
    )
    svg.text(
        100,
        1507,
        "Synthetic workload - 200 services - 300 service and 300 correlation queries per trial - Apple M4 Max - CPython 3.11.9 - SQLite 3.51.0",
        size=20,
        fill=MID,
    )
    svg.write(path)
    return path


def latest_comparison_summary() -> dict:
    result_root = ROOT / "data" / "comparison"
    candidates = sorted(
        path for path in result_root.glob("*/summary.json")
        if not path.parent.name.startswith("_")
    )
    if not candidates:
        raise FileNotFoundError(f"no completed comparison summary under {result_root}")
    return json.loads(candidates[-1].read_text(encoding="utf-8"))


def centered_multiline(svg: SVG, x: float, y: float, lines: list[str], size: float, fill: str = INK, weight: int = 700) -> None:
    line_height = size * 1.18
    start = y - line_height * (len(lines) - 1) / 2
    svg.multiline(x, start, lines, size=size, fill=fill, weight=weight, anchor="middle", line_height=line_height)


def figure_3_preservation() -> Path:
    path = OUT / "figure_3_kubernetes_preservation_v1_2.svg"
    summary = latest_comparison_summary()
    event_count = int(summary["input"]["events"])
    field_equality = summary["validation"]["post_export_canonical_projection_preservation"]["field_value_equality"]
    compared_values = int(field_equality["compared_field_values"])

    svg = SVG(
        2400,
        1520,
        "Figure 3. Kubernetes laboratory and corpus-preservation exercise",
        "A frozen sanitized corpus of 374 Kubernetes audit records was replayed through EACP and an OpenTelemetry reference pipeline. Both retained all records, and an external canonical projection check matched all 4,862 compared values. No performance ranking is shown.",
    )
    svg.rect(0, 0, 2400, 1520, fill=PAPER)
    svg.text(100, 105, "Kubernetes Laboratory and Corpus-Preservation Exercise", size=49, fill=NAVY, weight=700)
    svg.text(100, 158, "One frozen, sanitized audit corpus - ten fresh sequential replays per pipeline", size=27, fill=MID)

    panel(svg, 100, 205, 2200, 340)
    svg.text(135, 260, "A. Executed Kubernetes corpus", size=30, fill=NAVY, weight=700)
    cards = [
        ("AUDIT EVENTS", f"{event_count}", "namespace-filtered records"),
        ("EXPLICIT CORRELATION", "132", "records with eacp-round ID"),
        ("RBAC DENIALS", "3", "audited HTTP 403 events"),
        ("UNIQUE SOURCE KEYS", f"{event_count}", "auditID:stage; no duplicates"),
    ]
    for index, (label, value, note) in enumerate(cards):
        x = 140 + index * 530
        svg.rect(x, 305, 480, 195, fill=LIGHT_BLUE if index % 2 == 0 else LIGHT_TEAL, stroke=TEAL, stroke_width=3, radius=18)
        svg.text(x + 25, 345, label, size=19, fill=BLUE, weight=700)
        svg.text(x + 25, 415, value, size=53, fill=NAVY, weight=700)
        svg.text(x + 25, 470, note, size=18, fill=MID)

    panel(svg, 100, 590, 1055, 705)
    svg.text(135, 645, "B. Event preservation", size=30, fill=NAVY, weight=700)
    svg.text(135, 695, "Canonical projection checked after each replay", size=20, fill=MID)
    rows = [
        ("EACP", f"{event_count} / {event_count}", "indexed SQLite rows retained", LIGHT_TEAL, TEAL),
        ("OpenTelemetry", f"{event_count} / {event_count}", "exported audit bodies retained", LIGHT_TEAL, TEAL),
        ("Post-export field check", "Matched", f"{compared_values:,} / {compared_values:,} compared values matched", PALE_GOLD, GOLD),
    ]
    y = 745
    for label, value, note, fill, outline in rows:
        svg.rect(145, y, 965, 145, fill=fill, stroke=outline, stroke_width=3, radius=16)
        svg.text(175, y + 45, label, size=23, fill=NAVY, weight=700)
        svg.text(1075, y + 45, value, size=32, fill=TEAL if outline == TEAL else GOLD, weight=700, anchor="end")
        svg.text(175, y + 100, note, size=20, fill=INK)
        y += 175
    svg.text(150, 1272, "No SQLite-versus-file query comparison was performed.", size=18, fill=MID, weight=700)

    panel(svg, 1205, 590, 1095, 705)
    svg.text(1240, 645, "C. Interoperability reference exercise", size=30, fill=NAVY, weight=700)
    svg.text(1240, 695, "Same frozen bytes; distinct output and query semantics", size=20, fill=MID)

    svg.rect(1320, 735, 865, 130, fill=LIGHT_BLUE, stroke=BLUE, stroke_width=3, radius=16)
    centered_multiline(svg, 1752.5, 807, [f"SHARED INPUT - {event_count} frozen audit records - identical bytes"], 24, NAVY)
    svg.rect(1255, 925, 480, 160, fill=LIGHT_TEAL, stroke=TEAL, stroke_width=3, radius=16)
    svg.rect(1770, 925, 480, 160, fill=LIGHT_BLUE, stroke=BLUE, stroke_width=3, radius=16)
    centered_multiline(svg, 1495, 997, ["EACP", f"{event_count} / {event_count} indexed rows retained"], 23, NAVY)
    centered_multiline(svg, 2010, 997, ["OpenTelemetry", f"{event_count} / {event_count} raw bodies retained"], 23, NAVY)
    arrow(svg, 1620, 875, 1495, 915, TEAL, "arrow-teal", width=5)
    arrow(svg, 1885, 875, 2010, 915, BLUE, "arrow-blue", width=5)

    svg.rect(1320, 1140, 865, 120, fill=PALE_GOLD, stroke=GOLD, stroke_width=3, radius=16)
    centered_multiline(svg, 1752.5, 1205, [f"EXTERNAL PROJECTION CHECK - {compared_values:,} / {compared_values:,} values matched"], 23, INK)
    arrow(svg, 1495, 1095, 1620, 1130, GOLD, "arrow-gold", width=5)
    arrow(svg, 2010, 1095, 1885, 1130, GOLD, "arrow-gold", width=5)

    svg.text(
        100,
        1385,
        "Shared input SHA-256: 6aa39ee1...5400e01 - Collector Contrib 0.158.0 image digest: sha256:c5918f78...a32ed5",
        size=20,
        fill=MID,
    )
    svg.text(
        100,
        1430,
        "Scope: bounded replay and corpus preservation only - no performance ranking - no claim of Collector-native EACP semantics",
        size=21,
        fill=TEAL,
        weight=700,
    )
    svg.write(path)
    return path


def main() -> None:
    outputs = [
        figure_1_architecture(),
        figure_2_benchmark(),
        figure_3_preservation(),
    ]
    for path in outputs:
        print(path)


if __name__ == "__main__":
    main()
