#!/usr/bin/env python3
"""Generate a dependency-free SVG summary of the reference robustness run."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Mapping, Sequence


HERE = Path(__file__).resolve().parent


def xml_text(value: object) -> str:
    return (
        str(value)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def lookup(
    rows: Sequence[Mapping[str, Any]], scenario: str, algorithm: str, metric: str
) -> float:
    for row in rows:
        if row["scenario"] == scenario and row["algorithm"] == algorithm:
            value = row[f"{metric}_median"]
            if value is None:
                raise ValueError(f"undefined {metric} for {scenario}/{algorithm}")
            return float(value)
    raise KeyError(f"missing summary row for {scenario}/{algorithm}")


def polyline(points: Sequence[tuple[float, float]], color: str, dash: str = "") -> str:
    coordinates = " ".join(f"{x:.1f},{y:.1f}" for x, y in points)
    dashed = f' stroke-dasharray="{dash}"' if dash else ""
    circles = "".join(
        f'<circle cx="{x:.1f}" cy="{y:.1f}" r="4.5" fill="{color}"/>'
        for x, y in points
    )
    return (
        f'<polyline points="{coordinates}" fill="none" stroke="{color}" '
        f'stroke-width="3" stroke-linejoin="round" stroke-linecap="round"{dashed}/>'
        + circles
    )


def generate_svg(document: Mapping[str, Any]) -> str:
    rows = document["summaries"]
    seeds = document["configuration"]["seeds"]
    strict = "strict_service_plus_correlation"
    temporal = "naive_temporal_window"
    id_only = "correlation_id_only_ablation"

    missing_scenarios = [
        "control",
        "missing_random_1pct",
        "missing_random_5pct",
        "missing_random_10pct",
        "missing_random_20pct",
    ]
    missing_x = [0, 1, 5, 10, 20]
    strict_accuracy = [
        100 * lookup(rows, scenario, strict, "exact_chain_accuracy")
        for scenario in missing_scenarios
    ]
    strict_recall = [
        100 * lookup(rows, scenario, strict, "join_recall")
        for scenario in missing_scenarios
    ]
    temporal_accuracy = [
        100 * lookup(rows, scenario, temporal, "exact_chain_accuracy")
        for scenario in missing_scenarios
    ]

    collision_scenarios = [
        "control",
        "collision_same_service_1pct",
        "collision_same_service_5pct",
        "collision_same_service_10pct",
    ]
    collision_x = [0, 1, 5, 10]
    strict_abstention = [
        100 * lookup(rows, scenario, strict, "abstention_rate")
        for scenario in collision_scenarios
    ]
    strict_false = [
        100 * lookup(rows, scenario, strict, "false_join_rate")
        for scenario in collision_scenarios
    ]
    unsafe_false = [
        100 * lookup(rows, scenario, id_only, "false_join_rate")
        for scenario in collision_scenarios
    ]
    cross_strict = 100 * lookup(
        rows, "collision_cross_service_5pct", strict, "false_join_rate"
    )
    cross_unsafe = 100 * lookup(
        rows, "collision_cross_service_5pct", id_only, "false_join_rate"
    )

    width, height = 1240, 720
    left = (70, 118, 500, 390)
    right = (670, 118, 500, 390)

    def x_scale(value: float, panel, maximum: float) -> float:
        x, _y, w, _h = panel
        return x + value / maximum * w

    def y_scale(value: float, panel, maximum: float) -> float:
        _x, y, _w, h = panel
        return y + h - value / maximum * h

    pieces = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}" role="img" aria-labelledby="title desc">',
        '<title id="title">EACP adversarial correlation robustness</title>',
        '<desc id="desc">Two panels show degradation under missing identifiers and safe abstention under identifier reuse.</desc>',
        '<rect width="1240" height="720" fill="#ffffff"/>',
        '<style>text{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;fill:#17212b}.title{font-size:25px;font-weight:700}.subtitle{font-size:14px;fill:#53606d}.panel{font-size:17px;font-weight:650}.axis{font-size:12px;fill:#53606d}.legend{font-size:12px}.note{font-size:13px;fill:#344451}.grid{stroke:#dce2e8;stroke-width:1}.frame{stroke:#87939f;stroke-width:1.2;fill:none}</style>',
        '<text id="figure-title" class="title" x="70" y="45">Correlation faults expose a safety–coverage trade-off</text>',
        f'<text class="subtitle" x="70" y="70">Median across {len(seeds)} predetermined seeds; 600 six-plane chains and 3,600 canonical events per seed</text>',
        '<text class="panel" x="70" y="103">A. Missing IDs: degradation without fabricated joins</text>',
        '<text class="panel" x="670" y="103">B. ID reuse: abstain or silently merge</text>',
    ]

    for panel, y_max, y_ticks in ((left, 100, range(0, 101, 20)), (right, 25, range(0, 26, 5))):
        x, y, w, h = panel
        for tick in y_ticks:
            py = y_scale(tick, panel, y_max)
            pieces.append(f'<line class="grid" x1="{x}" y1="{py:.1f}" x2="{x+w}" y2="{py:.1f}"/>')
            pieces.append(f'<text class="axis" x="{x-10}" y="{py+4:.1f}" text-anchor="end">{tick}%</text>')
        pieces.append(f'<rect class="frame" x="{x}" y="{y}" width="{w}" height="{h}"/>')

    for value in missing_x:
        px = x_scale(value, left, 20)
        pieces.append(f'<text class="axis" x="{px:.1f}" y="528" text-anchor="middle">{value}%</text>')
    pieces.append('<text class="axis" x="320" y="553" text-anchor="middle">events with missing correlation ID</text>')

    left_accuracy_points = [
        (x_scale(x, left, 20), y_scale(y, left, 100))
        for x, y in zip(missing_x, strict_accuracy)
    ]
    left_recall_points = [
        (x_scale(x, left, 20), y_scale(y, left, 100))
        for x, y in zip(missing_x, strict_recall)
    ]
    left_temporal_points = [
        (x_scale(x, left, 20), y_scale(y, left, 100))
        for x, y in zip(missing_x, temporal_accuracy)
    ]
    pieces.extend(
        [
            polyline(left_accuracy_points, "#12355b"),
            polyline(left_recall_points, "#00798c", "8 5"),
            polyline(left_temporal_points, "#d1495b", "3 5"),
            '<line x1="85" y1="579" x2="115" y2="579" stroke="#12355b" stroke-width="3"/><text class="legend" x="122" y="583">strict exact-chain accuracy</text>',
            '<line x1="285" y1="579" x2="315" y2="579" stroke="#00798c" stroke-width="3" stroke-dasharray="8 5"/><text class="legend" x="322" y="583">strict pairwise recall</text>',
            '<line x1="445" y1="579" x2="475" y2="579" stroke="#d1495b" stroke-width="3" stroke-dasharray="3 5"/><text class="legend" x="482" y="583">temporal exact accuracy</text>',
            '<rect x="88" y="135" width="190" height="31" rx="6" fill="#e8f5ef"/><text class="note" x="100" y="156">strict false-join rate: 0%</text>',
        ]
    )

    for value in collision_x:
        px = x_scale(value, right, 10)
        pieces.append(f'<text class="axis" x="{px:.1f}" y="528" text-anchor="middle">{value}%</text>')
    pieces.append('<text class="axis" x="920" y="553" text-anchor="middle">reused-ID pairs / truth chains</text>')

    abstention_points = [
        (x_scale(x, right, 10), y_scale(y, right, 25))
        for x, y in zip(collision_x, strict_abstention)
    ]
    unsafe_points = [
        (x_scale(x, right, 10), y_scale(y, right, 25))
        for x, y in zip(collision_x, unsafe_false)
    ]
    strict_false_points = [
        (x_scale(x, right, 10), y_scale(y, right, 25))
        for x, y in zip(collision_x, strict_false)
    ]
    pieces.extend(
        [
            polyline(abstention_points, "#d1495b"),
            polyline(unsafe_points, "#7a5195", "8 5"),
            polyline(strict_false_points, "#00798c", "3 5"),
            '<line x1="686" y1="579" x2="716" y2="579" stroke="#d1495b" stroke-width="3"/><text class="legend" x="723" y="583">strict abstention</text>',
            '<line x1="835" y1="579" x2="865" y2="579" stroke="#7a5195" stroke-width="3" stroke-dasharray="8 5"/><text class="legend" x="872" y="583">ID-only false joins</text>',
            '<line x1="1010" y1="579" x2="1040" y2="579" stroke="#00798c" stroke-width="3" stroke-dasharray="3 5"/><text class="legend" x="1047" y="583">strict false joins</text>',
            '<rect x="690" y="135" width="315" height="48" rx="6" fill="#eef3f8"/>',
            f'<text class="note" x="703" y="155">Cross-service reuse at 5%: strict {cross_strict:.2f}% false joins;</text>',
            f'<text class="note" x="703" y="174">correlation-ID-only {cross_unsafe:.2f}%</text>',
        ]
    )

    pieces.extend(
        [
            '<line x1="70" y1="625" x2="1170" y2="625" stroke="#dce2e8"/>',
            '<text class="note" x="70" y="650">Strict mode preserves evidence but withholds missing, conflicting, or observably ambiguous records from multi-event joins.</text>',
            '<text class="subtitle" x="70" y="677">Synthetic sensitivity analysis; values are not production prevalence or performance claims.</text>',
            '<text class="subtitle" x="70" y="699">Full medians, quartiles, counts, and definitions: summary_results.json.</text>',
        ]
    )
    pieces.append("</svg>")
    return "\n".join(pieces) + "\n"


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--summary",
        type=Path,
        default=HERE / "results" / "reference" / "summary_results.json",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=HERE / "results" / "reference" / "figure_correlation_robustness.svg",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    document = json.loads(args.summary.read_text(encoding="utf-8"))
    svg = generate_svg(document)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(svg, encoding="utf-8")
    print(f"figure={args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
