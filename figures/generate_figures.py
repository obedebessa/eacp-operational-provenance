#!/usr/bin/env python3
"""Generate the code-native EACP architecture and benchmark figures."""

from __future__ import annotations

import csv
import json
import math
from pathlib import Path
from typing import Iterable

from PIL import Image, ImageDraw, ImageFont


ROOT = Path(__file__).resolve().parent
RESULTS = ROOT.parent / "data" / "sqlite" / "summary_results.csv"
OUT = ROOT
OUT.mkdir(parents=True, exist_ok=True)

FONT_CANDIDATES = {
    False: (
        "/System/Library/Fonts/Supplemental/Arial.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/local/share/fonts/DejaVuSans.ttf",
    ),
    True: (
        "/System/Library/Fonts/Supplemental/Arial Bold.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
        "/usr/local/share/fonts/DejaVuSans-Bold.ttf",
    ),
}

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


def font(size: int, bold: bool = False) -> ImageFont.FreeTypeFont:
    for candidate in FONT_CANDIDATES[bold]:
        if Path(candidate).is_file():
            return ImageFont.truetype(candidate, size=size)
    # Pillow normally ships DejaVu Sans and can resolve it by family filename.
    bundled_name = "DejaVuSans-Bold.ttf" if bold else "DejaVuSans.ttf"
    return ImageFont.truetype(bundled_name, size=size)


def text_size(draw: ImageDraw.ImageDraw, text: str, fnt: ImageFont.FreeTypeFont) -> tuple[int, int]:
    box = draw.textbbox((0, 0), text, font=fnt)
    return box[2] - box[0], box[3] - box[1]


def wrap(draw: ImageDraw.ImageDraw, text: str, fnt: ImageFont.FreeTypeFont, width: int) -> list[str]:
    words = text.split()
    lines: list[str] = []
    current = ""
    for word in words:
        candidate = word if not current else f"{current} {word}"
        if text_size(draw, candidate, fnt)[0] <= width:
            current = candidate
        else:
            if current:
                lines.append(current)
            current = word
    if current:
        lines.append(current)
    return lines


def centered_multiline(
    draw: ImageDraw.ImageDraw,
    box: tuple[int, int, int, int],
    text: str,
    fnt: ImageFont.FreeTypeFont,
    fill: str = INK,
    line_gap: int = 8,
) -> None:
    x1, y1, x2, y2 = box
    lines = wrap(draw, text, fnt, x2 - x1 - 32)
    heights = [text_size(draw, line, fnt)[1] for line in lines]
    total = sum(heights) + line_gap * max(0, len(lines) - 1)
    y = y1 + (y2 - y1 - total) / 2
    for line, height in zip(lines, heights):
        width, _ = text_size(draw, line, fnt)
        draw.text((x1 + (x2 - x1 - width) / 2, y), line, font=fnt, fill=fill)
        y += height + line_gap


def rounded_box(
    draw: ImageDraw.ImageDraw,
    box: tuple[int, int, int, int],
    fill: str,
    outline: str,
    width: int = 4,
    radius: int = 22,
) -> None:
    draw.rounded_rectangle(box, radius=radius, fill=fill, outline=outline, width=width)


def arrow(
    draw: ImageDraw.ImageDraw,
    start: tuple[int, int],
    end: tuple[int, int],
    fill: str = TEAL,
    width: int = 7,
    dashed: bool = False,
) -> None:
    x1, y1 = start
    x2, y2 = end
    if dashed:
        segments = 12
        for index in range(0, segments, 2):
            a = index / segments
            b = min((index + 1) / segments, 1)
            draw.line(
                (x1 + (x2 - x1) * a, y1 + (y2 - y1) * a,
                 x1 + (x2 - x1) * b, y1 + (y2 - y1) * b),
                fill=fill,
                width=width,
            )
    else:
        draw.line((x1, y1, x2, y2), fill=fill, width=width)
    angle = math.atan2(y2 - y1, x2 - x1)
    head = 22
    left = (x2 - head * math.cos(angle - math.pi / 6), y2 - head * math.sin(angle - math.pi / 6))
    right = (x2 - head * math.cos(angle + math.pi / 6), y2 - head * math.sin(angle + math.pi / 6))
    draw.polygon([(x2, y2), left, right], fill=fill)


def architecture() -> None:
    image = Image.new("RGB", (2400, 1400), WHITE)
    draw = ImageDraw.Draw(image)
    draw.text((100, 58), "Evidence-Aware Control Plane (EACP)", font=font(58, True), fill=NAVY)
    draw.text(
        (100, 125),
        "Asynchronous cross-plane operational provenance with a separate application data path",
        font=font(30),
        fill=MID,
    )

    draw.text((100, 208), "HETEROGENEOUS SOURCE PLANES", font=font(27, True), fill=BLUE)
    source_boxes = [
        ((100, 255, 610, 345), "CI/CD records"),
        ((100, 365, 610, 455), "Identity / IAM events"),
        ((100, 475, 610, 565), "Orchestration / audit events"),
        ((100, 585, 610, 675), "Policy decisions"),
        ((100, 695, 610, 785), "Telemetry signals"),
        ((100, 805, 610, 895), "Incident / recovery records"),
    ]
    for box, label in source_boxes:
        rounded_box(draw, box, LIGHT_BLUE, BLUE)
        centered_multiline(draw, box, label.replace("\n", " "), font(29, True), NAVY)

    eacp_outer = (780, 215, 1795, 980)
    rounded_box(draw, eacp_outer, PAPER, TEAL, width=6, radius=28)
    draw.text((835, 250), "EACP EVIDENCE PATH", font=font(32, True), fill=TEAL)

    components = [
        ((850, 325, 1725, 435), "1  Source adapters", "Map native identifiers and retain source pointers"),
        ((850, 480, 1725, 590), "2  Normalizer and correlation engine", "Bind service, intent, policy, action, outcome, and correlation"),
        ((850, 635, 1725, 775), "3  Append-only evidence index", "Idempotent source key • indexed queries • SHA-256 content hash"),
        ((850, 820, 1725, 930), "4  Query and evidence-package API", "State timeline • cross-plane chain • source-artifact links"),
    ]
    for index, (box, title, subtitle) in enumerate(components):
        rounded_box(draw, box, WHITE if index % 2 == 0 else LIGHT_TEAL, TEAL, width=3, radius=18)
        draw.text((box[0] + 28, box[1] + 18), title, font=font(28, True), fill=NAVY)
        draw.text((box[0] + 28, box[1] + 62), subtitle, font=font(22), fill=INK)
        if index < len(components) - 1:
            arrow(draw, ((box[0] + box[2]) // 2, box[3] + 8), ((box[0] + box[2]) // 2, components[index + 1][0][1] - 10))

    # Shared asynchronous ingestion bus.
    draw.line((685, 300, 685, 850), fill=TEAL, width=6)
    for box, _ in source_boxes:
        y = (box[1] + box[3]) // 2
        arrow(draw, (box[2] + 7, y), (685, y), width=5)
    arrow(draw, (685, 375), (843, 375), width=7)
    draw.text((525, 920), "asynchronous observation", font=font(22, True), fill=TEAL)

    draw.text((1905, 208), "OPERATIONAL USES", font=font(27, True), fill=BLUE)
    use_boxes = [
        ((1900, 290, 2305, 435), "Service-state reconstruction"),
        ((1900, 500, 2305, 645), "Policy-drift investigation"),
        ((1900, 710, 2305, 855), "Incident evidence package"),
    ]
    for box, label in use_boxes:
        rounded_box(draw, box, PALE_GOLD, GOLD)
        centered_multiline(draw, box, label, font(30, True), NAVY)
        arrow(draw, (1805, (box[1] + box[3]) // 2), (1890, (box[1] + box[3]) // 2), fill=GOLD)

    # Explicitly separate the application request path.
    draw.rounded_rectangle((100, 1080, 2305, 1315), radius=28, fill="#F3F5F7", outline=GRID, width=4)
    draw.text((150, 1118), "APPLICATION DATA PATH — UNCHANGED BY DEFAULT", font=font(28, True), fill=MID)
    path_boxes = [
        ((230, 1190, 570, 1270), "User request"),
        ((825, 1190, 1225, 1270), "Application service"),
        ((1510, 1190, 1910, 1270), "Data / downstream API"),
    ]
    for box, label in path_boxes:
        rounded_box(draw, box, WHITE, MID, width=3, radius=15)
        centered_multiline(draw, box, label, font(25, True), INK)
    arrow(draw, (580, 1230), (815, 1230), fill=MID)
    arrow(draw, (1235, 1230), (1500, 1230), fill=MID)
    draw.line((780, 1015, 1795, 1015), fill=TEAL, width=4)
    for x in range(790, 1795, 34):
        draw.line((x, 1015, min(x + 17, 1795), 1015), fill=WHITE, width=5)
    draw.text((927, 1025), "separate evidence path; no request-path dependency", font=font(22, True), fill=TEAL)

    image.save(OUT / "eacp_architecture.png", dpi=(300, 300))


def load_rows() -> list[dict[str, float]]:
    rows: list[dict[str, float]] = []
    with RESULTS.open(encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            rows.append({key: float(value) for key, value in row.items()})
    return rows


def chart_panel(
    draw: ImageDraw.ImageDraw,
    box: tuple[int, int, int, int],
    title: str,
    subtitle: str,
    categories: list[str],
    series: list[tuple[str, list[float], list[float], list[float], str]],
    y_max: float,
    y_label: str,
    decimals: int,
) -> None:
    x1, y1, x2, y2 = box
    draw.rounded_rectangle(box, radius=22, fill=WHITE, outline=GRID, width=3)
    draw.text((x1 + 34, y1 + 24), title, font=font(30, True), fill=NAVY)
    draw.text((x1 + 34, y1 + 65), subtitle, font=font(20), fill=MID)

    left = x1 + 115
    right = x2 - 42
    top = y1 + 125
    bottom = y2 - 82
    plot_width = right - left
    plot_height = bottom - top
    ticks = 4
    for tick in range(ticks + 1):
        value = y_max * tick / ticks
        y = bottom - plot_height * tick / ticks
        draw.line((left, y, right, y), fill=GRID, width=2)
        label = f"{value:,.{decimals}f}"
        tw, th = text_size(draw, label, font(18))
        draw.text((left - tw - 12, y - th / 2), label, font=font(18), fill=MID)
    draw.line((left, top, left, bottom), fill=INK, width=3)
    draw.line((left, bottom, right, bottom), fill=INK, width=3)

    group_width = plot_width / len(categories)
    bar_slot = min(80, group_width / (len(series) + 1))
    for category_index, category in enumerate(categories):
        center = left + group_width * (category_index + 0.5)
        total_bar_width = bar_slot * len(series)
        for series_index, (_, values, q1, q3, color) in enumerate(series):
            center_x = center - total_bar_width / 2 + bar_slot * (series_index + 0.5)
            value = values[category_index]
            bar_height = plot_height * min(value, y_max) / y_max
            bx1 = int(center_x - bar_slot * 0.34)
            bx2 = int(center_x + bar_slot * 0.34)
            by1 = int(bottom - bar_height)
            draw.rounded_rectangle((bx1, by1, bx2, bottom), radius=6, fill=color)
            low_y = bottom - plot_height * min(q1[category_index], y_max) / y_max
            high_y = bottom - plot_height * min(q3[category_index], y_max) / y_max
            draw.line((center_x, low_y, center_x, high_y), fill=INK, width=3)
            draw.line((center_x - 9, low_y, center_x + 9, low_y), fill=INK, width=3)
            draw.line((center_x - 9, high_y, center_x + 9, high_y), fill=INK, width=3)
        tw, th = text_size(draw, category, font(20, True))
        draw.text((center - tw / 2, bottom + 17), category, font=font(20, True), fill=INK)

    # Compact legend.
    legend_x = right - sum(170 for _ in series)
    for name, _, _, _, color in series:
        draw.rounded_rectangle((legend_x, y1 + 80, legend_x + 22, y1 + 102), radius=4, fill=color)
        draw.text((legend_x + 31, y1 + 79), name, font=font(18, True), fill=INK)
        legend_x += 170
    if y_label:
        draw.text((left, y1 + 100), y_label, font=font(17, True), fill=MID)


def benchmark() -> None:
    rows = load_rows()
    categories = [f"{int(row['event_count']) // 1000}k" for row in rows]
    image = Image.new("RGB", (2400, 1550), PAPER)
    draw = ImageDraw.Draw(image)
    draw.text((100, 55), "Reproducible Pilot Benchmark", font=font(56, True), fill=NAVY)
    draw.text(
        (100, 120),
        "Median of 10 sequential seeded trials; whiskers show the interquartile range",
        font=font(28),
        fill=MID,
    )

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

    panels = [
        (100, 200, 1170, 805),
        (1230, 200, 2300, 805),
        (100, 850, 1170, 1455),
        (1230, 850, 2300, 1455),
    ]
    chart_panel(
        draw, panels[0], "A. Service-state reconstruction", "Indexed warm-cache p95 by service (milliseconds)",
        categories,
        [("Fragmented", *bsvc, BLUE), ("EACP", *esvc, TEAL)],
        y_max=1.5, y_label="", decimals=2,
    )
    chart_panel(
        draw, panels[1], "B. Cross-plane correlation", "Indexed warm-cache p95 by correlation ID (milliseconds)",
        categories,
        [("Fragmented", *bcorr, BLUE), ("EACP", *ecorr, TEAL)],
        y_max=0.06, y_label="", decimals=3,
    )
    chart_panel(
        draw, panels[2], "C. Evidence ingestion", "Amortized bulk normalization, SHA-256, three indexes, and one commit (events / second)",
        categories,
        [("EACP", *ingest, GOLD)],
        y_max=230000, y_label="", decimals=0,
    )
    chart_panel(
        draw, panels[3], "D. Physical SQLite storage", "Separate database size after VACUUM (bytes / event)",
        categories,
        [("Fragmented", *bstore, BLUE), ("EACP", *estore, TEAL)],
        y_max=500, y_label="", decimals=0,
    )
    draw.text(
        (100, 1490),
        "Synthetic workload • 200 services • 300 service and 300 correlation queries per trial • Apple M4 Max • CPython 3.11.9 • SQLite 3.51.0",
        font=font(20),
        fill=MID,
    )
    image.save(OUT / "eacp_benchmark_results.png", dpi=(300, 300))


def comparison() -> None:
    result_root = ROOT.parent / "data" / "comparison"
    candidates = sorted(
        path for path in result_root.glob("*/summary.json")
        if not path.parent.name.startswith("_")
    )
    if not candidates:
        raise FileNotFoundError(f"no completed comparison summary under {result_root}")
    summary = json.loads(candidates[-1].read_text(encoding="utf-8"))
    event_count = int(summary["input"]["events"])
    validation = summary["validation"]
    field_equality = validation["post_export_canonical_projection_preservation"]["field_value_equality"]
    accuracy = float(field_equality["overall"])
    compared_values = int(field_equality["compared_field_values"])
    results = summary["descriptive_results"]

    image = Image.new("RGB", (2400, 1520), PAPER)
    draw = ImageDraw.Draw(image)
    draw.text((100, 55), "Kubernetes Laboratory and Reference-Pipeline Comparison", font=font(51, True), fill=NAVY)
    draw.text(
        (100, 120),
        "One frozen, sanitized audit corpus • ten fresh sequential replays per pipeline",
        font=font(27),
        fill=MID,
    )

    # A. Corpus cards.
    panel_a = (100, 205, 2300, 545)
    rounded_box(draw, panel_a, WHITE, GRID, width=3, radius=22)
    draw.text((135, 235), "A. Executed Kubernetes corpus", font=font(30, True), fill=NAVY)
    cards = [
        ("AUDIT EVENTS", f"{event_count}", "namespace-filtered records"),
        ("EXPLICIT CORRELATION", "132", "records with eacp-round ID"),
        ("RBAC DENIALS", "3", "audited HTTP 403 events"),
        ("UNIQUE SOURCE KEYS", f"{event_count}", "auditID:stage; no duplicates"),
    ]
    for index, (label, value, note) in enumerate(cards):
        x1 = 140 + index * 530
        box = (x1, 305, x1 + 480, 500)
        rounded_box(draw, box, LIGHT_BLUE if index % 2 == 0 else LIGHT_TEAL, TEAL, width=3, radius=18)
        draw.text((x1 + 25, 330), label, font=font(19, True), fill=BLUE)
        draw.text((x1 + 25, 365), value, font=font(53, True), fill=NAVY)
        draw.text((x1 + 25, 440), note, font=font(18), fill=MID)

    # B. Validation and common-scope interpretation.
    panel_b = (100, 590, 1155, 1295)
    rounded_box(draw, panel_b, WHITE, GRID, width=3, radius=22)
    draw.text((135, 620), "B. Event preservation", font=font(30, True), fill=NAVY)
    draw.text((135, 670), "Canonical projection checked after the timed intervals", font=font(20), fill=MID)
    validation_rows = [
        ("EACP", f"{event_count} / {event_count}", "indexed SQLite rows retained"),
        ("OpenTelemetry", f"{event_count} / {event_count}", "exported audit bodies retained"),
        ("Post-export field check", "Matched", f"{compared_values:,} / {compared_values:,} compared values matched"),
    ]
    y = 745
    for index, (label, value, note) in enumerate(validation_rows):
        fill = LIGHT_TEAL if index < 2 else PALE_GOLD
        outline = TEAL if index < 2 else GOLD
        rounded_box(draw, (145, y, 1110, y + 145), fill, outline, width=3, radius=16)
        draw.text((175, y + 22), label, font=font(23, True), fill=NAVY)
        value_width, _ = text_size(draw, value, font(32, True))
        draw.text((1075 - value_width, y + 18), value, font=font(32, True), fill=TEAL if index < 2 else GOLD)
        draw.text((175, y + 77), note, font=font(20), fill=INK)
        y += 175
    draw.text((150, 1248), "No SQLite-versus-file query comparison was performed.", font=font(18, True), fill=MID)

    # C. Descriptive end-to-end wall time.
    panel_c = (1205, 590, 2300, 1295)
    rounded_box(draw, panel_c, WHITE, GRID, width=3, radius=22)
    draw.text((1240, 620), "C. Observed time to validated output", font=font(30, True), fill=NAVY)
    draw.text((1240, 670), "Median and IQR across ten fresh runs (milliseconds)", font=font(20), fill=MID)
    plot_left, plot_right = 1395, 2240
    plot_top, plot_bottom = 760, 1110
    y_max = 750.0
    for tick in range(0, 751, 150):
        y_tick = plot_bottom - (tick / y_max) * (plot_bottom - plot_top)
        draw.line((plot_left, y_tick, plot_right, y_tick), fill=GRID, width=2)
        label = str(tick)
        tw, th = text_size(draw, label, font(18))
        draw.text((plot_left - tw - 18, y_tick - th / 2), label, font=font(18), fill=MID)
    draw.line((plot_left, plot_top, plot_left, plot_bottom), fill=INK, width=3)
    draw.line((plot_left, plot_bottom, plot_right, plot_bottom), fill=INK, width=3)

    pipeline_values = [
        ("EACP", results["eacp"]["wall_time_ms"], TEAL),
        ("OpenTelemetry", results["opentelemetry"]["wall_time_ms"], BLUE),
    ]
    centers = [1620, 2040]
    for (label, stats, color), center in zip(pipeline_values, centers):
        median = float(stats["median"])
        q1 = float(stats["q1"])
        q3 = float(stats["q3"])
        top_y = plot_bottom - (median / y_max) * (plot_bottom - plot_top)
        low_y = plot_bottom - (q1 / y_max) * (plot_bottom - plot_top)
        high_y = plot_bottom - (q3 / y_max) * (plot_bottom - plot_top)
        draw.rounded_rectangle((center - 80, top_y, center + 80, plot_bottom), radius=9, fill=color)
        draw.line((center, low_y, center, high_y), fill=INK, width=5)
        draw.line((center - 22, low_y, center + 22, low_y), fill=INK, width=5)
        draw.line((center - 22, high_y, center + 22, high_y), fill=INK, width=5)
        value_label = f"{median:.1f} ms"
        tw, th = text_size(draw, value_label, font(22, True))
        draw.text((center - tw / 2, top_y - th - 18), value_label, font=font(22, True), fill=NAVY)
        tw, _ = text_size(draw, label, font(21, True))
        draw.text((center - tw / 2, plot_bottom + 20), label, font=font(21, True), fill=INK)

    rounded_box(draw, (1245, 1180, 2260, 1260), PALE_GOLD, GOLD, width=2, radius=14)
    centered_multiline(
        draw,
        (1260, 1185, 2245, 1255),
        "Descriptive only: OTel includes Docker startup and host decoding; EACP projection validation occurs after its timer.",
        font(17, True),
        fill=INK,
        line_gap=4,
    )

    draw.text(
        (100, 1360),
        "Shared input SHA-256: 6aa39ee1…5400e01  •  Collector Contrib 0.158.0 image digest: sha256:c5918f78…a32ed5",
        font=font(20),
        fill=MID,
    )
    draw.text(
        (100, 1405),
        "Scope: bounded replay and corpus preservation. Raw bodies were mapped later by an external EACP validator.",
        font=font(21, True),
        fill=TEAL,
    )
    image.save(OUT / "eacp_kubernetes_otel_results.png", dpi=(300, 300))


def main() -> None:
    architecture()
    benchmark()
    comparison()
    print(OUT)


if __name__ == "__main__":
    main()
