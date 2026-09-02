#!/usr/bin/env python3
"""Generate publication PNGs for the EACP 1.3 candidate experiments."""

from __future__ import annotations

import csv
import json
from pathlib import Path

from PIL import Image, ImageDraw

from generate_figures import (
    BLUE,
    GOLD,
    GRID,
    INK,
    LIGHT_BLUE,
    LIGHT_TEAL,
    MID,
    NAVY,
    PALE_GOLD,
    PAPER,
    TEAL,
    WHITE,
    arrow,
    centered_multiline,
    font,
    rounded_box,
    text_size,
    wrap,
)


ROOT = Path(__file__).resolve().parent
REPOSITORY = ROOT.parent
CORRELATION_SUMMARY = (
    REPOSITORY
    / "experiments/correlation_robustness/results/reference/summary_results.csv"
)
LIVE_SUMMARY = (
    REPOSITORY
    / "experiments/github_actions/results/reference/run-33682116347/reference_summary.json"
)

GREEN = "#25805A"
PALE_GREEN = "#E3F3EA"
RED = "#A54545"
PALE_RED = "#F8E9E8"


def draw_lines(
    draw: ImageDraw.ImageDraw,
    x: int,
    y: int,
    text: str,
    size: int,
    width: int,
    *,
    bold: bool = False,
    fill: str = INK,
    gap: int = 8,
) -> int:
    face = font(size, bold)
    lines = wrap(draw, text, face, width)
    for line in lines:
        draw.text((x, y), line, font=face, fill=fill)
        y += text_size(draw, line, face)[1] + gap
    return y


def architecture_v1_3() -> None:
    image = Image.new("RGB", (2400, 1500), PAPER)
    draw = ImageDraw.Draw(image)
    draw.text((95, 55), "EACP Profile 1.3 and Evidence Path", font=font(58, True), fill=NAVY)
    draw.text(
        (95, 125),
        "Typed evidence composition with explicit abstention and a separate application data path",
        font=font(29),
        fill=MID,
    )

    draw.text((95, 215), "INDEPENDENT SOURCE PLANES", font=font(26, True), fill=BLUE)
    sources = [
        ("GitHub Actions", "run • job • artifact"),
        ("Kubernetes API", "audit • object • Pod"),
        ("Identity / policy", "decision • principal"),
        ("Telemetry / incident / recovery", "signal • ticket • restore"),
    ]
    y = 270
    for title, subtitle in sources:
        box = (95, y, 610, y + 130)
        rounded_box(draw, box, WHITE, BLUE, width=4, radius=20)
        draw.text((125, y + 24), title, font=font(29, True), fill=NAVY)
        draw.text((125, y + 75), subtitle, font=font(22), fill=MID)
        y += 160

    outer = (755, 205, 1780, 1120)
    rounded_box(draw, outer, WHITE, TEAL, width=6, radius=28)
    draw.text((810, 245), "OFF-PATH EVIDENCE CONTROL", font=font(30, True), fill=TEAL)
    components = [
        ((825, 325, 1710, 445), "1  Adapters", "stable source key • native pointer • source/observation time"),
        ((825, 485, 1710, 635), "2  EACP profile/1.3", "actor roles • scoped service • typed multi-links • optional source digest"),
        ((825, 675, 1710, 805), "3  Append-only materialization", "idempotent insert • service/time and link indexes • tuple digest"),
        ((825, 845, 1710, 1045), "4  Safe resolver", "exact typed + scoped key", "match set", "missing", "ambiguous"),
    ]
    for index, values in enumerate(components):
        box, title, subtitle, *states = values
        rounded_box(draw, box, LIGHT_TEAL if index == 3 else LIGHT_BLUE, TEAL, width=3, radius=18)
        draw.text((box[0] + 25, box[1] + 18), title, font=font(28, True), fill=NAVY)
        draw.text((box[0] + 25, box[1] + 62), subtitle, font=font(21), fill=INK)
        if states:
            state_y = box[1] + 116
            state_width = 245
            for state_index, state in enumerate(states):
                sx = box[0] + 25 + state_index * 275
                fill = PALE_GREEN if state_index == 0 else PALE_GOLD
                outline = GREEN if state_index == 0 else GOLD
                rounded_box(draw, (sx, state_y, sx + state_width, state_y + 54), fill, outline, width=2, radius=12)
                centered_multiline(draw, (sx, state_y, sx + state_width, state_y + 54), state, font(20, True), NAVY, 2)
        if index < len(components) - 1:
            next_box = components[index + 1][0]
            arrow(draw, ((box[0] + box[2]) // 2, box[3] + 8), ((box[0] + box[2]) // 2, next_box[1] - 10), width=7)

    bus_x = 685
    draw.line((bus_x, 335, bus_x, 815), fill=TEAL, width=6)
    y = 335
    for _ in sources:
        arrow(draw, (617, y), (bus_x, y), width=5)
        y += 160
    arrow(draw, (bus_x, 385), (815, 385), width=7)
    draw.text((487, 905), "asynchronous", font=font(22, True), fill=TEAL)

    draw.text((1860, 215), "RESOLUTION OUTPUT", font=font(26, True), fill=BLUE)
    outputs = [
        ((1840, 285, 2300, 430), "Ordered evidence chain", PALE_GREEN, GREEN),
        ((1840, 475, 2300, 620), "Native evidence pointers", PALE_GOLD, GOLD),
        ((1840, 665, 2300, 810), "Machine-readable abstention", PALE_RED, RED),
        ((1840, 855, 2300, 1035), "No automatic claim of truth, authenticity, or causality", LIGHT_BLUE, BLUE),
    ]
    for box, label, fill, outline in outputs:
        rounded_box(draw, box, fill, outline, width=4, radius=20)
        centered_multiline(draw, box, label, font(27, True), NAVY)
        arrow(draw, (1790, (box[1] + box[3]) // 2), (1830, (box[1] + box[3]) // 2), fill=outline, width=5)

    draw.rounded_rectangle((95, 1210, 2300, 1415), radius=28, fill="#F1F4F6", outline=GRID, width=4)
    draw.text((145, 1245), "APPLICATION REQUEST PATH — UNCHANGED BY DEFAULT", font=font(27, True), fill=MID)
    boxes = [
        ((230, 1320, 570, 1385), "User request"),
        ((865, 1320, 1265, 1385), "Application service"),
        ((1585, 1320, 2025, 1385), "Data / downstream API"),
    ]
    for box, label in boxes:
        rounded_box(draw, box, WHITE, MID, width=3, radius=14)
        centered_multiline(draw, box, label, font(23, True), INK, 2)
    arrow(draw, (580, 1352), (855, 1352), fill=MID, width=5)
    arrow(draw, (1275, 1352), (1575, 1352), fill=MID, width=5)
    image.save(ROOT / "eacp_architecture_v1_3.png", dpi=(300, 300))


def load_correlation_rows() -> dict[tuple[str, str], dict[str, str]]:
    with CORRELATION_SUMMARY.open(encoding="utf-8", newline="") as stream:
        rows = list(csv.DictReader(stream))
    return {(row["scenario"], row["algorithm"]): row for row in rows}


def metric(rows: dict[tuple[str, str], dict[str, str]], scenario: str, field: str) -> float:
    return float(rows[(scenario, "strict_service_plus_correlation")][field]) * 100.0


def correlation_robustness() -> None:
    rows = load_correlation_rows()
    image = Image.new("RGB", (2400, 1520), PAPER)
    draw = ImageDraw.Draw(image)
    draw.text((95, 52), "Correlation Failure Is a Measured Trade-off", font=font(57, True), fill=NAVY)
    draw.text((95, 120), "25 scenarios × 3 policies × 30 deterministic seeds; medians shown", font=font(28), fill=MID)

    # Left panel: missingness curve.
    left_box = (90, 215, 1190, 1165)
    rounded_box(draw, left_box, WHITE, GRID, width=3, radius=24)
    draw.text((135, 250), "Randomly missing identifiers", font=font(31, True), fill=NAVY)
    draw.text((135, 295), "Strict service + correlation policy", font=font(22), fill=MID)
    plot = (245, 385, 1110, 1030)
    px1, py1, px2, py2 = plot
    for tick in range(0, 101, 20):
        y = py2 - (py2 - py1) * tick / 100
        draw.line((px1, y, px2, y), fill=GRID, width=2)
        label = f"{tick}%"
        tw, th = text_size(draw, label, font(19))
        draw.text((px1 - tw - 15, y - th / 2), label, font=font(19), fill=MID)
    draw.line((px1, py1, px1, py2), fill=INK, width=3)
    draw.line((px1, py2, px2, py2), fill=INK, width=3)
    rates = [0, 1, 5, 10, 20]
    scenarios = ["control", "missing_random_1pct", "missing_random_5pct", "missing_random_10pct", "missing_random_20pct"]
    exact = [metric(rows, scenario, "exact_chain_accuracy_median") for scenario in scenarios]
    recall = [metric(rows, scenario, "join_recall_median") for scenario in scenarios]
    for values, color in ((exact, TEAL), (recall, GOLD)):
        points = []
        for index, value in enumerate(values):
            x = px1 + (px2 - px1) * index / (len(values) - 1)
            y = py2 - (py2 - py1) * value / 100
            points.append((x, y))
        draw.line(points, fill=color, width=8)
        for x, y in points:
            draw.ellipse((x - 11, y - 11, x + 11, y + 11), fill=color, outline=WHITE, width=3)
        for (x, y), value in zip(points, values):
            label = f"{value:.1f}%"
            tw, _ = text_size(draw, label, font(18, True))
            draw.text((x - tw / 2, y - 38), label, font=font(18, True), fill=color)
    for index, rate in enumerate(rates):
        x = px1 + (px2 - px1) * index / (len(rates) - 1)
        label = f"{rate}%"
        tw, _ = text_size(draw, label, font(20, True))
        draw.text((x - tw / 2, py2 + 20), label, font=font(20, True), fill=INK)
    draw.text((245, 1080), "Fraction of event identifiers removed", font=font(21, True), fill=MID)
    draw.line((315, 350, 375, 350), fill=TEAL, width=7)
    draw.text((390, 336), "Exact six-event chain", font=font(20, True), fill=INK)
    draw.line((720, 350, 780, 350), fill=GOLD, width=7)
    draw.text((795, 336), "Pairwise recall", font=font(20, True), fill=INK)

    # Right panel: safety/availability conditions.
    right_box = (1240, 215, 2310, 1165)
    rounded_box(draw, right_box, WHITE, GRID, width=3, radius=24)
    draw.text((1285, 250), "Adversarial cases", font=font(31, True), fill=NAVY)
    draw.text((1285, 295), "Strict policy; percentage of chains or observations", font=font(22), fill=MID)
    cases = [
        ("Same-service\nreuse 10%", "collision_same_service_10pct"),
        ("Wrong IDs\n20%", "wrong_id_same_service_20pct"),
        ("Clock skew\n10%, ±5 s", "clock_skew_random_10pct_5s"),
        ("Compound", "compound_adversarial"),
    ]
    rx1, ry1, rx2, ry2 = (1360, 400, 2250, 1015)
    for tick in range(0, 101, 20):
        y = ry2 - (ry2 - ry1) * tick / 100
        draw.line((rx1, y, rx2, y), fill=GRID, width=2)
        label = f"{tick}%"
        tw, th = text_size(draw, label, font(18))
        draw.text((rx1 - tw - 12, y - th / 2), label, font=font(18), fill=MID)
    draw.line((rx1, ry1, rx1, ry2), fill=INK, width=3)
    draw.line((rx1, ry2, rx2, ry2), fill=INK, width=3)
    colors = (TEAL, GOLD, RED)
    fields = ("exact_chain_accuracy_median", "join_recall_median", "abstention_rate_median")
    group_width = (rx2 - rx1) / len(cases)
    bar_width = 42
    for case_index, (label, scenario) in enumerate(cases):
        center = rx1 + group_width * (case_index + 0.5)
        for field_index, (field, color) in enumerate(zip(fields, colors)):
            value = metric(rows, scenario, field)
            x1 = center + (field_index - 1) * 52 - bar_width / 2
            x2 = x1 + bar_width
            y1 = ry2 - (ry2 - ry1) * value / 100
            draw.rounded_rectangle((x1, y1, x2, ry2), radius=6, fill=color)
        label_lines = label.split("\n")
        ly = ry2 + 17
        for line in label_lines:
            tw, th = text_size(draw, line, font(18, True))
            draw.text((center - tw / 2, ly), line, font=font(18, True), fill=INK)
            ly += th + 4
    legend = ((TEAL, "Exact chain"), (GOLD, "Pairwise recall"), (RED, "Abstention"))
    lx = 1360
    for color, label in legend:
        draw.rounded_rectangle((lx, 350, lx + 22, 372), radius=4, fill=color)
        draw.text((lx + 30, 347), label, font=font(18, True), fill=INK)
        lx += 270

    callout = (90, 1215, 2310, 1435)
    rounded_box(draw, callout, PALE_GREEN, GREEN, width=4, radius=24)
    draw.text((135, 1252), "Observed safety boundary", font=font(28, True), fill=GREEN)
    draw_lines(
        draw,
        135,
        1302,
        "Strict mode emitted zero false joins and accepted zero mixed groups in the declared adversarial matrix by abstaining. "
        "This is conditional on synthetic plane/cadence invariants; a complete, internally consistent wrong chain can evade structural checks.",
        24,
        2080,
        fill=INK,
        gap=7,
    )
    image.save(ROOT / "eacp_correlation_robustness_v1_3.png", dpi=(300, 300))


def live_cross_plane() -> None:
    summary = json.loads(LIVE_SUMMARY.read_text(encoding="utf-8"))
    attempts = summary["attempt_results"]
    image = Image.new("RGB", (2400, 1520), PAPER)
    draw = ImageDraw.Draw(image)
    draw.text((95, 52), "Public GitHub Actions → Kubernetes Evidence", font=font(56, True), fill=NAVY)
    draw.text(
        (95, 120),
        "Run 33682116347 • three successful attempts • exact source revision • frozen artifacts and attestations",
        font=font(27),
        fill=MID,
    )

    card_y1, card_y2 = 205, 430
    for index, attempt in enumerate(attempts):
        x1 = 95 + index * 770
        x2 = x1 + 710
        rounded_box(draw, (x1, card_y1, x2, card_y2), PALE_GREEN, GREEN, width=4, radius=24)
        draw.text((x1 + 30, card_y1 + 24), f"ATTEMPT {attempt['attempt']}  PASS", font=font(31, True), fill=GREEN)
        draw.text((x1 + 30, card_y1 + 78), "completed / success", font=font(22, True), fill=NAVY)
        draw.text((x1 + 30, card_y1 + 118), f"Kubernetes records: {attempt['kubernetes_namespace_records']}", font=font(21), fill=INK)
        draw.text((x1 + 30, card_y1 + 151), "8 source-native + 1 explicit target-bound", font=font(20), fill=INK)
        draw.text((x1 + 30, card_y1 + 184), f"archive sha256: {attempt['archive_sha256'][:16]}…", font=font(18), fill=MID)

    # Main evidence flow.
    y1, y2 = 535, 1050
    boxes = [
        ((95, y1, 670, y2), "GITHUB ACTIONS", "3 completed records", ["workflow", "job", "artifact"]),
        ((900, y1, 1500, y2), "EXACT HAND-OFF", "attempt-specific ID + OCI digest", ["8 source-native audit rows", "Deployment annotation", "Pod spec + runtime imageID"]),
        ((1730, y1, 2305, y2), "KUBERNETES", "real API-server evidence", ["51–56 sanitized rows", "negative control unjoined", "1 target-bound HTTP 403"]),
    ]
    for index, (box, title, subtitle, items) in enumerate(boxes):
        fill = WHITE if index != 1 else LIGHT_TEAL
        outline = BLUE if index != 1 else TEAL
        rounded_box(draw, box, fill, outline, width=5, radius=26)
        draw.text((box[0] + 38, box[1] + 38), title, font=font(30, True), fill=outline)
        draw_lines(draw, box[0] + 38, box[1] + 92, subtitle, 25, box[2] - box[0] - 75, bold=True, fill=NAVY)
        item_y = box[1] + 205
        for item in items:
            rounded_box(draw, (box[0] + 38, item_y, box[2] - 38, item_y + 70), LIGHT_BLUE, GRID, width=2, radius=14)
            centered_multiline(draw, (box[0] + 38, item_y, box[2] - 38, item_y + 70), item, font(22, True), INK, 3)
            item_y += 95
    arrow(draw, (685, 790), (885, 790), fill=TEAL, width=10)
    arrow(draw, (1515, 790), (1715, 790), fill=TEAL, width=10)
    draw.text((705, 735), "exact ID", font=font(22, True), fill=TEAL)
    draw.text((1537, 735), "observed", font=font(22, True), fill=TEAL)

    # Assurance and negative-control band.
    assurance = (95, 1125, 2305, 1435)
    rounded_box(draw, assurance, WHITE, GRID, width=4, radius=24)
    left = (135, 1170, 1125, 1388)
    right = (1270, 1170, 2265, 1388)
    rounded_box(draw, left, PALE_GREEN, GREEN, width=3, radius=18)
    rounded_box(draw, right, PALE_GOLD, GOLD, width=3, radius=18)
    draw.text((170, 1200), "ARCHIVE ASSURANCE  3/3", font=font(27, True), fill=GREEN)
    draw_lines(draw, 170, 1250, "Portable checksum matched; SLSA statement named the exact archive; offline Sigstore verification passed under repository, workflow, commit, ref, and hosted-runner policy.", 21, 900, fill=INK)
    draw.text((1305, 1200), "INTERPRETATION BOUNDARY", font=font(27, True), fill=GOLD)
    draw_lines(draw, 1305, 1250, "The positive chain is source-native. The 403 link is adapter-explicit by exact target because authorization preceded body decoding. No claim of source truth, universal causality, or production scale.", 21, 900, fill=INK)
    image.save(ROOT / "eacp_live_cross_plane_v1_3.png", dpi=(300, 300))


def main() -> None:
    architecture_v1_3()
    correlation_robustness()
    live_cross_plane()
    print("Generated EACP 1.3 figures")


if __name__ == "__main__":
    main()
