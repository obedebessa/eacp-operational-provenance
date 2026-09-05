#!/usr/bin/env python3
"""Describe supplied paired observations; never invent truth or infer field success."""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import math
import os
from pathlib import Path
import re
import statistics
import sys

REQUIRED = {
    "case_id", "method", "truth_status", "duration_seconds", "expected_links", "coverage",
    "correct_accepted_links", "false_accepted_links", "abstentions",
}
OPTIONAL = {"operational_cost_minutes"}
METHODS = ("baseline", "eacp")
MAX_ROWS = 20000


def number(text: str, field: str, *, integer=False) -> int | float:
    pattern = r"(?:0|[1-9][0-9]*)" if integer else r"(?:0|[1-9][0-9]*)(?:\.[0-9]+)?"
    if not isinstance(text, str) or len(text) > 32 or not re.fullmatch(pattern, text):
        raise ValueError(f"{field} requires a finite nonnegative {'integer' if integer else 'decimal'}")
    result = int(text) if integer else float(text)
    if not math.isfinite(result):
        raise ValueError(f"{field} is not finite")
    return result


def parse_csv(text: str) -> list[dict]:
    reader = csv.DictReader(io.StringIO(text, newline=""), strict=True)
    headers = reader.fieldnames
    if (headers is None or len(headers) != len(set(headers)) or not REQUIRED <= set(headers)
            or not set(headers) <= REQUIRED | OPTIONAL):
        raise ValueError("CSV headers must contain the exact required fields and only documented optional fields")
    rows = []
    for line, raw in enumerate(reader, 2):
        if line > MAX_ROWS + 1:
            raise ValueError("CSV exceeds the bounded row count")
        if None in raw or any(value is None for value in raw.values()):
            raise ValueError(f"CSV row {line} has a missing or extra field")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}", raw["case_id"]):
            raise ValueError(f"CSV row {line} requires a pseudonymous case identifier")
        if raw["method"] not in METHODS or raw["truth_status"] not in {"adjudicated", "unknown"}:
            raise ValueError(f"CSV row {line} has an unsupported method or truth status")
        row = {"case_id": raw["case_id"], "method": raw["method"], "truth_status": raw["truth_status"],
               "duration_seconds": number(raw["duration_seconds"], "duration_seconds"),
               "abstentions": number(raw["abstentions"], "abstentions", integer=True)}
        truth_fields = ("expected_links", "coverage", "correct_accepted_links", "false_accepted_links")
        if raw["truth_status"] == "unknown":
            if any(raw[field] != "" for field in truth_fields):
                raise ValueError("unknown truth must leave expected_links/coverage/correct/false fields blank")
            row.update({field: None for field in truth_fields})
        else:
            row.update({field: number(raw[field], field, integer=(field != "coverage")) for field in truth_fields})
            if row["expected_links"] < 1 or row["correct_accepted_links"] > row["expected_links"]:
                raise ValueError("adjudicated expected_links must be positive and cover all correct accepted links")
            if not 0 <= row["coverage"] <= 1:
                raise ValueError("coverage must be a fraction between zero and one")
            expected_coverage = row["correct_accepted_links"] / row["expected_links"]
            if not math.isclose(row["coverage"], expected_coverage, rel_tol=0, abs_tol=0.000001):
                raise ValueError("coverage disagrees with correct_accepted_links / expected_links")
        cost = raw.get("operational_cost_minutes", "")
        row["operational_cost_minutes"] = number(cost, "operational_cost_minutes") if cost else None
        rows.append(row)
    if not rows:
        raise ValueError("actual input observations are required; an empty CSV is not a pilot")
    return rows


def evaluate_rows(rows: list[dict]) -> dict:
    """Consume rows from parse_csv; report paired differences, including failures."""
    groups = {}
    for row in rows:
        case = groups.setdefault(row["case_id"], {})
        if row["method"] in case:
            raise ValueError("duplicate case/method observation")
        case[row["method"]] = row
    if not groups:
        raise ValueError("actual input observations are required")
    pairs = []
    for case_id, methods in sorted(groups.items()):
        if set(methods) != set(METHODS):
            raise ValueError("every case must contain one baseline and one EACP observation")
        baseline, eacp = (methods[method] for method in METHODS)
        if (baseline["truth_status"] != eacp["truth_status"]
                or baseline["expected_links"] != eacp["expected_links"]):
            raise ValueError("paired methods must use the same independently adjudicated truth scope")
        if (baseline["operational_cost_minutes"] is None) != (eacp["operational_cost_minutes"] is None):
            raise ValueError("paired operational costs must both be recorded or both be blank")
        deltas = {}
        for field in ("duration_seconds", "coverage", "correct_accepted_links", "false_accepted_links",
                      "abstentions", "operational_cost_minutes"):
            deltas[field] = None if baseline[field] is None else eacp[field] - baseline[field]
        pairs.append({"case_id": case_id, "baseline": baseline, "eacp": eacp,
                      "eacp_minus_baseline": deltas})
    summaries = {}
    for field in pairs[0]["eacp_minus_baseline"]:
        differences = [pair["eacp_minus_baseline"][field] for pair in pairs
                       if pair["eacp_minus_baseline"][field] is not None]
        summaries[field] = {"paired_n": len(differences),
                            "mean_difference": statistics.mean(differences) if differences else None,
                            "median_difference": statistics.median(differences) if differences else None}
    quality_totals = {}
    for method in METHODS:
        eligible = [pair[method] for pair in pairs if pair[method]["truth_status"] == "adjudicated"]
        correct = sum(row["correct_accepted_links"] for row in eligible)
        false = sum(row["false_accepted_links"] for row in eligible)
        expected = sum(row["expected_links"] for row in eligible)
        quality_totals[method] = {
            "adjudicated_cases": len(eligible), "correct_accepted_links": correct if eligible else None,
            "false_accepted_links": false if eligible else None, "expected_links": expected if eligible else None,
            "pooled_coverage": correct / expected if expected else None,
            "false_fraction_of_accepted_links": false / (correct + false) if correct + false else None,
        }
    return {
        "schema": "eacp.paired-pilot-description/1", "classification": "descriptive_user_supplied_observations",
        "case_count": len(pairs), "unknown_truth_cases": sum(pair["baseline"]["truth_status"] == "unknown" for pair in pairs),
        "paired_differences": summaries, "quality_totals": quality_totals, "cases": pairs,
        "difference_direction": "EACP minus baseline; negative duration/cost means less measured time",
        "input_authenticity_verified": False, "independently_reproduced": False,
        "field_success_inferred": False, "ground_truth_created_by_tool": False,
        "claim_boundary": "Descriptive paired observations only; unknown truth excluded from quality statistics, not converted to zero errors.",
        "unmeasured_costs": "One-time adapter/setup/training and unrecorded operating costs are not inferred; disclose them separately.",
    }


def evaluate_csv(text: str) -> dict:
    return evaluate_rows(parse_csv(text))


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, help="new file, never replace an earlier assessment")
    args = parser.parse_args(argv)
    try:
        with args.input.open("rb") as stream:
            raw = stream.read(8 * 1024 * 1024 + 1)
        if len(raw) > 8 * 1024 * 1024:
            raise ValueError("CSV exceeds eight MiB")
        result = evaluate_csv(raw.decode("utf-8-sig"))
        result["input_sha256"] = hashlib.sha256(raw).hexdigest()
        encoded = json.dumps(result, indent=2, sort_keys=True, allow_nan=False) + "\n"
        if args.output:
            descriptor = os.open(args.output, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                stream.write(encoded)
        else:
            sys.stdout.write(encoded)
        return 0
    except (OSError, ValueError, csv.Error) as exc:
        print(f"Pilot evaluation rejected: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
