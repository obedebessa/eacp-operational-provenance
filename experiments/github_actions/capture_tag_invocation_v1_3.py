#!/usr/bin/env python3
"""Capture a minimized observation that an evidence tag triggered exactly one run."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence


SCHEMA_VERSION = "eacp.tag-invocation-observation/1.3.0"
WORKFLOW_PATH = ".github/workflows/eacp-cross-plane-v1.3.yml"
WORKFLOW_FILE = "eacp-cross-plane-v1.3.yml"
RUN_NAME = "EACP cross-plane v1.3"
TAG_PATTERN = re.compile(
    r"^eacp-v1\.3-evidence/k8s-v1\.(?:34\.8|35\.5|36\.1)/run-0[1-6]$"
)
SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")
REPOSITORY_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


class InvocationError(ValueError):
    """The workflow-run listing does not prove a sole exact-tag invocation."""


def require_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise InvocationError(f"{label} must be a JSON object")
    return value


def positive_integer(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise InvocationError(f"{label} must be a positive integer")
    return value


def timestamp(value: Any, label: str, *, allow_null: bool = False) -> str | None:
    if value is None and allow_null:
        return None
    if not isinstance(value, str) or not value or len(value) > 64:
        raise InvocationError(f"{label} must be a non-empty timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise InvocationError(f"{label} is not an ISO 8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise InvocationError(f"{label} must include a timezone")
    return value


def command_json(argv: Sequence[str], label: str) -> Any:
    try:
        completed = subprocess.run(argv, check=False, capture_output=True, text=True)
    except OSError as exc:
        raise InvocationError(f"could not execute {argv[0]!r}: {exc}") from exc
    if completed.returncode != 0:
        detail = completed.stderr.strip() or f"exit status {completed.returncode}"
        raise InvocationError(f"{label} failed: {detail}")
    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise InvocationError(f"{label} returned invalid JSON") from exc


def fetch_listing(repository: str, evidence_tag: str) -> dict[str, Any]:
    return require_object(
        command_json(
            [
                "gh",
                "api",
                "--hostname",
                "github.com",
                "-X",
                "GET",
                f"repos/{repository}/actions/workflows/{WORKFLOW_FILE}/runs",
                "-f",
                f"branch={evidence_tag}",
                "-f",
                "event=push",
                "-f",
                "per_page=100",
            ],
            "GitHub exact-tag workflow-runs query",
        ),
        "GitHub workflow-runs response",
    )


def build_observation(
    source: Any,
    *,
    repository: str,
    evidence_tag: str,
    run_id: int,
    protocol_commit: str,
    conclusion: str,
    captured_at: str,
    acquisition: str,
) -> dict[str, Any]:
    if not REPOSITORY_PATTERN.fullmatch(repository):
        raise InvocationError("repository must use owner/name syntax")
    if not TAG_PATTERN.fullmatch(evidence_tag):
        raise InvocationError("evidence tag is outside the exact v1.3 allowlist")
    positive_integer(run_id, "run ID")
    if not SHA_PATTERN.fullmatch(protocol_commit):
        raise InvocationError("protocol commit must be a lowercase 40-character Git SHA")
    if conclusion not in {
        "action_required",
        "cancelled",
        "failure",
        "neutral",
        "skipped",
        "stale",
        "startup_failure",
        "success",
        "timed_out",
    }:
        raise InvocationError("unsupported completed-run conclusion")
    captured = timestamp(captured_at, "captured_at")
    assert captured is not None

    response = require_object(source, "workflow-runs response")
    total_count = response.get("total_count")
    runs = response.get("workflow_runs")
    if (
        isinstance(total_count, bool)
        or not isinstance(total_count, int)
        or total_count != 1
        or not isinstance(runs, list)
        or len(runs) != 1
    ):
        raise InvocationError(
            "exact-tag query must report exactly one workflow invocation at capture time"
        )
    run = require_object(runs[0], "workflow-runs response member")
    canonical_web_url = f"https://github.com/{repository}/actions/runs/{run_id}"
    canonical_api_url = f"https://api.github.com/repos/{repository}/actions/runs/{run_id}"
    expected = {
        "id": run_id,
        "run_attempt": 1,
        "event": "push",
        "head_branch": evidence_tag,
        "head_sha": protocol_commit,
        "path": WORKFLOW_PATH,
        "status": "completed",
        "conclusion": conclusion,
        "html_url": canonical_web_url,
        "url": canonical_api_url,
        "name": f"{RUN_NAME} / {evidence_tag} / ref-selected",
        "display_title": f"{RUN_NAME} / {evidence_tag} / ref-selected",
        "previous_attempt_url": None,
    }
    for field, expected_value in expected.items():
        if run.get(field) != expected_value:
            raise InvocationError(
                f"sole exact-tag run {field}={run.get(field)!r}; expected {expected_value!r}"
            )
    positive_integer(run.get("workflow_id"), "workflow ID")
    positive_integer(run.get("run_number"), "workflow run number")
    if run.get("pull_requests") != [] or run.get("referenced_workflows") != []:
        raise InvocationError("evidence-tag run unexpectedly references a pull request or workflow")
    repository_value = require_object(run.get("repository"), "run repository")
    head_repository = require_object(run.get("head_repository"), "run head repository")
    if (
        repository_value.get("full_name") != repository
        or head_repository.get("full_name") != repository
        or repository_value.get("private") is not False
        or head_repository.get("private") is not False
    ):
        raise InvocationError("exact-tag run repository identity or visibility differs")
    head_commit = require_object(run.get("head_commit"), "run head commit")
    if head_commit.get("id") != protocol_commit:
        raise InvocationError("exact-tag run head-commit identity differs")

    created_at = timestamp(run.get("created_at"), "run created_at")
    started_at = timestamp(run.get("run_started_at"), "run run_started_at", allow_null=True)
    updated_at = timestamp(run.get("updated_at"), "run updated_at")
    head_commit_timestamp = timestamp(head_commit.get("timestamp"), "head commit timestamp")
    assert created_at is not None and updated_at is not None and head_commit_timestamp is not None

    return {
        "schema_version": SCHEMA_VERSION,
        "repository": repository,
        "workflow_path": WORKFLOW_PATH,
        "evidence_tag": evidence_tag,
        "protocol_commit": protocol_commit,
        "selected_run_id": run_id,
        "captured_at": captured,
        "source_acquisition": acquisition,
        "query": {
            "hostname": "github.com",
            "branch": evidence_tag,
            "event": "push",
            "per_page": 100,
        },
        "total_count_at_capture": 1,
        "sole_exact_tag_invocation_at_capture": True,
        "selection_policy": (
            "Fail unless the exact workflow/tag push query returns one and only one run; "
            "run_attempt=1 alone is not treated as proof of first tag invocation."
        ),
        "run": {
            "id": run_id,
            "workflow_id": run["workflow_id"],
            "run_number": run["run_number"],
            "run_attempt": 1,
            "event": "push",
            "head_branch": evidence_tag,
            "head_sha": protocol_commit,
            "path": WORKFLOW_PATH,
            "status": "completed",
            "conclusion": conclusion,
            "created_at": created_at,
            "run_started_at": started_at,
            "updated_at": updated_at,
            "head_commit_timestamp": head_commit_timestamp,
            "html_url": canonical_web_url,
            "api_url": canonical_api_url,
        },
        "claim_boundary": (
            "This checksum-bound file records GitHub's public API response at capture time. "
            "It proves the cohort selector did not choose among multiple exact-tag invocations "
            "then; it is not a signed GitHub API response and should be rechecked online when needed."
        ),
    }


def write_observation(path: Path, value: dict[str, Any]) -> None:
    if os.path.lexists(path):
        raise InvocationError(f"refusing to overwrite existing output: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser()
    value.add_argument("--repo", required=True)
    value.add_argument("--tag", required=True)
    value.add_argument("--run-id", required=True, type=int)
    value.add_argument("--protocol-commit", required=True)
    value.add_argument("--conclusion", required=True)
    value.add_argument("--output", required=True, type=Path)
    value.add_argument("--input-json", type=Path)
    return value


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    source = (
        json.loads(args.input_json.read_text(encoding="utf-8"))
        if args.input_json
        else fetch_listing(args.repo, args.tag)
    )
    acquisition = "provided_json" if args.input_json else "github_workflow_runs_api"
    captured_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )
    observation = build_observation(
        source,
        repository=args.repo,
        evidence_tag=args.tag,
        run_id=args.run_id,
        protocol_commit=args.protocol_commit,
        conclusion=args.conclusion,
        captured_at=captured_at,
        acquisition=acquisition,
    )
    write_observation(args.output, observation)
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
