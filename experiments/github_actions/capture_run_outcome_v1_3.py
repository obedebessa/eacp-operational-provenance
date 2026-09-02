#!/usr/bin/env python3
"""Freeze a minimized first-attempt outcome for the EACP cross-version cohort."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

try:
    from . import capture_tag_invocation_v1_3 as tag_invocation
except ImportError:  # Direct script execution.
    import capture_tag_invocation_v1_3 as tag_invocation


SCHEMA_VERSION = "eacp.cross-version-run-outcome/1.3.0"
DEFAULT_REPOSITORY = "obedebessa/eacp-operational-provenance"
WORKFLOW_NAME = "EACP cross-plane v1.3"
WORKFLOW_PATH = ".github/workflows/eacp-cross-plane-v1.3.yml"
JOB_NAME = "github-actions-to-kubernetes"
RUN_FIELDS = (
    "attempt",
    "conclusion",
    "event",
    "headBranch",
    "headSha",
    "status",
    "url",
    "workflowName",
)
TAG_PATTERN = re.compile(
    r"^eacp-v1\.3-evidence/k8s-(v1\.(?:34\.8|35\.5|36\.1))/run-(0[1-6])$"
)
REPOSITORY_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")
ALLOWED_CONCLUSIONS = {
    "action_required",
    "cancelled",
    "failure",
    "neutral",
    "skipped",
    "stale",
    "startup_failure",
    "success",
    "timed_out",
}
ALLOWED_JOB_STATUSES = {"completed"}
ALLOWED_STEP_STATUSES = {"completed", "in_progress", "pending", "queued"}
MAX_STEPS = 100
INITIAL_PROTOCOL_COMMIT = "15d72da095a0c7640b9318b50b28728e76d68928"
FAILED_LOG_SCHEMA_VERSION = "eacp.failed-log-observation/1.3.0"
EXECUTION_STEP = "Execute real cross-plane chain and controls"
VERSION_MARKER = re.compile(
    r"^Validated exact client/server/kubelet profile: "
    r"(?P<version>v1\.(?:34\.8|35\.5|36\.1))$"
)
LIFECYCLE_FAILURE_MESSAGE = (
    "cross-plane validation failed: expected three GitHub evidence records"
)


class OutcomeError(ValueError):
    """The supplied run cannot be admitted to the predeclared cohort."""


def require_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise OutcomeError(f"{label} must be a JSON object")
    return value


def require_string(value: Any, label: str, *, maximum: int = 512) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise OutcomeError(f"{label} must be a non-empty string of at most {maximum} characters")
    if any(character in value for character in "\x00\r\n"):
        raise OutcomeError(f"{label} contains a prohibited control character")
    return value


def optional_timestamp(value: Any, label: str) -> str | None:
    if value in (None, ""):
        return None
    text = require_string(value, label, maximum=64)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise OutcomeError(f"{label} is not an ISO 8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise OutcomeError(f"{label} must include a timezone")
    return text


def positive_integer(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise OutcomeError(f"{label} must be a positive integer")
    return value


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def command_json(argv: Sequence[str], label: str) -> Any:
    try:
        completed = subprocess.run(argv, check=False, capture_output=True, text=True)
    except OSError as exc:
        raise OutcomeError(f"could not execute {argv[0]!r}: {exc}") from exc
    if completed.returncode != 0:
        detail = completed.stderr.strip() or f"exit status {completed.returncode}"
        raise OutcomeError(f"{label} failed: {detail}")
    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise OutcomeError(f"{label} returned invalid JSON") from exc


def command_bytes(argv: Sequence[str], label: str) -> bytes:
    try:
        completed = subprocess.run(argv, check=False, capture_output=True)
    except OSError as exc:
        raise OutcomeError(f"could not execute {argv[0]!r}: {exc}") from exc
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        raise OutcomeError(f"{label} failed: {detail or f'exit status {completed.returncode}'}")
    return completed.stdout


def gh_cli_version() -> str:
    raw = command_bytes(["gh", "--version"], "gh version")
    try:
        first = raw.decode("utf-8").splitlines()[0]
    except (UnicodeDecodeError, IndexError) as exc:
        raise OutcomeError("gh version returned no valid UTF-8 version line") from exc
    return require_string(first, "gh CLI version", maximum=128)


def capture_failed_log(repository: str, run_id: int) -> bytes:
    return command_bytes(
        [
            "gh",
            "run",
            "view",
            str(run_id),
            "--repo",
            repository,
            "--attempt",
            "1",
            "--log-failed",
        ],
        "gh first-attempt failed-log capture",
    )


def build_failed_log_observation(
    log_bytes: bytes,
    *,
    repository: str,
    run_id: int,
    protocol_commit: str,
    evidence_tag: str,
    conclusion: str,
    captured_at: str,
    acquisition: str,
    gh_version: str,
) -> dict[str, Any]:
    """Retain only two exact diagnostic markers plus a fingerprint of the full log."""

    try:
        text = log_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise OutcomeError("failed-step log is not valid UTF-8") from exc
    tag_match = TAG_PATTERN.fullmatch(evidence_tag)
    if not tag_match:
        raise OutcomeError("failed-log observation has an invalid evidence tag")
    expected_version = tag_match.group(1)
    normalized_captured_at = optional_timestamp(captured_at, "failed-log captured_at")
    assert normalized_captured_at is not None
    require_string(acquisition, "failed-log source acquisition", maximum=128)
    require_string(gh_version, "failed-log gh CLI version", maximum=128)

    retained: list[dict[str, Any]] = []
    for raw_line in text.splitlines():
        fields = raw_line.split("\t", 2)
        if len(fields) != 3:
            continue
        job_name, step_name, timestamp_and_message = fields
        if job_name != JOB_NAME or step_name != EXECUTION_STEP:
            continue
        try:
            observed_timestamp, message = timestamp_and_message.split(" ", 1)
        except ValueError:
            continue
        marker = None
        version_match = VERSION_MARKER.fullmatch(message)
        if version_match:
            if version_match.group("version") != expected_version:
                raise OutcomeError("failed log reports a Kubernetes version different from its tag")
            marker = "exact_client_server_kubelet_profile_validated"
        elif message == LIFECYCLE_FAILURE_MESSAGE:
            marker = "premature_completed_artifact_row_assertion"
        if marker is None:
            continue
        observed = optional_timestamp(observed_timestamp, f"failed-log {marker} timestamp")
        assert observed is not None
        retained.append(
            {
                "marker": marker,
                "job_name": JOB_NAME,
                "step_name": EXECUTION_STEP,
                "timestamp": observed,
                "message": message,
                "selected_line_sha256": hashlib.sha256(raw_line.encode("utf-8")).hexdigest(),
            }
        )

    markers = [row["marker"] for row in retained]
    if len(markers) != len(set(markers)):
        raise OutcomeError("failed log contains duplicate recognized diagnostic markers")
    lifecycle_observed = "premature_completed_artifact_row_assertion" in markers
    version_observed = "exact_client_server_kubelet_profile_validated" in markers
    if lifecycle_observed and not version_observed:
        raise OutcomeError("lifecycle failure marker lacks the preceding exact-version marker")
    if protocol_commit == INITIAL_PROTOCOL_COMMIT and conclusion == "failure" and not (
        lifecycle_observed and version_observed
    ):
        raise OutcomeError("initial-cohort failure log lacks its two predeclared diagnostic markers")
    if lifecycle_observed:
        marker_times = {
            row["marker"]: datetime.fromisoformat(row["timestamp"].replace("Z", "+00:00"))
            for row in retained
        }
        if marker_times["exact_client_server_kubelet_profile_validated"] >= marker_times[
            "premature_completed_artifact_row_assertion"
        ]:
            raise OutcomeError("failed-log diagnostic markers are out of order")

    return {
        "schema_version": FAILED_LOG_SCHEMA_VERSION,
        "repository": repository,
        "run_id": run_id,
        "run_attempt": 1,
        "head_sha": protocol_commit,
        "evidence_tag": evidence_tag,
        "expected_kubernetes_version": expected_version,
        "conclusion": conclusion,
        "captured_at": normalized_captured_at,
        "source_acquisition": acquisition,
        "gh_cli_version": gh_version,
        "full_failed_log_sha256": hashlib.sha256(log_bytes).hexdigest(),
        "full_failed_log_size_bytes": len(log_bytes),
        "full_failed_log_retained": False,
        "recognized_markers": retained,
        "diagnostic_boundary": (
            "Only exact allowlisted program markers are retained; the full failed-step log is "
            "represented by its SHA-256 fingerprint and byte count. GitHub log text is a public "
            "API observation, not a signed origin record, and these markers do not convert the "
            "failed run into partial technical success."
        ),
    }


def capture_online(repository: str, run_id: int) -> dict[str, Any]:
    run = require_object(
        command_json(
            [
                "gh",
                "run",
                "view",
                str(run_id),
                "--repo",
                repository,
                "--json",
                ",".join(RUN_FIELDS),
            ],
            "gh run view",
        ),
        "gh run view response",
    )
    jobs_response = require_object(
        command_json(
            [
                "gh",
                "api",
                "-X",
                "GET",
                f"repos/{repository}/actions/runs/{run_id}/attempts/1/jobs",
                "-f",
                "per_page=100",
            ],
            "GitHub Actions jobs API",
        ),
        "jobs API response",
    )
    jobs = jobs_response.get("jobs")
    total_count = jobs_response.get("total_count")
    if not isinstance(jobs, list) or isinstance(total_count, bool) or not isinstance(total_count, int):
        raise OutcomeError("jobs API response lacks jobs and total_count")
    if total_count != len(jobs):
        raise OutcomeError("jobs API response was truncated or internally inconsistent")
    run["jobs"] = jobs
    return run


def normalized_step(value: Any, job_index: int, step_index: int) -> dict[str, Any]:
    step = require_object(value, f"jobs[{job_index}].steps[{step_index}]")
    number = step.get("number")
    if isinstance(number, bool) or not isinstance(number, int) or number < 0:
        raise OutcomeError(f"jobs[{job_index}].steps[{step_index}].number is invalid")
    status = require_string(step.get("status"), f"jobs[{job_index}].steps[{step_index}].status", maximum=32)
    if status not in ALLOWED_STEP_STATUSES:
        raise OutcomeError(f"jobs[{job_index}].steps[{step_index}].status is unsupported")
    conclusion_value = step.get("conclusion")
    conclusion = None
    if conclusion_value not in (None, ""):
        conclusion = require_string(
            conclusion_value, f"jobs[{job_index}].steps[{step_index}].conclusion", maximum=32
        )
        if conclusion not in ALLOWED_CONCLUSIONS:
            raise OutcomeError(f"jobs[{job_index}].steps[{step_index}].conclusion is unsupported")
    return {
        "number": number,
        "name": require_string(
            step.get("name"), f"jobs[{job_index}].steps[{step_index}].name", maximum=256
        ),
        "status": status,
        "conclusion": conclusion,
        "started_at": optional_timestamp(
            step.get("started_at", step.get("startedAt")),
            f"jobs[{job_index}].steps[{step_index}].started_at",
        ),
        "completed_at": optional_timestamp(
            step.get("completed_at", step.get("completedAt")),
            f"jobs[{job_index}].steps[{step_index}].completed_at",
        ),
    }


def normalized_job(
    value: Any,
    index: int,
    *,
    run_id: int,
    protocol_commit: str,
    evidence_tag: str,
) -> dict[str, Any]:
    job = require_object(value, f"jobs[{index}]")
    database_id = positive_integer(job.get("id", job.get("databaseId")), f"jobs[{index}].id")
    name = require_string(job.get("name"), f"jobs[{index}].name", maximum=256)
    if name != JOB_NAME:
        raise OutcomeError(f"jobs[{index}].name={name!r}; expected {JOB_NAME!r}")
    for field, expected in (
        ("run_id", run_id),
        ("run_attempt", 1),
        ("head_sha", protocol_commit),
        ("head_branch", evidence_tag),
        ("workflow_name", f"{WORKFLOW_NAME} / {evidence_tag} / ref-selected"),
    ):
        if field in job and job[field] != expected:
            raise OutcomeError(f"jobs[{index}].{field} differs from the selected run")
    labels = job.get("labels")
    if labels != ["ubuntu-24.04"]:
        raise OutcomeError(f"jobs[{index}].labels must equal ['ubuntu-24.04']")
    status = require_string(job.get("status"), f"jobs[{index}].status", maximum=32)
    if status not in ALLOWED_JOB_STATUSES:
        raise OutcomeError(f"jobs[{index}].status must be completed")
    conclusion = require_string(job.get("conclusion"), f"jobs[{index}].conclusion", maximum=32)
    if conclusion not in ALLOWED_CONCLUSIONS:
        raise OutcomeError(f"jobs[{index}].conclusion is unsupported")
    steps_value = job.get("steps")
    if not isinstance(steps_value, list) or len(steps_value) > MAX_STEPS:
        raise OutcomeError(f"jobs[{index}].steps must contain at most {MAX_STEPS} entries")
    steps = [normalized_step(step, index, step_index) for step_index, step in enumerate(steps_value)]
    numbers = [step["number"] for step in steps]
    if len(numbers) != len(set(numbers)):
        raise OutcomeError(f"jobs[{index}] contains duplicate step numbers")
    return {
        "database_id": database_id,
        "name": name,
        "labels": list(labels),
        "status": status,
        "conclusion": conclusion,
        "started_at": optional_timestamp(
            job.get("started_at", job.get("startedAt")), f"jobs[{index}].started_at"
        ),
        "completed_at": optional_timestamp(
            job.get("completed_at", job.get("completedAt")), f"jobs[{index}].completed_at"
        ),
        "steps": steps,
    }


def build_outcome(
    source: Any,
    *,
    repository: str,
    run_id: int,
    protocol_commit: str,
    captured_at: str,
    acquisition: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    value = require_object(source, "run source")
    if not REPOSITORY_PATTERN.fullmatch(repository):
        raise OutcomeError("repository must use owner/name syntax")
    if not SHA_PATTERN.fullmatch(protocol_commit):
        raise OutcomeError("protocol commit must be a lowercase 40-character Git SHA")
    expected_url = f"https://github.com/{repository}/actions/runs/{run_id}"
    expected = {
        "attempt": 1,
        "event": "push",
        "headSha": protocol_commit,
        "status": "completed",
        "url": expected_url,
        "workflowName": WORKFLOW_PATH,
    }
    for field, expected_value in expected.items():
        if value.get(field) != expected_value:
            raise OutcomeError(
                f"run {field}={value.get(field)!r}; expected {expected_value!r}"
            )
    conclusion = require_string(value.get("conclusion"), "run conclusion", maximum=32)
    if conclusion not in ALLOWED_CONCLUSIONS:
        raise OutcomeError(f"unsupported completed-run conclusion: {conclusion!r}")
    evidence_tag = require_string(value.get("headBranch"), "run headBranch", maximum=128)
    tag_match = TAG_PATTERN.fullmatch(evidence_tag)
    if not tag_match:
        raise OutcomeError(f"run is not an approved evidence tag: {evidence_tag!r}")
    kubernetes_version, run_index_text = tag_match.groups()
    jobs_value = value.get("jobs")
    if not isinstance(jobs_value, list) or len(jobs_value) > 1:
        raise OutcomeError("run must expose zero or one workflow job")
    jobs = [
        normalized_job(
            job,
            index,
            run_id=run_id,
            protocol_commit=protocol_commit,
            evidence_tag=evidence_tag,
        )
        for index, job in enumerate(jobs_value)
    ]
    if conclusion == "success" and len(jobs) != 1:
        raise OutcomeError("a successful run must contain its completed workflow job")
    if jobs and jobs[0]["conclusion"] != conclusion:
        raise OutcomeError("run and sole-job conclusions differ")
    normalized_captured_at = optional_timestamp(captured_at, "captured_at")
    assert normalized_captured_at is not None
    run_metadata = {field: value[field] for field in RUN_FIELDS}
    outcome = {
        "schema_version": SCHEMA_VERSION,
        "repository": repository,
        "run_id": run_id,
        "run_attempt": 1,
        "head_sha": protocol_commit,
        "evidence_tag": evidence_tag,
        "run_index": int(run_index_text),
        "kubernetes_version": kubernetes_version,
        "run_url": expected_url,
        "workflow_name": WORKFLOW_NAME,
        "event": "push",
        "status": "completed",
        "conclusion": conclusion,
        "captured_at": normalized_captured_at,
        "source_acquisition": acquisition,
        "jobs": jobs,
    }
    return run_metadata, outcome


def write_outcome(
    output_dir: Path,
    run_metadata: dict[str, Any],
    outcome: dict[str, Any],
    invocation: dict[str, Any],
    failed_log: dict[str, Any],
) -> None:
    if os.path.lexists(output_dir):
        raise OutcomeError(f"refusing to overwrite existing output: {output_dir}")
    output_dir.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(
        tempfile.mkdtemp(prefix=f".{output_dir.name}.pending-", dir=str(output_dir.parent))
    )
    try:
        metadata_path = temporary / "run_metadata.json"
        outcome_path = temporary / "job_outcome.json"
        invocation_path = temporary / "tag_invocation.json"
        failed_log_path = temporary / "failed_log_observation.json"
        metadata_path.write_text(
            json.dumps(run_metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        outcome_path.write_text(
            json.dumps(outcome, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        invocation_path.write_text(
            json.dumps(invocation, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        failed_log_path.write_text(
            json.dumps(failed_log, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        manifest = temporary / "OUTCOME_SHA256SUMS"
        manifest.write_text(
            "".join(
                f"{sha256(path)}  ./{path.name}\n"
                for path in (failed_log_path, outcome_path, metadata_path, invocation_path)
            ),
            encoding="utf-8",
        )
        temporary.replace(output_dir)
    except BaseException:
        shutil.rmtree(temporary, ignore_errors=True)
        raise


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser()
    value.add_argument("--repo", default=DEFAULT_REPOSITORY)
    value.add_argument("--run-id", required=True, type=int)
    value.add_argument("--protocol-commit", required=True)
    value.add_argument("--output-dir", required=True, type=Path)
    value.add_argument(
        "--input-json",
        type=Path,
        help="Read a saved gh-style run object instead of calling GitHub",
    )
    value.add_argument(
        "--input-invocation-json",
        type=Path,
        help="Read a saved exact-tag workflow-runs response instead of calling GitHub",
    )
    value.add_argument(
        "--input-failed-log",
        type=Path,
        help="Read saved first-attempt failed-step log bytes instead of calling GitHub",
    )
    return value


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    run_id = positive_integer(args.run_id, "run ID")
    if args.input_json:
        source = json.loads(args.input_json.read_text(encoding="utf-8"))
        acquisition = "provided_json"
    else:
        source = capture_online(args.repo, run_id)
        acquisition = "github_cli_read_only"
    captured_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )
    run_metadata, outcome = build_outcome(
        source,
        repository=args.repo,
        run_id=run_id,
        protocol_commit=args.protocol_commit,
        captured_at=captured_at,
        acquisition=acquisition,
    )
    if outcome["conclusion"] == "success":
        raise OutcomeError(
            "successful runs require capture_completed_run_v1_3.sh, not minimized outcome capture"
        )
    if args.input_json:
        if not args.input_invocation_json or not args.input_failed_log:
            raise OutcomeError(
                "--input-json requires --input-invocation-json and --input-failed-log"
            )
        invocation_source = json.loads(
            args.input_invocation_json.read_text(encoding="utf-8")
        )
        log_bytes = args.input_failed_log.read_bytes()
        log_acquisition = "provided_failed_log"
        version = "provided-gh-version"
    else:
        if args.input_invocation_json or args.input_failed_log:
            raise OutcomeError("saved invocation/log inputs require --input-json")
        invocation_source = tag_invocation.fetch_listing(args.repo, outcome["evidence_tag"])
        log_bytes = capture_failed_log(args.repo, run_id)
        log_acquisition = "github_cli_first_attempt_failed_log"
        version = gh_cli_version()
    invocation = tag_invocation.build_observation(
        invocation_source,
        repository=args.repo,
        evidence_tag=outcome["evidence_tag"],
        run_id=run_id,
        protocol_commit=args.protocol_commit,
        conclusion=outcome["conclusion"],
        captured_at=captured_at,
        acquisition="provided_json" if args.input_json else "github_workflow_runs_api",
    )
    failed_log = build_failed_log_observation(
        log_bytes,
        repository=args.repo,
        run_id=run_id,
        protocol_commit=args.protocol_commit,
        evidence_tag=outcome["evidence_tag"],
        conclusion=outcome["conclusion"],
        captured_at=captured_at,
        acquisition=log_acquisition,
        gh_version=version,
    )
    write_outcome(args.output_dir, run_metadata, outcome, invocation, failed_log)
    print(
        f"Captured {outcome['conclusion']} outcome for run {run_id} at {args.output_dir}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
