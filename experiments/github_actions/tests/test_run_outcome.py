import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from experiments.github_actions.capture_run_outcome_v1_3 import (
    EXECUTION_STEP,
    JOB_NAME,
    RUN_FIELDS,
    OutcomeError,
    build_failed_log_observation,
    build_outcome,
    write_outcome,
)


REPOSITORY = "obedebessa/eacp-operational-provenance"
RUN_ID = 123456789
PROTOCOL_COMMIT = "a" * 40
TAG = "eacp-v1.3-evidence/k8s-v1.34.8/run-01"


def source(*, conclusion="failure", tag=TAG, jobs=None):
    return {
        "attempt": 1,
        "conclusion": conclusion,
        "event": "push",
        "headBranch": tag,
        "headSha": PROTOCOL_COMMIT,
        "status": "completed",
        "url": f"https://github.com/{REPOSITORY}/actions/runs/{RUN_ID}",
        "workflowName": ".github/workflows/eacp-cross-plane-v1.3.yml",
        "jobs": [] if jobs is None else jobs,
        "untrusted_extra": "must-not-be-retained",
    }


def completed_job(conclusion="success", tag=TAG):
    return {
        "id": 987654321,
        "run_id": RUN_ID,
        "run_attempt": 1,
        "head_sha": PROTOCOL_COMMIT,
        "head_branch": tag,
        "workflow_name": f"EACP cross-plane v1.3 / {tag} / ref-selected",
        "name": "github-actions-to-kubernetes",
        "labels": ["ubuntu-24.04"],
        "status": "completed",
        "conclusion": conclusion,
        "started_at": "2026-09-02T20:00:00Z",
        "completed_at": "2026-09-02T20:01:00Z",
        "runner_id": 42,
        "runner_name": "sensitive-runner-name",
        "token": "must-not-be-retained",
        "steps": [
            {
                "number": 1,
                "name": "Set up job",
                "status": "completed",
                "conclusion": "success",
                "started_at": "2026-09-02T20:00:00Z",
                "completed_at": "2026-09-02T20:00:01Z",
                "log": "must-not-be-retained",
            }
        ],
    }


def invocation_observation(conclusion="success", tag=TAG):
    return {
        "schema_version": "eacp.tag-invocation-observation/1.3.0",
        "selected_run_id": RUN_ID,
        "evidence_tag": tag,
        "run": {"conclusion": conclusion},
    }


def failed_log_observation(conclusion="success", tag=TAG, log_bytes=b""):
    return build_failed_log_observation(
        log_bytes,
        repository=REPOSITORY,
        run_id=RUN_ID,
        protocol_commit=PROTOCOL_COMMIT,
        evidence_tag=tag,
        conclusion=conclusion,
        captured_at="2026-09-02T21:00:00Z",
        acquisition="saved-test-log",
        gh_version="gh version test",
    )


class RunOutcomeTests(unittest.TestCase):
    def build(self, value):
        return build_outcome(
            value,
            repository=REPOSITORY,
            run_id=RUN_ID,
            protocol_commit=PROTOCOL_COMMIT,
            captured_at="2026-09-02T21:00:00Z",
            acquisition="provided_json",
        )

    def test_success_is_minimized_and_checksum_bound(self):
        metadata, outcome = self.build(
            source(conclusion="success", jobs=[completed_job()])
        )
        self.assertEqual(set(metadata), set(RUN_FIELDS))
        self.assertEqual(outcome["schema_version"], "eacp.cross-version-run-outcome/1.3.0")
        self.assertEqual(outcome["kubernetes_version"], "v1.34.8")
        self.assertEqual(outcome["run_index"], 1)
        self.assertEqual(outcome["jobs"][0]["labels"], ["ubuntu-24.04"])
        self.assertNotIn("runner_name", outcome["jobs"][0])
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "run-123456789"
            write_outcome(
                output,
                metadata,
                outcome,
                invocation_observation(),
                failed_log_observation(),
            )
            self.assertEqual(
                {path.name for path in output.iterdir()},
                {
                    "run_metadata.json",
                    "job_outcome.json",
                    "tag_invocation.json",
                    "failed_log_observation.json",
                    "OUTCOME_SHA256SUMS",
                },
            )
            retained = "".join(
                path.read_text(encoding="utf-8") for path in output.iterdir() if path.is_file()
            )
            self.assertNotIn("must-not-be-retained", retained)
            self.assertNotIn("sensitive-runner-name", retained)
            for line in (output / "OUTCOME_SHA256SUMS").read_text(encoding="utf-8").splitlines():
                expected, relative = line.split(None, 1)
                target = output / relative.removeprefix("./")
                self.assertEqual(hashlib.sha256(target.read_bytes()).hexdigest(), expected)

    def test_startup_failure_without_a_job_is_preserved(self):
        metadata, outcome = self.build(source(conclusion="startup_failure"))
        self.assertEqual(metadata["conclusion"], "startup_failure")
        self.assertEqual(outcome["conclusion"], "startup_failure")
        self.assertEqual(outcome["jobs"], [])

    def test_failed_log_retains_only_exact_allowlisted_markers_and_full_hash(self):
        raw = (
            f"{JOB_NAME}\t{EXECUTION_STEP}\t2026-09-02T22:14:23.8679387Z "
            "Validated exact client/server/kubelet profile: v1.34.8\n"
            f"{JOB_NAME}\t{EXECUTION_STEP}\t2026-09-02T22:14:25Z secret=discard-me\n"
            f"{JOB_NAME}\t{EXECUTION_STEP}\t2026-09-02T22:14:31.5801070Z "
            "cross-plane validation failed: expected three GitHub evidence records\n"
        ).encode()
        diagnostic = failed_log_observation(conclusion="failure", log_bytes=raw)
        self.assertEqual(
            [row["marker"] for row in diagnostic["recognized_markers"]],
            [
                "exact_client_server_kubelet_profile_validated",
                "premature_completed_artifact_row_assertion",
            ],
        )
        self.assertNotIn("discard-me", repr(diagnostic))
        self.assertEqual(diagnostic["full_failed_log_sha256"], hashlib.sha256(raw).hexdigest())
        self.assertFalse(diagnostic["full_failed_log_retained"])

    def test_failed_log_rejects_mismatched_version_or_duplicate_marker(self):
        prefix = f"{JOB_NAME}\t{EXECUTION_STEP}\t2026-09-02T22:14:23Z "
        wrong = (prefix + "Validated exact client/server/kubelet profile: v1.35.5\n").encode()
        duplicate = (
            prefix + "Validated exact client/server/kubelet profile: v1.34.8\n"
            + prefix + "Validated exact client/server/kubelet profile: v1.34.8\n"
        ).encode()
        for raw in (wrong, duplicate):
            with self.subTest(raw=raw), self.assertRaises(OutcomeError):
                failed_log_observation(conclusion="failure", log_bytes=raw)

    def test_confirmatory_tags_run_04_through_06_are_accepted(self):
        for version in ("v1.34.8", "v1.35.5", "v1.36.1"):
            for run_index in range(4, 7):
                tag = f"eacp-v1.3-evidence/k8s-{version}/run-{run_index:02d}"
                with self.subTest(tag=tag):
                    _, outcome = self.build(
                        source(
                            conclusion="success",
                            tag=tag,
                            jobs=[completed_job(tag=tag)],
                        )
                    )
                    self.assertEqual(outcome["kubernetes_version"], version)
                    self.assertEqual(outcome["run_index"], run_index)

    def test_unapproved_identity_or_rerun_is_rejected(self):
        cases = []
        wrong_attempt = source()
        wrong_attempt["attempt"] = 2
        cases.append(wrong_attempt)
        wrong_sha = source()
        wrong_sha["headSha"] = "b" * 40
        cases.append(wrong_sha)
        wrong_workflow = source()
        wrong_workflow["workflowName"] = "Other workflow"
        cases.append(wrong_workflow)
        cases.append(source(tag="eacp-v1.3-evidence/k8s-v1.34.8/run-00"))
        cases.append(source(tag="eacp-v1.3-evidence/k8s-v1.34.8/run-07"))
        cases.append(source(tag="eacp-v1.3-evidence/k8s-v1.37.0/run-01"))
        for value in cases:
            with self.subTest(value=value), self.assertRaises(OutcomeError):
                self.build(value)

    def test_refuses_to_overwrite_any_existing_path(self):
        metadata, outcome = self.build(source())
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "existing"
            output.mkdir()
            with self.assertRaises(OutcomeError):
                write_outcome(
                    output,
                    metadata,
                    outcome,
                    invocation_observation(conclusion=outcome["conclusion"]),
                    failed_log_observation(conclusion=outcome["conclusion"]),
                )


if __name__ == "__main__":
    unittest.main()
