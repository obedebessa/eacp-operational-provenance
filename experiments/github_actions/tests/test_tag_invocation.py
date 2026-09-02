from __future__ import annotations

import copy
import unittest
from unittest.mock import patch

from experiments.github_actions import capture_tag_invocation_v1_3 as invocation


REPOSITORY = "obedebessa/eacp-operational-provenance"
TAG = "eacp-v1.3-evidence/k8s-v1.34.8/run-04"
RUN_ID = 123456789
COMMIT = "a" * 40


def run_listing() -> dict:
    run_name = f"EACP cross-plane v1.3 / {TAG} / ref-selected"
    run = {
        "id": RUN_ID,
        "workflow_id": 348771431,
        "run_number": 18,
        "run_attempt": 1,
        "event": "push",
        "head_branch": TAG,
        "head_sha": COMMIT,
        "path": invocation.WORKFLOW_PATH,
        "status": "completed",
        "conclusion": "success",
        "html_url": f"https://github.com/{REPOSITORY}/actions/runs/{RUN_ID}",
        "url": f"https://api.github.com/repos/{REPOSITORY}/actions/runs/{RUN_ID}",
        "name": run_name,
        "display_title": run_name,
        "previous_attempt_url": None,
        "pull_requests": [],
        "referenced_workflows": [],
        "repository": {"full_name": REPOSITORY, "private": False},
        "head_repository": {"full_name": REPOSITORY, "private": False},
        "head_commit": {"id": COMMIT, "timestamp": "2026-09-02T22:26:32Z"},
        "created_at": "2026-09-02T22:27:06Z",
        "run_started_at": "2026-09-02T22:27:06Z",
        "updated_at": "2026-09-02T22:28:05Z",
    }
    return {"total_count": 1, "workflow_runs": [run]}


class TagInvocationTests(unittest.TestCase):
    def build(self, source: dict | None = None) -> dict:
        return invocation.build_observation(
            run_listing() if source is None else source,
            repository=REPOSITORY,
            evidence_tag=TAG,
            run_id=RUN_ID,
            protocol_commit=COMMIT,
            conclusion="success",
            captured_at="2026-09-02T22:30:00Z",
            acquisition="saved-test-input",
        )

    def test_sole_exact_tag_invocation_is_minimized(self) -> None:
        observed = self.build()
        self.assertTrue(observed["sole_exact_tag_invocation_at_capture"])
        self.assertEqual(observed["total_count_at_capture"], 1)
        self.assertEqual(observed["run"]["id"], RUN_ID)
        retained = repr(observed)
        self.assertNotIn("actor", retained)
        self.assertIn("not a signed GitHub API response", observed["claim_boundary"])

    def test_multiple_or_truncated_invocations_are_rejected(self) -> None:
        duplicate = run_listing()
        duplicate["total_count"] = 2
        duplicate["workflow_runs"].append(copy.deepcopy(duplicate["workflow_runs"][0]))
        truncated = run_listing()
        truncated["total_count"] = 2
        for source in (duplicate, truncated):
            with self.subTest(source=source), self.assertRaises(invocation.InvocationError):
                self.build(source)

    def test_rerun_wrong_commit_and_wrong_workflow_are_rejected(self) -> None:
        cases = []
        for field, value in (
            ("run_attempt", 2),
            ("head_sha", "b" * 40),
            ("path", ".github/workflows/other.yml"),
            ("previous_attempt_url", "https://api.github.com/attempts/1"),
        ):
            source = run_listing()
            source["workflow_runs"][0][field] = value
            cases.append(source)
        for source in cases:
            with self.subTest(source=source), self.assertRaises(invocation.InvocationError):
                self.build(source)

    def test_fetch_query_is_exactly_scoped_to_github_workflow_and_tag(self) -> None:
        with patch.object(invocation, "command_json", return_value=run_listing()) as command:
            invocation.fetch_listing(REPOSITORY, TAG)
        argv = command.call_args.args[0]
        self.assertEqual(argv[argv.index("--hostname") + 1], "github.com")
        self.assertIn(
            f"repos/{REPOSITORY}/actions/workflows/{invocation.WORKFLOW_FILE}/runs",
            argv,
        )
        self.assertIn(f"branch={TAG}", argv)
        self.assertIn("event=push", argv)


if __name__ == "__main__":
    unittest.main()
