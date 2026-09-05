"""Synthetic tooling fixtures only; never execute the full reproduction recursively."""

import csv
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

from scripts import evaluate_pilot_v1_4 as pilot
from scripts import reproduce_hardening_v1_4 as reproduction

ROOT = Path(__file__).resolve().parents[2]
HEADERS = ["case_id", "method", "truth_status", "duration_seconds", "expected_links", "coverage",
           "correct_accepted_links", "false_accepted_links", "abstentions", "operational_cost_minutes"]


def csv_fixture(rows=None):
    stream = io.StringIO(newline="")
    writer = csv.writer(stream)
    writer.writerow(HEADERS)
    writer.writerows(rows if rows is not None else [
        ["fixture-1", "baseline", "adjudicated", "100", "4", "0.5", "2", "1", "2", "8"],
        ["fixture-1", "eacp", "adjudicated", "60", "4", "0.75", "3", "0", "1", "5"],
    ])
    return stream.getvalue()


class PilotEvaluatorTests(unittest.TestCase):
    def test_paired_descriptive_results_have_no_automatic_claims(self):
        result = pilot.evaluate_csv(csv_fixture())
        self.assertEqual(result["case_count"], 1)
        self.assertEqual(result["paired_differences"]["duration_seconds"]["mean_difference"], -40)
        self.assertEqual(result["paired_differences"]["coverage"]["mean_difference"], 0.25)
        self.assertEqual(result["paired_differences"]["operational_cost_minutes"]["mean_difference"], -3)
        for field in ("input_authenticity_verified", "independently_reproduced", "field_success_inferred",
                      "ground_truth_created_by_tool"):
            self.assertIs(result[field], False)

    def test_unknown_truth_is_retained_and_excluded_not_zeroed(self):
        result = pilot.evaluate_csv(csv_fixture([
            ["unknown-1", "baseline", "unknown", "12", "", "", "", "", "3", ""],
            ["unknown-1", "eacp", "unknown", "10", "", "", "", "", "2", ""],
        ]))
        self.assertEqual(result["unknown_truth_cases"], 1)
        self.assertEqual(result["paired_differences"]["duration_seconds"]["paired_n"], 1)
        self.assertEqual(result["paired_differences"]["coverage"]["paired_n"], 0)
        self.assertIsNone(result["quality_totals"]["eacp"]["false_accepted_links"])
        self.assertIsNone(result["paired_differences"]["coverage"]["mean_difference"])

    def test_zero_accepted_links_is_not_perfect_precision(self):
        rows = [["none-1", method, "adjudicated", "20", "4", "0", "0", "0", "4", ""]
                for method in ("baseline", "eacp")]
        result = pilot.evaluate_csv(csv_fixture(rows))
        self.assertIsNone(result["quality_totals"]["eacp"]["false_fraction_of_accepted_links"])
        self.assertEqual(result["quality_totals"]["eacp"]["pooled_coverage"], 0)

    def test_missing_duplicate_or_unpaired_cases_rejected(self):
        rows = list(csv.reader(io.StringIO(csv_fixture())))[1:]
        for changed in (rows[:1], rows + rows[:1], [rows[0], ["other", *rows[1][1:]]]):
            with self.subTest(rows=changed), self.assertRaises(ValueError):
                pilot.evaluate_csv(csv_fixture(changed))

    def test_truth_scopes_and_partial_costs_rejected(self):
        rows = list(csv.reader(io.StringIO(csv_fixture())))[1:]
        for index, value in ((4, "8"), (2, "unknown"), (9, "")):
            changed = [row[:] for row in rows]
            changed[1][index] = value
            with self.subTest(index=index), self.assertRaises(ValueError):
                pilot.evaluate_csv(csv_fixture(changed))

    def test_unknown_truth_cannot_report_zero_error_as_fact(self):
        rows = [["unknown-1", method, "unknown", "20", "", "", "", "0", "3", ""]
                for method in ("baseline", "eacp")]
        with self.assertRaises(ValueError):
            pilot.evaluate_csv(csv_fixture(rows))

    def test_nonfinite_negative_fractional_count_and_false_denominator_rejected(self):
        rows = list(csv.reader(io.StringIO(csv_fixture())))[1:]
        for index, value in ((3, "NaN"), (3, "inf"), (3, "-1"), (3, "1e3"),
                             (5, "1.1"), (5, "0.7"), (6, "1.5"), (6, "true"),
                             (4, "0"), (6, "5"), (8, "-2")):
            changed = [row[:] for row in rows]
            changed[0][index] = value
            with self.subTest(index=index, value=value), self.assertRaises(ValueError):
                pilot.evaluate_csv(csv_fixture(changed))

    def test_headers_and_actual_input_are_required(self):
        for text in ("", ",".join(HEADERS) + "\n", "case_id,case_id\nx,x\n",
                     csv_fixture().replace("method", "undocumented", 1)):
            with self.subTest(text=text), self.assertRaises(ValueError):
                pilot.evaluate_csv(text)

    def test_cli_does_not_overwrite_existing_assessment(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, output = root / "fixture.csv", root / "existing.json"
            source.write_text(csv_fixture())
            output.write_text("retained assessment")
            with mock.patch("sys.stderr", new_callable=io.StringIO):
                self.assertEqual(pilot.main(["--input", str(source), "--output", str(output)]), 2)
            self.assertEqual(output.read_text(), "retained assessment")


class ReproductionRunnerTests(unittest.TestCase):
    def test_fixed_plan_is_small_and_never_calls_the_runner(self):
        plan = reproduction.build_plan(Path("/unused/reproduction-fixture"))
        reproduction.verify_plan(plan)
        self.assertEqual(len(plan), 8)
        self.assertTrue(all(step["command"][0] == sys.executable for step in plan))
        for step in plan:
            self.assertNotIn("scripts/reproduce_hardening_v1_4.py", step["command"][1:])
        correlation = next(step for step in plan if step["name"] == "correlation_smoke")
        self.assertIn("24", correlation["command"])

    def test_dry_run_and_plan_verification_never_execute_or_create_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "new-output"
            for mode in ("--dry-run", "--verify-plan"):
                with mock.patch.object(reproduction, "execute_step") as execute, mock.patch(
                    "sys.stdout", new_callable=io.StringIO
                ) as stdout:
                    self.assertEqual(reproduction.main(["--output", str(target), mode]), 0)
                    self.assertEqual(json.loads(stdout.getvalue())["status"], "plan_validated_not_executed")
                    execute.assert_not_called()
                    self.assertFalse(target.exists())

    def test_existing_output_is_rejected_before_source_capture(self):
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
            reproduction, "source_state"
        ) as capture, mock.patch("sys.stderr", new_callable=io.StringIO):
            self.assertEqual(reproduction.main(["--output", temporary]), 2)
            capture.assert_not_called()

    def test_failed_child_retains_stdout_stderr_and_returncode(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            step = {"name": "tiny_failure", "command": [sys.executable, "-c",
                    "import sys; print('fixture stdout'); print('fixture stderr', file=sys.stderr); sys.exit(7)"]}
            result = reproduction.execute_step(step, root=root, output=root, timeout_seconds=5)
            self.assertEqual(result["status"], "failed")
            self.assertEqual(result["returncode"], 7)
            self.assertIn("fixture stdout", (root / result["stdout"]).read_text())
            self.assertIn("fixture stderr", (root / result["stderr"]).read_text())

    def test_timeout_retains_partial_logs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            step = {"name": "tiny_timeout", "command": [sys.executable, "-c",
                    "import time; print('before timeout', flush=True); time.sleep(10)"]}
            result = reproduction.execute_step(step, root=root, output=root, timeout_seconds=0.3)
            self.assertEqual(result["status"], "timed_out")
            self.assertIn("before timeout", (root / result["stdout"]).read_text())

    def test_ambient_secrets_are_not_forwarded(self):
        with mock.patch.dict(os.environ, {"EACP_ACCESS_TOKEN": "fixture-secret", "GH_TOKEN": "fixture-secret",
                                          "EACP_STORAGE_KEY_HEX": "fixture-secret"}):
            child = reproduction._child_environment()
        self.assertNotIn("EACP_ACCESS_TOKEN", child)
        self.assertNotIn("GH_TOKEN", child)
        self.assertNotIn("EACP_STORAGE_KEY_HEX", child)
        self.assertEqual(child["PYTHONDONTWRITEBYTECODE"], "1")

    def test_actual_tiny_plan_continues_after_failure_and_keeps_self_run_label(self):
        # This replaces the full plan with three tiny processes: no recursive suite.
        tiny = [{"name": name, "command": [sys.executable, "-c", f"raise SystemExit({code})"]}
                for name, code in (("first", 0), ("second", 3), ("third", 0))]
        source = {"source_tree_sha256": "a" * 64, "commit": "b" * 40}
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "fresh"
            with mock.patch.object(reproduction, "build_plan", return_value=tiny), mock.patch.object(
                reproduction, "verify_plan"
            ), mock.patch.object(reproduction, "source_state", return_value=source), mock.patch(
                "sys.stdout", new_callable=io.StringIO
            ):
                self.assertEqual(reproduction.main(["--output", str(target)]), 1)
            result = json.loads((target / "summary.json").read_text())
            self.assertEqual([step["status"] for step in result["steps"]], ["passed", "failed", "passed"])
            self.assertEqual(result["classification"], "executor_self_run")
            self.assertIs(result["independently_reproduced"], False)

    def test_source_hash_includes_dirty_file_but_excludes_own_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "source.py").write_text("fixture source")
            output = root / "output"
            output.mkdir()
            (output / "result.json").write_text("fixture result")
            def git(_root, *args):
                if args[0] == "ls-files":
                    return "source.py\0output/result.json\0"
                if args[0] == "status":
                    return " M source.py"
                return "a" * 40
            with mock.patch.object(reproduction, "_git", side_effect=git):
                state = reproduction.source_state(root, output.resolve())
            self.assertEqual(set(state["files"]), {"source.py"})
            self.assertTrue(state["dirty"])

    def test_pilot_template_is_unstarted_and_unapproved(self):
        protocol = json.loads((ROOT / "docs/v1.4/PILOT_PROTOCOL.json").read_text())
        self.assertEqual(protocol["status"], "not_started")
        self.assertFalse(protocol["execution_record"]["actual_observations"])
        self.assertTrue(protocol["observation_only"])
        self.assertTrue(all(gate["approved"] is False for gate in protocol["approvals"].values()))
        self.assertEqual(protocol["sources"], [])


if __name__ == "__main__":
    unittest.main()
