from __future__ import annotations

import copy
import io
import json
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
MODULE_ROOT = HERE.parent
sys.path.insert(0, str(MODULE_ROOT))

import summarize_cross_version_run_set as cohort  # noqa: E402
import capture_run_outcome_v1_3 as outcome_capture  # noqa: E402


TARGET_MANIFEST = MODULE_ROOT / "kubernetes_targets_v1.3.json"
PROTOCOL_COMMIT = "a" * 40
VERSION = "v1.34.8"
TAG = f"eacp-v1.3-evidence/k8s-{VERSION}/run-01"
RUN_ID = 123456789


def write_tar(path: Path, members: list[tuple[str, bytes, bytes | None]]) -> None:
    with tarfile.open(path, "w:gz") as archive:
        for name, content, member_type in members:
            info = tarfile.TarInfo(name)
            if member_type is not None:
                info.type = member_type
            if info.isreg():
                info.size = len(content)
                archive.addfile(info, io.BytesIO(content))
            else:
                info.linkname = "target"
                archive.addfile(info)


def verification_fixture() -> tuple[dict, dict, list[dict]]:
    source_ref = f"refs/tags/{TAG}"
    signer = f"{cohort.REPOSITORY_URL}/{cohort.WORKFLOW_PATH}@{source_ref}"
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": "artifact.tar.gz", "digest": {"sha256": "b" * 64}}],
        "predicateType": cohort.PREDICATE_TYPE,
        "predicate": {
            "buildDefinition": {
                "buildType": "https://actions.github.io/buildtypes/workflow/v1",
                "externalParameters": {
                    "workflow": {
                        "path": cohort.WORKFLOW_PATH,
                        "ref": source_ref,
                        "repository": cohort.REPOSITORY_URL,
                    }
                },
                "internalParameters": {
                    "github": {
                        "event_name": "push",
                        "runner_environment": "github-hosted",
                    }
                },
                "resolvedDependencies": [
                    {
                        "uri": f"git+{cohort.REPOSITORY_URL}@{source_ref}",
                        "digest": {"gitCommit": PROTOCOL_COMMIT},
                    }
                ],
            },
            "runDetails": {
                "builder": {"id": signer},
                "metadata": {
                    "invocationId": (
                        f"{cohort.REPOSITORY_URL}/actions/runs/{RUN_ID}/attempts/1"
                    )
                },
            },
        },
    }
    bundle = {
        "mediaType": cohort.SIGSTORE_BUNDLE_MEDIA_TYPE,
        "verificationMaterial": {
            "certificate": {"rawBytes": "certificate"},
            "tlogEntries": [{"logIndex": "1"}],
        },
        "dsseEnvelope": {
            "payload": "unused-by-direct-validator",
            "payloadType": "application/vnd.in-toto+json",
            "signatures": [{"sig": "signature"}],
        },
    }
    verification = [
        {
            "attestation": {"bundle": bundle},
            "verificationResult": {
                "mediaType": cohort.VERIFICATION_RESULT_MEDIA_TYPE,
                "signature": {
                    "certificate": cohort.expected_identity(
                        protocol_commit=PROTOCOL_COMMIT, tag=TAG, run_id=RUN_ID
                    )
                },
                "verifiedTimestamps": [
                    {
                        "type": "Tlog",
                        "uri": "https://rekor.sigstore.dev",
                        "timestamp": "2026-09-02T20:56:01-04:00",
                    }
                ],
                "verifiedIdentity": {"runnerEnvironment": "github-hosted"},
                "statement": statement,
            },
        }
    ]
    return bundle, statement, verification


class AttestedArchiveTests(unittest.TestCase):
    def test_safe_tar_is_materialized_and_matches_exact_sibling_inventory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sibling = root / "results"
            (sibling / "nested").mkdir(parents=True)
            (sibling / "one.txt").write_bytes(b"one")
            (sibling / "nested/two.txt").write_bytes(b"two")
            archive = root / "evidence.tar.gz"
            write_tar(
                archive,
                [
                    ("./one.txt", b"one", None),
                    ("./nested/two.txt", b"two", None),
                ],
            )
            with cohort.validated_archive_tree(archive, sibling) as extracted:
                self.assertEqual((extracted / "one.txt").read_bytes(), b"one")
                self.assertEqual((extracted / "nested/two.txt").read_bytes(), b"two")

    def test_tar_and_sibling_content_mismatch_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sibling = root / "results"
            sibling.mkdir()
            (sibling / "one.txt").write_bytes(b"tree")
            archive = root / "evidence.tar.gz"
            write_tar(archive, [("./one.txt", b"tar", None)])
            with self.assertRaisesRegex(cohort.CohortError, "sibling results tree differ"):
                with cohort.validated_archive_tree(archive, sibling):
                    pass

    def test_traversal_and_links_are_rejected_without_extraction(self):
        for name, member_type in (("../escape", None), ("link", tarfile.SYMTYPE)):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                sibling = root / "results"
                sibling.mkdir()
                (sibling / "one.txt").write_bytes(b"one")
                archive = root / "evidence.tar.gz"
                write_tar(archive, [(name, b"one", member_type)])
                with self.assertRaises(cohort.CohortError):
                    with cohort.validated_archive_tree(archive, sibling):
                        pass


class AttestationVerificationTests(unittest.TestCase):
    def test_exact_capture_time_verification_result_is_accepted(self):
        bundle, statement, verification = verification_fixture()
        self.assertEqual(
            cohort.validate_verification_value(
                verification,
                sigstore_bundle=bundle,
                statement=statement,
                protocol_commit=PROTOCOL_COMMIT,
                tag=TAG,
                run_id=RUN_ID,
            ),
            1,
        )

    def test_identity_timestamp_statement_and_runner_tampering_are_rejected(self):
        bundle, statement, baseline = verification_fixture()
        cases = []
        wrong_digest = copy.deepcopy(baseline)
        wrong_digest[0]["verificationResult"]["signature"]["certificate"][
            "sourceRepositoryDigest"
        ] = "c" * 40
        cases.append(wrong_digest)
        no_timestamp = copy.deepcopy(baseline)
        no_timestamp[0]["verificationResult"]["verifiedTimestamps"] = []
        cases.append(no_timestamp)
        wrong_statement = copy.deepcopy(baseline)
        wrong_statement[0]["verificationResult"]["statement"]["subject"] = []
        cases.append(wrong_statement)
        self_hosted = copy.deepcopy(baseline)
        self_hosted[0]["verificationResult"]["verifiedIdentity"][
            "runnerEnvironment"
        ] = "self-hosted"
        cases.append(self_hosted)
        for value in cases:
            with self.subTest(value=value), self.assertRaises(cohort.CohortError):
                cohort.validate_verification_value(
                    value,
                    sigstore_bundle=bundle,
                    statement=statement,
                    protocol_commit=PROTOCOL_COMMIT,
                    tag=TAG,
                    run_id=RUN_ID,
                )

    def test_fresh_verification_uses_captured_trusted_root_and_exact_policy(self):
        bundle, statement, verification = verification_fixture()
        completed = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=json.dumps(verification), stderr=""
        )
        with tempfile.TemporaryDirectory() as temporary, patch.object(
            cohort.subprocess, "run", return_value=completed
        ) as run:
            root = Path(temporary)
            archive = root / "artifact.tar.gz"
            bundle_path = root / "bundle.jsonl"
            trusted_root = root / "trusted_root.jsonl"
            cohort.reverify_attestation(
                archive,
                bundle_path,
                trusted_root,
                sigstore_bundle=bundle,
                statement=statement,
                protocol_commit=PROTOCOL_COMMIT,
                tag=TAG,
                run_id=RUN_ID,
            )
        command = run.call_args.args[0]
        self.assertEqual(command[command.index("--custom-trusted-root") + 1], str(trusted_root))
        self.assertEqual(command[command.index("--source-ref") + 1], f"refs/tags/{TAG}")
        self.assertIn("--deny-self-hosted-runners", command)


class BalancedCohortTests(unittest.TestCase):
    def rows(self) -> list[dict]:
        versions = ["v1.34.8", "v1.35.5", "v1.36.1"]
        return [
            {
                "kubernetes_version": version,
                "evidence_tag": f"eacp-v1.3-evidence/k8s-{version}/run-{repeat:02d}",
                "run_id": 1000 + index,
                "run_url": f"{cohort.REPOSITORY_URL}/actions/runs/{1000 + index}",
            }
            for index, (repeat, version) in enumerate(
                (repeat, version)
                for repeat in range(1, 4)
                for version in versions
            )
        ]

    def test_exact_nine_run_design_aggregates_three_per_version(self):
        rows = self.rows()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "run_set.json").write_text(
                json.dumps(
                    {
                        "schema_version": "eacp.cross-version-run-set/1.3.0",
                        "protocol_commit": PROTOCOL_COMMIT,
                        "runs": rows,
                    }
                ),
                encoding="utf-8",
            )

            def fake_verify(_root, row, protocol_commit, _targets, **_kwargs):
                return {
                    "kubernetes_version": row["kubernetes_version"],
                    "run_id": row["run_id"],
                    "correlation_id": f"correlation-{row['run_id']}",
                    "head_sha": protocol_commit,
                    "conclusion": "success",
                }

            with patch.object(cohort, "verify_cohort_member", side_effect=fake_verify):
                summary = cohort.summarize(root, TARGET_MANIFEST)
        self.assertEqual(summary["aggregate"]["preserved_first_attempt_outcomes"], 9)
        self.assertEqual(
            {
                key: value["first_attempt_outcomes"]
                for key, value in summary["per_version"].items()
            },
            {"v1.34.8": 3, "v1.35.5": 3, "v1.36.1": 3},
        )

    def test_unbalanced_nine_row_design_is_rejected(self):
        rows = self.rows()
        rows[-1] = dict(rows[0], run_id=9999)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "run_set.json").write_text(
                json.dumps(
                    {
                        "schema_version": "eacp.cross-version-run-set/1.3.0",
                        "protocol_commit": PROTOCOL_COMMIT,
                        "runs": rows,
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(cohort.CohortError, "balanced 3-by-3"):
                cohort.summarize(root, TARGET_MANIFEST)

    def test_frozen_pre_job_failure_is_preserved_without_full_evidence(self):
        run_id = 778899
        row = {
            "kubernetes_version": VERSION,
            "evidence_tag": TAG,
            "run_id": run_id,
            "run_url": f"{cohort.REPOSITORY_URL}/actions/runs/{run_id}",
        }
        source = {
            "attempt": 1,
            "conclusion": "startup_failure",
            "event": "push",
            "headBranch": TAG,
            "headSha": PROTOCOL_COMMIT,
            "status": "completed",
            "url": row["run_url"],
            "workflowName": "EACP cross-plane v1.3",
            "jobs": [],
        }
        metadata, outcome = outcome_capture.build_outcome(
            source,
            repository=cohort.REPOSITORY,
            run_id=run_id,
            protocol_commit=PROTOCOL_COMMIT,
            captured_at="2026-09-02T22:00:00Z",
            acquisition="saved-test-input",
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            outcome_capture.write_outcome(root / f"run-{run_id}", metadata, outcome)
            result = cohort.verify_cohort_member(
                root,
                row,
                PROTOCOL_COMMIT,
                cohort.load_manifest(TARGET_MANIFEST)["targets"],
            )
        self.assertEqual(result["conclusion"], "startup_failure")
        self.assertEqual(result["criteria_status"], "not_satisfied")
        self.assertFalse(result["full_evidence_verified"])
        self.assertIsNone(result["job_conclusion"])

    def test_mixed_outcomes_are_reported_as_partial(self):
        rows = self.rows()
        failed_run = rows[0]["run_id"]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "run_set.json").write_text(
                json.dumps(
                    {
                        "schema_version": "eacp.cross-version-run-set/1.3.0",
                        "protocol_commit": PROTOCOL_COMMIT,
                        "runs": rows,
                    }
                ),
                encoding="utf-8",
            )

            def fake_verify(_root, row, protocol_commit, _targets, **_kwargs):
                if row["run_id"] == failed_run:
                    return {
                        "kubernetes_version": row["kubernetes_version"],
                        "run_id": row["run_id"],
                        "head_sha": protocol_commit,
                        "conclusion": "failure",
                    }
                return {
                    "kubernetes_version": row["kubernetes_version"],
                    "run_id": row["run_id"],
                    "correlation_id": f"correlation-{row['run_id']}",
                    "head_sha": protocol_commit,
                    "conclusion": "success",
                }

            with patch.object(cohort, "verify_cohort_member", side_effect=fake_verify):
                summary = cohort.summarize(root, TARGET_MANIFEST)
        self.assertEqual(summary["overall_status"], "partial")
        self.assertEqual(summary["aggregate"]["successful_full_evidence_runs"], 8)
        self.assertEqual(summary["aggregate"]["non_successful_first_attempt_runs"], 1)


if __name__ == "__main__":
    unittest.main()
