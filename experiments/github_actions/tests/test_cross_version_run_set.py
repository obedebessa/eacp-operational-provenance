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
import capture_tag_invocation_v1_3 as invocation_capture  # noqa: E402


TARGET_MANIFEST = MODULE_ROOT / "kubernetes_targets_v1.3.json"
PROTOCOL_COMMIT = "a" * 40
VERSION = "v1.34.8"
TAG = f"eacp-v1.3-evidence/k8s-{VERSION}/run-01"
RUN_ID = 123456789


def invocation_observation(run_id: int, tag: str, conclusion: str) -> dict:
    repository = cohort.REPOSITORY
    name = f"EACP cross-plane v1.3 / {tag} / ref-selected"
    source = {
        "total_count": 1,
        "workflow_runs": [
            {
                "id": run_id,
                "workflow_id": 348771431,
                "run_number": 18,
                "run_attempt": 1,
                "event": "push",
                "head_branch": tag,
                "head_sha": PROTOCOL_COMMIT,
                "path": cohort.WORKFLOW_PATH,
                "status": "completed",
                "conclusion": conclusion,
                "html_url": f"{cohort.REPOSITORY_URL}/actions/runs/{run_id}",
                "url": f"https://api.github.com/repos/{repository}/actions/runs/{run_id}",
                "name": name,
                "display_title": name,
                "previous_attempt_url": None,
                "pull_requests": [],
                "referenced_workflows": [],
                "repository": {"full_name": repository, "private": False},
                "head_repository": {"full_name": repository, "private": False},
                "head_commit": {
                    "id": PROTOCOL_COMMIT,
                    "timestamp": "2026-09-02T21:59:00Z",
                },
                "created_at": "2026-09-02T22:00:00Z",
                "run_started_at": "2026-09-02T22:00:00Z",
                "updated_at": "2026-09-02T22:01:00Z",
            }
        ],
    }
    return invocation_capture.build_observation(
        source,
        repository=repository,
        evidence_tag=tag,
        run_id=run_id,
        protocol_commit=PROTOCOL_COMMIT,
        conclusion=conclusion,
        captured_at="2026-09-02T22:02:00Z",
        acquisition="saved-test-input",
    )


def failed_log_observation(run_id: int, tag: str, conclusion: str) -> dict:
    return outcome_capture.build_failed_log_observation(
        b"",
        repository=cohort.REPOSITORY,
        run_id=run_id,
        protocol_commit=PROTOCOL_COMMIT,
        evidence_tag=tag,
        conclusion=conclusion,
        captured_at="2026-09-02T22:02:00Z",
        acquisition="saved-test-log",
        gh_version="gh version test",
    )


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
        self.assertEqual(command[command.index("--hostname") + 1], "github.com")
        self.assertEqual(command[command.index("--signer-digest") + 1], PROTOCOL_COMMIT)
        self.assertEqual(command[command.index("--predicate-type") + 1], cohort.PREDICATE_TYPE)
        self.assertIn("--deny-self-hosted-runners", command)

    def test_captured_root_policy_records_default_trust_bootstrap_and_scope(self):
        with tempfile.TemporaryDirectory() as temporary:
            run_root = Path(temporary) / "run-123"
            attestation = run_root / "attestation"
            attestation.mkdir(parents=True)
            trusted_root = attestation / "trusted_root.jsonl"
            trusted_root.write_text(
                json.dumps(
                    {
                        "mediaType": (
                            "application/vnd.dev.sigstore.trustedroot+json;version=0.1"
                        )
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            policy = {
                "schema_version": "eacp.attestation-verification-policy/1.3.1",
                "repository": cohort.REPOSITORY,
                "signer_workflow": cohort.SIGNER_WORKFLOW,
                "signer_digest": PROTOCOL_COMMIT,
                "source_digest": PROTOCOL_COMMIT,
                "source_ref": f"refs/tags/{TAG}",
                "predicate_type": cohort.PREDICATE_TYPE,
                "deny_self_hosted_runners": True,
                "bundle_on_disk": True,
                "capture_time_default_trust_verification": True,
                "capture_time_captured_root_verification": True,
                "custom_trusted_root_on_disk": True,
                "trusted_root_sha256": cohort.sha256(trusted_root),
                "gh_cli_version": "gh version 2.97.0",
                "attested_scope": "in_run_tar_archive_only",
                "completed_finalization_builder_attested": False,
                "trust_bootstrap_boundary": (
                    "The captured root authenticity is not self-proving; capture also uses "
                    "the default trust configuration."
                ),
            }
            policy_path = attestation / "verification-policy.json"
            policy_path.write_text(json.dumps(policy), encoding="utf-8")
            self.assertEqual(
                cohort.validate_attestation_policy(run_root, PROTOCOL_COMMIT, TAG),
                trusted_root,
            )
            policy["completed_finalization_builder_attested"] = True
            policy_path.write_text(json.dumps(policy), encoding="utf-8")
            with self.assertRaises(cohort.CohortError):
                cohort.validate_attestation_policy(run_root, PROTOCOL_COMMIT, TAG)


class BalancedCohortTests(unittest.TestCase):
    def rows(self, tag_run_indices=(1, 2, 3)) -> list[dict]:
        versions = ["v1.34.8", "v1.35.5", "v1.36.1"]
        return [
            {
                "kubernetes_version": version,
                "evidence_tag": f"eacp-v1.3-evidence/k8s-{version}/run-{run_index:02d}",
                "run_id": 1000 + index,
                "run_url": f"{cohort.REPOSITORY_URL}/actions/runs/{1000 + index}",
            }
            for index, (run_index, version) in enumerate(
                (run_index, version)
                for run_index in tag_run_indices
                for version in versions
            )
        ]

    def test_both_exact_nine_run_generations_aggregate_three_per_version(self):
        for tag_run_indices in ((1, 2, 3), (4, 5, 6)):
            with self.subTest(tag_run_indices=tag_run_indices):
                rows = self.rows(tag_run_indices)
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    (root / "run_set.json").write_text(
                        json.dumps(
                            {
                                "schema_version": "eacp.cross-version-run-set/1.3.0",
                                "protocol_commit": PROTOCOL_COMMIT,
                                "tag_run_indices": list(tag_run_indices),
                                "runs": rows,
                            }
                        ),
                        encoding="utf-8",
                    )

                    def fake_verify(_root, row, protocol_commit, _targets, **kwargs):
                        self.assertEqual(tuple(kwargs["tag_run_indices"]), tag_run_indices)
                        return {
                            "kubernetes_version": row["kubernetes_version"],
                            "run_index": int(row["evidence_tag"].rsplit("-", 1)[1]),
                            "evidence_tag": row["evidence_tag"],
                            "run_id": row["run_id"],
                            "correlation_id": f"correlation-{row['run_id']}",
                            "head_sha": protocol_commit,
                            "conclusion": "success",
                            "sole_exact_tag_invocation_at_capture": True,
                        }

                    with patch.object(
                        cohort, "verify_cohort_member", side_effect=fake_verify
                    ):
                        summary = cohort.summarize(root, TARGET_MANIFEST)
                self.assertEqual(summary["tag_run_indices"], list(tag_run_indices))
                self.assertEqual(
                    summary["aggregate"]["preserved_first_attempt_outcomes"], 9
                )
                self.assertEqual(
                    {
                        key: value["first_attempt_outcomes"]
                        for key, value in summary["per_version"].items()
                    },
                    {"v1.34.8": 3, "v1.35.5": 3, "v1.36.1": 3},
                )
                for value in summary["per_version"].values():
                    self.assertEqual(value["run_indices"], list(tag_run_indices))
                    self.assertEqual(
                        [int(tag.rsplit("-", 1)[1]) for tag in value["evidence_tags"]],
                        list(tag_run_indices),
                    )

    def test_missing_or_invalid_tag_run_indices_are_rejected(self):
        cases = [None, [1, 2], [1, 2, 4], [1, 2, 3, 4], [3, 2, 1], [True, 2, 3], "1,2,3"]
        for tag_run_indices in cases:
            with self.subTest(tag_run_indices=tag_run_indices), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                run_set = {
                    "schema_version": "eacp.cross-version-run-set/1.3.0",
                    "protocol_commit": PROTOCOL_COMMIT,
                    "runs": self.rows(),
                }
                if tag_run_indices is not None:
                    run_set["tag_run_indices"] = tag_run_indices
                (root / "run_set.json").write_text(json.dumps(run_set), encoding="utf-8")
                with self.assertRaisesRegex(cohort.CohortError, "tag_run_indices"):
                    cohort.summarize(root, TARGET_MANIFEST)

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
                        "tag_run_indices": [1, 2, 3],
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
            "workflowName": ".github/workflows/eacp-cross-plane-v1.3.yml",
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
            outcome_capture.write_outcome(
                root / f"run-{run_id}",
                metadata,
                outcome,
                invocation_observation(run_id, TAG, "startup_failure"),
                failed_log_observation(run_id, TAG, "startup_failure"),
            )
            result = cohort.verify_cohort_member(
                root,
                row,
                PROTOCOL_COMMIT,
                cohort.load_manifest(TARGET_MANIFEST)["targets"],
                tag_run_indices=[1, 2, 3],
            )
        self.assertEqual(result["conclusion"], "startup_failure")
        self.assertEqual(result["criteria_status"], "not_satisfied")
        self.assertFalse(result["all_predeclared_criteria_validated"])
        self.assertTrue(result["sole_exact_tag_invocation_at_capture"])
        self.assertFalse(result["completed_finalization_builder_attested"])
        self.assertIsNone(result["job_conclusion"])
        self.assertEqual(result["run_index"], 1)
        self.assertEqual(result["evidence_tag"], TAG)

    def test_corrective_failure_preserves_run_index_and_tag_identity(self):
        run_id = 778900
        tag = f"eacp-v1.3-evidence/k8s-{VERSION}/run-04"
        row = {
            "kubernetes_version": VERSION,
            "evidence_tag": tag,
            "run_id": run_id,
            "run_url": f"{cohort.REPOSITORY_URL}/actions/runs/{run_id}",
        }
        source = {
            "attempt": 1,
            "conclusion": "startup_failure",
            "event": "push",
            "headBranch": tag,
            "headSha": PROTOCOL_COMMIT,
            "status": "completed",
            "url": row["run_url"],
            "workflowName": ".github/workflows/eacp-cross-plane-v1.3.yml",
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
            outcome_capture.write_outcome(
                root / f"run-{run_id}",
                metadata,
                outcome,
                invocation_observation(run_id, tag, "startup_failure"),
                failed_log_observation(run_id, tag, "startup_failure"),
            )
            result = cohort.verify_cohort_member(
                root,
                row,
                PROTOCOL_COMMIT,
                cohort.load_manifest(TARGET_MANIFEST)["targets"],
                tag_run_indices=[4, 5, 6],
            )
        self.assertEqual(result["conclusion"], "startup_failure")
        self.assertEqual(result["run_index"], 4)
        self.assertEqual(result["evidence_tag"], tag)

    def test_declared_generation_must_match_every_tag_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "run_set.json").write_text(
                json.dumps(
                    {
                        "schema_version": "eacp.cross-version-run-set/1.3.0",
                        "protocol_commit": PROTOCOL_COMMIT,
                        "tag_run_indices": [4, 5, 6],
                        "runs": self.rows((1, 2, 3)),
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(cohort.CohortError, "balanced 3-by-3"):
                cohort.summarize(root, TARGET_MANIFEST)

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
                        "tag_run_indices": [1, 2, 3],
                        "runs": rows,
                    }
                ),
                encoding="utf-8",
            )

            def fake_verify(_root, row, protocol_commit, _targets, **_kwargs):
                if row["run_id"] == failed_run:
                    return {
                        "kubernetes_version": row["kubernetes_version"],
                        "run_index": int(row["evidence_tag"].rsplit("-", 1)[1]),
                        "evidence_tag": row["evidence_tag"],
                        "run_id": row["run_id"],
                        "head_sha": protocol_commit,
                        "conclusion": "failure",
                        "sole_exact_tag_invocation_at_capture": True,
                    }
                return {
                    "kubernetes_version": row["kubernetes_version"],
                    "run_index": int(row["evidence_tag"].rsplit("-", 1)[1]),
                    "evidence_tag": row["evidence_tag"],
                    "run_id": row["run_id"],
                    "correlation_id": f"correlation-{row['run_id']}",
                    "head_sha": protocol_commit,
                    "conclusion": "success",
                    "sole_exact_tag_invocation_at_capture": True,
                }

            with patch.object(cohort, "verify_cohort_member", side_effect=fake_verify):
                summary = cohort.summarize(root, TARGET_MANIFEST)
        self.assertEqual(summary["overall_status"], "partial")
        self.assertEqual(
            summary["aggregate"]["successful_runs_satisfying_all_predeclared_criteria"],
            8,
        )
        self.assertEqual(summary["aggregate"]["non_successful_first_attempt_runs"], 1)


if __name__ == "__main__":
    unittest.main()
