from __future__ import annotations

import csv
import json
import sys
import tempfile
import unittest
import zipfile
from argparse import Namespace
from pathlib import Path


HERE = Path(__file__).resolve().parent
MODULE_ROOT = HERE.parent
FIXTURES = HERE / "fixtures"
sys.path.insert(0, str(MODULE_ROOT))

import eacp_gha_v1_3 as adapter  # noqa: E402


class GitHubActionsAdapterTests(unittest.TestCase):
    def raw_inputs(self):
        run = json.loads((FIXTURES / "run.json").read_text(encoding="utf-8"))
        jobs = json.loads((FIXTURES / "jobs.json").read_text(encoding="utf-8"))["jobs"]
        artifacts = json.loads((FIXTURES / "artifacts.json").read_text(encoding="utf-8"))["artifacts"]
        return run, jobs, artifacts

    def snapshot(self, **overrides):
        run, jobs, artifacts = self.raw_inputs()
        options = {
            "captured_at": "2026-01-02T04:00:00Z",
            "acquisition": "imported-api-json",
            "transport": "offline-import",
            "authenticated": None,
            "service": "fixture/service",
            "correlation_id": None,
            "deployment": "fixture-deployment",
            "namespace": "fixture-namespace",
        }
        options.update(overrides)
        return adapter.build_source_snapshot(run, jobs, artifacts, **options)

    def test_minimization_and_deterministic_correlation(self):
        snapshot = self.snapshot()
        rendered = adapter.canonical_json(snapshot)
        self.assertEqual(
            snapshot["projection"]["correlation_id"],
            "eacp-gha-424242-987654321-2",
        )
        self.assertNotIn("fixture-secret@example.invalid", rendered)
        self.assertNotIn("private-runner-name", rendered)
        self.assertNotIn("temporary_token", rendered)
        self.assertNotIn("must-not-survive", rendered)
        self.assertEqual(
            snapshot["artifacts"][0]["archive_download_url"],
            "https://api.github.com/repos/example/eacp-fixture/actions/artifacts/88001/zip",
        )
        self.assertEqual([job["id"] for job in snapshot["jobs"]], [7001, 7002])

    def test_bundle_round_trip_projection_and_checksums(self):
        with tempfile.TemporaryDirectory() as temporary:
            bundle = Path(temporary) / "bundle"
            summary = adapter.write_bundle(self.snapshot(), bundle)
            result = adapter.validate_bundle(bundle)
            self.assertTrue(result["valid"])
            self.assertEqual(result["evidence_rows"], 4)
            self.assertEqual(summary["source_classification"], "imported_api_metadata_authenticity_not_established_by_adapter")
            rows = adapter.read_csv_rows(bundle / "eacp/evidence.csv")
            self.assertEqual(
                [row["source_type"] for row in rows],
                [
                    "github.actions.run",
                    "github.actions.job",
                    "github.actions.job",
                    "github.actions.artifact",
                ],
            )
            self.assertEqual(len({row["content_hash"] for row in rows}), 4)
            patch = json.loads(
                (bundle / "kubernetes/annotation_merge_patch.json").read_text(encoding="utf-8")
            )
            self.assertEqual(
                patch["metadata"]["annotations"][adapter.ANNOTATION_KEY],
                "eacp-gha-424242-987654321-2",
            )

    def test_checksum_tampering_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            bundle = Path(temporary) / "bundle"
            adapter.write_bundle(self.snapshot(), bundle)
            with (bundle / "summary.json").open("a", encoding="utf-8") as handle:
                handle.write(" ")
            with self.assertRaisesRegex(adapter.AdapterError, "checksum mismatch"):
                adapter.validate_bundle(bundle)

    def test_exact_cross_plane_csv_and_object_join(self):
        snapshot = self.snapshot()
        correlation_id = snapshot["projection"]["correlation_id"]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            csv_path = root / "kubernetes.csv"
            fieldnames = [
                "source_type",
                "source_id",
                "source_ts",
                "actor",
                "correlation_id",
                "source_pointer",
            ]
            with csv_path.open("w", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerow(
                    {
                        "source_type": "kubernetes.audit",
                        "source_id": "audit-1:ResponseComplete",
                        "source_ts": "2026-01-02T03:06:01Z",
                        "actor": "kubernetes-admin",
                        "correlation_id": correlation_id,
                        "source_pointer": "kubernetes-audit://audit-1",
                    }
                )
                writer.writerow(
                    {
                        "source_type": "kubernetes.audit",
                        "source_id": "audit-2:ResponseComplete",
                        "source_ts": "2026-01-02T03:06:02Z",
                        "actor": "kubernetes-admin",
                        "correlation_id": correlation_id + "-near-miss",
                        "source_pointer": "kubernetes-audit://audit-2",
                    }
                )
            object_path = root / "deployment.json"
            object_path.write_text(
                json.dumps(
                    {
                        "apiVersion": "apps/v1",
                        "kind": "Deployment",
                        "metadata": {
                            "name": "fixture-deployment",
                            "namespace": "fixture-namespace",
                            "annotations": {adapter.ANNOTATION_KEY: correlation_id},
                        },
                    }
                ),
                encoding="utf-8",
            )
            report = adapter.join_report(
                snapshot,
                kubernetes_csv=csv_path,
                kubernetes_object=object_path,
            )
            self.assertEqual(report["status"], "observed_cross_plane_link")
            self.assertEqual(report["kubernetes"]["kubernetes_source_rows_with_exact_id"], 1)
            self.assertTrue(report["kubernetes"]["object"]["exact_match"])

    def test_no_match_is_reported_without_inference(self):
        snapshot = self.snapshot()
        with tempfile.TemporaryDirectory() as temporary:
            object_path = Path(temporary) / "deployment.json"
            object_path.write_text(
                json.dumps(
                    {
                        "apiVersion": "apps/v1",
                        "kind": "Deployment",
                        "metadata": {
                            "name": "fixture-deployment",
                            "namespace": "fixture-namespace",
                            "annotations": {adapter.ANNOTATION_KEY: "different-id"},
                        },
                    }
                ),
                encoding="utf-8",
            )
            report = adapter.join_report(snapshot, kubernetes_csv=None, kubernetes_object=object_path)
            self.assertEqual(report["status"], "no_matching_kubernetes_evidence_observed")
            self.assertFalse(report["kubernetes"]["object"]["exact_match"])

    def test_subject_digest_principals_and_runtime_image_are_reported(self):
        digest = "sha256:" + "a" * 64
        subject_uri = "registry.example.invalid/team/service"
        snapshot = self.snapshot(subject_uri=subject_uri, subject_digest=digest)
        correlation_id = snapshot["projection"]["correlation_id"]
        expected_image = f"{subject_uri}@{digest}"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            csv_path = root / "kubernetes.csv"
            fieldnames = [
                "source_type",
                "source_id",
                "source_ts",
                "actor",
                "correlation_id",
                "source_pointer",
                "outcome",
            ]
            with csv_path.open("w", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerow(
                    {
                        "source_type": "kubernetes.audit",
                        "source_id": "audit-denied:ResponseComplete",
                        "source_ts": "2026-01-02T03:06:01Z",
                        "actor": "system:serviceaccount:fixture-namespace:eacp-observer",
                        "correlation_id": correlation_id,
                        "source_pointer": "kubernetes-audit://audit-denied",
                        "outcome": "403:Forbidden",
                    }
                )
            deployment_path = root / "deployment.json"
            deployment_path.write_text(
                json.dumps(
                    {
                        "apiVersion": "apps/v1",
                        "kind": "Deployment",
                        "metadata": {
                            "name": "fixture-deployment",
                            "namespace": "fixture-namespace",
                            "annotations": {
                                adapter.ANNOTATION_KEY: correlation_id,
                                "eacp.io/subject-uri": subject_uri,
                                "eacp.io/subject-digest": digest,
                            },
                        },
                        "spec": {
                            "template": {
                                "spec": {"containers": [{"name": "subject", "image": expected_image}]}
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )
            negative_path = root / "negative.json"
            negative_path.write_text(
                json.dumps(
                    {
                        "apiVersion": "v1",
                        "kind": "ConfigMap",
                        "metadata": {"name": "negative", "namespace": "fixture-namespace"},
                    }
                ),
                encoding="utf-8",
            )
            pods_path = root / "pods.json"
            pods_path.write_text(
                json.dumps(
                    {
                        "apiVersion": "v1",
                        "kind": "List",
                        "items": [
                            {
                                "metadata": {"annotations": {adapter.ANNOTATION_KEY: correlation_id}},
                                "spec": {"containers": [{"name": "subject", "image": expected_image}]},
                                "status": {
                                    "containerStatuses": [
                                        {"name": "subject", "imageID": f"registry.example.invalid/team/service@{digest}"}
                                    ]
                                },
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            audit_summary_path = root / "audit_summary.json"
            audit_summary_path.write_text(
                json.dumps(
                    {
                        "rbac_denial": {
                            "expected_target": {
                                "api_group": "apps",
                                "resource": "deployments",
                                "namespace": "fixture-namespace",
                                "name": "fixture-deployment",
                            },
                            "binding_method": "adapter_explicit_exact_target",
                            "source_native_correlation_required": False,
                            "source_native_correlation_records": 0,
                            "matching_http_403_records": 1,
                        }
                    }
                ),
                encoding="utf-8",
            )
            report = adapter.join_report(
                snapshot,
                kubernetes_csv=csv_path,
                kubernetes_object=deployment_path,
                negative_control_object=negative_path,
                kubernetes_pods=pods_path,
                kubernetes_audit_summary=audit_summary_path,
            )
            self.assertEqual(report["status"], "observed_cross_plane_link_with_subject_digest")
            self.assertEqual(report["kubernetes"]["rbac_denied_rows_in_projection"], 1)
            self.assertEqual(
                report["kubernetes"]["rbac_denial_binding"]["binding_method"],
                "adapter_explicit_exact_target",
            )
            self.assertTrue(report["kubernetes"]["negative_control"]["correlation_annotation_absent"])
            self.assertTrue(report["kubernetes"]["pods"]["pod_spec_subject_exact_match"])
            self.assertTrue(report["kubernetes"]["pods"]["runtime_image_id_exact_subject_digest_match"])

    def test_private_repository_requires_explicit_acknowledgement(self):
        snapshot = self.snapshot()
        snapshot["repository"]["private"] = True
        with self.assertRaisesRegex(adapter.AdapterError, "private"):
            adapter.private_capture_guard(snapshot, False)
        adapter.private_capture_guard(snapshot, True)

    def test_import_artifact_zip_rejects_path_traversal(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            malicious = root / "artifact.zip"
            with zipfile.ZipFile(malicious, "w") as archive:
                archive.writestr("../source/github_actions.json", "{}")
            with self.assertRaisesRegex(adapter.AdapterError, "unsafe path"):
                adapter.safe_extract_artifact(malicious, root / "extract")

    def test_nested_extracted_artifact_source_is_found(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "eacp-cross-plane-v1.3-results/github/source/github_actions.json"
            source.parent.mkdir(parents=True)
            source.write_text("{}", encoding="utf-8")
            self.assertEqual(adapter.safe_extract_artifact(root, root / "unused"), source)

    def test_annotation_defaults_to_non_mutating_plan(self):
        with tempfile.TemporaryDirectory() as temporary:
            bundle = Path(temporary) / "bundle"
            adapter.write_bundle(self.snapshot(), bundle)
            result = adapter.command_annotate(
                Namespace(
                    bundle=bundle,
                    deployment=None,
                    namespace=None,
                    context=None,
                    kubectl="kubectl",
                    apply=False,
                    snapshot_output=None,
                )
            )
            self.assertEqual(result["mode"], "plan")
            self.assertFalse(result["mutation_performed"])
            self.assertIn("--type=merge", result["argv"])

    def test_mismatched_job_run_is_rejected(self):
        run, jobs, artifacts = self.raw_inputs()
        jobs[0]["run_id"] += 1
        with self.assertRaisesRegex(adapter.AdapterError, "belongs to run"):
            adapter.build_source_snapshot(
                run,
                jobs,
                artifacts,
                captured_at="2026-01-02T04:00:00Z",
                acquisition="imported-api-json",
                transport="offline-import",
                authenticated=None,
                service=None,
                correlation_id=None,
                deployment="fixture-deployment",
                namespace="fixture-namespace",
            )


if __name__ == "__main__":
    unittest.main()
