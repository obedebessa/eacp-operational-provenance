from __future__ import annotations

import csv
import json
import sys
import tempfile
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import extract_kubernetes_audit_v1_3 as extractor  # noqa: E402


CORRELATION = "eacp-gha-424242-987654321-2"
NAMESPACE = "fixture-namespace"
DENIED = f"system:serviceaccount:{NAMESPACE}:eacp-observer"


def audit_record(
    audit_id: str,
    *,
    resource: str,
    name: str,
    verb: str,
    code: int,
    correlation: str | None,
    actor: str = "kubernetes-admin",
    impersonated: str | None = None,
    namespace: str = NAMESPACE,
) -> dict:
    annotations = {}
    if correlation is not None:
        annotations = {
            "eacp.io/correlation-id": correlation,
            "eacp.io/github-repository-id": "424242",
            "eacp.io/github-run-id": "987654321",
            "eacp.io/github-run-attempt": "2",
            "eacp.io/github-commit-sha": "0123456789abcdef0123456789abcdef01234567",
            "eacp.io/subject-uri": "registry.example.invalid/team/service",
            "eacp.io/subject-digest": "sha256:" + "a" * 64,
        }
    value = {
        "kind": "Event",
        "apiVersion": "audit.k8s.io/v1",
        "auditID": audit_id,
        "stage": "ResponseComplete",
        "requestReceivedTimestamp": "2026-01-02T03:06:00Z",
        "stageTimestamp": "2026-01-02T03:06:01Z",
        "verb": verb,
        "user": {"username": actor},
        "sourceIPs": ["192.0.2.10"],
        "objectRef": {"resource": resource, "namespace": namespace, "name": name},
        "requestObject": {
            "metadata": {
                "name": name,
                "namespace": namespace,
                "uid": "4bd54a10-f2b8-45e9-b86f-09eb94bde001",
                "annotations": annotations,
                "labels": {"app.kubernetes.io/name": "fixture-service"},
            }
        },
        "responseStatus": {
            "code": code,
            "status": "Failure" if code == 403 else "Success",
            "reason": "Forbidden" if code == 403 else "",
        },
    }
    if impersonated:
        value["impersonatedUser"] = {"username": impersonated}
    return value


class KubernetesExtractorTests(unittest.TestCase):
    def records(self) -> list[dict]:
        return [
            audit_record(
                "audit-positive",
                resource="deployments",
                name="fixture-deployment",
                verb="patch",
                code=200,
                correlation=CORRELATION,
            ),
            audit_record(
                "audit-denied",
                resource="deployments",
                name="fixture-deployment",
                verb="patch",
                code=403,
                correlation=CORRELATION,
                impersonated=DENIED,
            ),
            audit_record(
                "audit-negative",
                resource="configmaps",
                name="negative-control-no-correlation",
                verb="create",
                code=201,
                correlation=None,
            ),
            audit_record(
                "audit-outside",
                resource="configmaps",
                name="outside",
                verb="create",
                code=201,
                correlation=None,
                namespace="other-namespace",
            ),
        ]

    def write_log(self, path: Path, records: list[dict]) -> None:
        path.write_text(
            "".join(json.dumps(record, sort_keys=True) + "\n" for record in records),
            encoding="utf-8",
        )

    def test_positive_negative_and_rbac_controls(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            log = root / "audit.jsonl"
            self.write_log(log, self.records())
            output = root / "out"
            summary = extractor.write_outputs(
                log,
                output,
                namespace=NAMESPACE,
                correlation_id=CORRELATION,
                denied_principal=DENIED,
                negative_control_name="negative-control-no-correlation",
                cluster_id="kind://fixture-cluster",
            )
            self.assertEqual(summary["scope"]["namespace_records"], 3)
            self.assertEqual(summary["positive_control"]["matching_audit_records"], 2)
            self.assertEqual(summary["rbac_denial"]["matching_http_403_records"], 1)
            self.assertTrue(summary["negative_control"]["validated"])
            public = (output / "public_filtered_audit.jsonl").read_text(encoding="utf-8")
            self.assertNotIn("sourceIPs", public)
            self.assertNotIn("192.0.2.10", public)
            with (output / "normalized_evidence.csv").open(newline="", encoding="utf-8") as handle:
                rows = list(csv.DictReader(handle))
            self.assertEqual(sum(row["correlation_id"] == CORRELATION for row in rows), 2)
            negative = [row for row in rows if "negative-control-no-correlation" in row["correlation_id"]]
            self.assertEqual(len(negative), 1)
            profile_records = [
                json.loads(line)
                for line in (output / "profile_records.jsonl").read_text(encoding="utf-8").splitlines()
            ]
            positive_profile = next(
                record for record in profile_records if record["source_id"].startswith("audit-positive")
            )
            self.assertEqual(
                {link["type"] for link in positive_profile["links"]},
                {
                    "operational_correlation",
                    "workflow_run",
                    "vcs_revision",
                    "artifact_digest",
                    "deployment_uid",
                },
            )

    def test_negative_control_with_id_is_rejected(self):
        records = self.records()
        records[2]["requestObject"]["metadata"]["annotations"]["eacp.io/correlation-id"] = CORRELATION
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            log = root / "audit.jsonl"
            self.write_log(log, records)
            with self.assertRaisesRegex(extractor.ExtractionError, "negative control failed"):
                extractor.write_outputs(
                    log,
                    root / "out",
                    namespace=NAMESPACE,
                    correlation_id=CORRELATION,
                    denied_principal=DENIED,
                    negative_control_name="negative-control-no-correlation",
                    cluster_id="kind://fixture-cluster",
                )


if __name__ == "__main__":
    unittest.main()
