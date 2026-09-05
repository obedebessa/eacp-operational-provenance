from __future__ import annotations

import copy
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

from eacp_hardening.common import HardeningError, canonical_bytes
from eacp_hardening.privacy import (
    POLICY, check_oci_digest, project_github_actions,
    project_github_metadata, project_kubernetes_audit,
)


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "experiments/github_actions"))
import extract_kubernetes_audit_v1_4 as extractor  # noqa: E402

CORRELATION = "eacp-gha-424242-987654321-2"
NAMESPACE = "fixture-namespace"
DENIED = "system:serviceaccount:fixture-namespace:eacp-observer"
DIGEST = "sha256:" + "a" * 64
SHA = "0123456789abcdef0123456789abcdef01234567"
CANARY = "CANARY_DO_NOT_PUBLISH_9a8d"


def audit(audit_id: str = "audit-positive", *, correlation: str | None = CORRELATION,
          name: str = "fixture-deployment", code: int = 200) -> dict:
    annotations = {} if correlation is None else {
        "eacp.io/correlation-id": correlation,
        "eacp.io/github-repository-id": "424242",
        "eacp.io/github-run-id": "987654321",
        "eacp.io/github-run-attempt": "2",
        "eacp.io/github-commit-sha": SHA,
        "eacp.io/subject-uri": "registry.example.invalid/team/service",
        "eacp.io/subject-digest": DIGEST,
    }
    return {"kind": "Event", "apiVersion": "audit.k8s.io/v1", "auditID": audit_id,
            "stage": "ResponseComplete", "requestReceivedTimestamp": "2026-01-02T03:06:00Z",
            "stageTimestamp": "2026-01-02T03:06:01Z", "verb": "patch",
            "user": {"username": "kubernetes-admin"},
            "objectRef": {"apiGroup": "apps", "resource": "deployments", "namespace": NAMESPACE, "name": name},
            "requestObject": {"metadata": {"name": name, "namespace": NAMESPACE, "uid": "uid-1234",
                                              "labels": {"app.kubernetes.io/name": "fixture-service"},
                                              "annotations": annotations}},
            "responseStatus": {"code": code, "reason": "Forbidden" if code == 403 else ""}}


def github_run() -> dict:
    return {"id": 987654321, "run_attempt": 2, "head_sha": SHA,
            "repository": {"id": 424242, "full_name": "example/eacp-fixture", "private": False},
            "created_at": "2026-01-02T03:00:00Z", "updated_at": "2026-01-02T04:00:00Z",
            "actor": {"id": 123, "login": "fixture-user", "type": "User"},
            "status": "completed", "conclusion": "success"}


def control_records() -> list[dict]:
    positive = audit()
    denied = audit("audit-denied", correlation=None, code=403)
    denied.pop("requestObject")
    denied["impersonatedUser"] = {"username": DENIED}
    negative = audit("audit-negative", correlation=None, name="negative-control")
    negative["objectRef"].update({"apiGroup": "", "resource": "configmaps"})
    return [positive, denied, negative]


def options() -> dict:
    return {"namespace": NAMESPACE, "correlation_id": CORRELATION, "denied_principal": DENIED,
            "denied_target_api_group": "apps", "denied_target_resource": "deployments",
            "denied_target_name": "fixture-deployment", "negative_control_name": "negative-control",
            "cluster_id": "kind://fixture-cluster"}


class PrivacyProjectionTests(unittest.TestCase):
    def assert_no_canary(self, result) -> None:
        self.assertNotIn(CANARY, canonical_bytes({"payload": result.payload, "report": result.report}).decode())

    def test_four_demonstrated_kubernetes_gaps_are_dropped(self):
        record = audit()
        record["requestObject"]["metadata"]["annotations"]["example.test/note"] = CANARY
        record["requestObject"]["spec"] = {"containers": [{"env": [{"name": "API_KEY", "value": CANARY}]}]}
        record["requestObject"]["data"] = {"application_password": CANARY}
        record["requestURI"] = "/api/v1/pods?access_token=" + CANARY
        result = project_kubernetes_audit(record)
        self.assert_no_canary(result)
        self.assertNotIn("requestURI", result.payload)
        self.assertEqual(set(result.payload["requestObject"]), {"metadata"})
        self.assertEqual(result.payload["requestObject"]["metadata"]["annotations"]["eacp.io/correlation-id"], CORRELATION)
        self.assertEqual(result.report["dropped_member_count"], 5)  # includes free-text reason

    def test_nested_unknown_values_and_sensitive_field_names_do_not_enter_report(self):
        record = audit()
        record[CANARY] = {CANARY: [CANARY, {"nested": CANARY}]}
        record["requestObject"]["metadata"]["annotations"][CANARY] = CANARY
        record["user"]["extra"] = {CANARY: [CANARY]}
        result = project_kubernetes_audit(record)
        self.assert_no_canary(result)
        self.assertIn({"path": "/requestObject/metadata/annotations/*", "reason": "not_allowlisted", "count": 1}, result.report["drops"])

    def test_kubernetes_all_urls_body_messages_and_credentials_are_dropped(self):
        record = audit()
        record.update({"requestURI": "https://user:" + CANARY + "@api.invalid/a?token=" + CANARY + "#" + CANARY,
                       "sourceIPs": [CANARY], "annotations": {"authorization.k8s.io/reason": CANARY}})
        record["responseStatus"].update({"message": CANARY, "details": {"causes": [CANARY]}})
        record["responseObject"] = {"metadata": {"name": "fixture-deployment"}, "data": {"tls.key": CANARY}}
        self.assert_no_canary(project_kubernetes_audit(record))

    def test_json_patch_body_is_omitted_without_interpreting_paths_or_values(self):
        record = audit()
        record["responseObject"] = record["requestObject"]
        record["requestObject"] = [{"op": "add", "path": CANARY, "value": CANARY}]
        result = project_kubernetes_audit(record)
        self.assert_no_canary(result)
        self.assertEqual(result.payload["requestObject"], {})

    def test_required_and_allowlisted_malformed_types_reject_without_echo(self):
        cases = [lambda r: r.pop("auditID"), lambda r: r.update(auditID=[CANARY]),
                 lambda r: r.update(user=CANARY), lambda r: r.update(stageTimestamp=CANARY),
                 lambda r: r["responseStatus"].update(code=True),
                 lambda r: r["requestObject"]["metadata"].update(annotations=[CANARY]),
                 lambda r: r["requestObject"]["metadata"]["annotations"].update({"eacp.io/correlation-id": {"value": CANARY}}),
                 lambda r: r.update(requestObject=CANARY), lambda r: r.update({1: CANARY})]
        for mutate in cases:
            record = audit()
            mutate(record)
            with self.subTest(record_type=type(record)), self.assertRaises(HardeningError) as caught:
                project_kubernetes_audit(record)
            self.assertNotIn(CANARY, str(caught.exception))

    def test_sensitive_resource_and_identity_conflict_fail_closed(self):
        for resource in ("secrets", "tokenreviews", "subjectaccessreviews"):
            record = audit()
            record["objectRef"]["resource"] = resource
            with self.assertRaises(HardeningError):
                project_kubernetes_audit(record)
        record = audit()
        record["requestObject"]["metadata"]["namespace"] = "another-namespace"
        with self.assertRaises(HardeningError):
            project_kubernetes_audit(record)
        with self.assertRaises(HardeningError):
            project_kubernetes_audit(audit(), namespace="another-namespace")

    def test_collection_and_create_without_object_ref_name_preserve_source_identity(self):
        for verb in ("list", "create"):
            record = audit(correlation=None)
            record["objectRef"].pop("name")
            record["verb"] = verb
            result = project_kubernetes_audit(record)
            self.assertEqual(result.payload["auditID"], record["auditID"])
            self.assertNotIn("name", result.payload["objectRef"])
            self.assertEqual(result.payload["requestObject"]["metadata"]["name"], "fixture-deployment")

    def test_conflicting_and_partial_typed_linkage_is_rejected(self):
        record = audit()
        record["responseObject"] = copy.deepcopy(record["requestObject"])
        record["responseObject"]["metadata"]["annotations"]["eacp.io/correlation-id"] = "different-id"
        with self.assertRaises(HardeningError):
            project_kubernetes_audit(record)
        record = audit()
        record["requestObject"]["metadata"]["annotations"].pop("eacp.io/subject-digest")
        with self.assertRaises(HardeningError):
            project_kubernetes_audit(record)

    def test_oci_uri_credentials_and_query_are_rejected_without_echo(self):
        for uri in ("https://user:" + CANARY + "@registry.invalid/a", "registry.invalid/a?token=" + CANARY, "registry.invalid/a#" + CANARY):
            record = audit()
            record["requestObject"]["metadata"]["annotations"]["eacp.io/subject-uri"] = uri
            with self.assertRaises(HardeningError) as caught:
                project_kubernetes_audit(record)
            self.assertNotIn(CANARY, str(caught.exception))

    def test_projection_and_report_are_deterministic_and_input_is_unchanged(self):
        record = audit()
        record["unknown"] = CANARY
        original = copy.deepcopy(record)
        first = project_kubernetes_audit(record)
        second = project_kubernetes_audit(dict(reversed(list(record.items()))))
        self.assertEqual(first, second)
        self.assertEqual(record, original)
        self.assertEqual(first.report["policy"], POLICY)

    def test_allowed_identifiers_remain_attributable_and_require_review(self):
        record = audit()
        record["user"]["username"] = "syntactically-valid-sensitive-identity"
        result = project_kubernetes_audit(record)
        self.assertEqual(result.payload["user"]["username"], record["user"]["username"])
        self.assertTrue(result.report["manual_publication_review_required"])

    def test_github_unknown_free_text_and_url_credentials_never_survive(self):
        record = github_run()
        dirty_url = "https://user:" + CANARY + "@github.com/example/eacp-fixture/actions/runs/987654321?token=" + CANARY + "#" + CANARY
        for key in ("name", "display_title", "head_branch", "path", "html_url", "url", "jobs_url", "logs", "event_payload"):
            record[key] = dirty_url if "url" in key else {CANARY: CANARY}
        record["actor"].update({"email": CANARY, "html_url": dirty_url})
        record["repository"].update({"description": CANARY, "html_url": dirty_url})
        result = project_github_metadata(record)
        self.assert_no_canary(result)
        self.assertEqual(result.payload["html_url"], "https://github.com/example/eacp-fixture/actions/runs/987654321")
        self.assertEqual(result.payload["head_sha"], SHA)
        self.assertEqual(result.payload["actor"]["login"], "fixture-user")

    def test_github_job_artifact_projection_and_run_binding(self):
        job = {"id": 55, "run_id": 987654321, "run_attempt": 2, "name": CANARY, "steps": [{"name": CANARY}], "runner_name": CANARY}
        artifact = {"id": 77, "workflow_run": {"id": 987654321, "repository_id": 424242, "head_sha": SHA, "head_branch": CANARY},
                    "name": CANARY, "digest": DIGEST, "archive_download_url": "https://user:" + CANARY + "@invalid/a?token=" + CANARY}
        result = project_github_actions(github_run(), [job], [artifact])
        self.assert_no_canary(result)
        self.assertEqual(result.payload["artifacts"][0]["digest"], DIGEST)
        for group, replacement in (("job", {**job, "run_attempt": 1}), ("artifact", {**artifact, "workflow_run": {"id": 999}})):
            with self.subTest(group=group), self.assertRaises(HardeningError):
                project_github_actions(github_run(), [replacement] if group == "job" else [job], [replacement] if group == "artifact" else [artifact])
        with self.assertRaises(HardeningError):
            project_github_actions(github_run(), [job, job], [artifact])

    def test_github_malformed_allowed_types_private_and_missing_identity_reject(self):
        for change in (lambda r: r.update(id=True), lambda r: r.pop("head_sha"),
                       lambda r: r.update(actor=[CANARY]), lambda r: r["repository"].update(private=True),
                       lambda r: r["repository"].update(private="false"),
                       lambda r: r.update(status=CANARY), lambda r: r.update(created_at=CANARY)):
            record = github_run()
            change(record)
            with self.assertRaises(HardeningError) as caught:
                project_github_metadata(record)
            self.assertNotIn(CANARY, str(caught.exception))

    def test_github_reconstructed_url_rejects_path_traversal_identity(self):
        for name in ("../repository", "example/..", "./repository"):
            record = github_run()
            record["repository"]["full_name"] = name
            with self.assertRaises(HardeningError):
                project_github_metadata(record)

    def test_oci_comparison_is_independent_and_not_source_authentication(self):
        self.assertTrue(check_oci_digest(DIGEST, DIGEST)["matched"])
        result = check_oci_digest(DIGEST, "sha256:" + "b" * 64)
        self.assertFalse(result["matched"])
        self.assertTrue(result["independent_of_correlation"])
        self.assertFalse(result["source_authenticity_established"])


class PrivacyExtractorIntegrationTests(unittest.TestCase):
    def test_exact_no_id_and_explicit_403_controls_survive_minimization(self):
        records = control_records()
        records[0]["requestObject"]["spec"] = {"env": {"password": CANARY}}
        result = extractor.extract_records(records, **options(), expected_subject_digest=DIGEST, observed_subject_digest=DIGEST)
        self.assertNotIn(CANARY, canonical_bytes(result).decode())
        rows = {row["source_id"]: row for row in result["evidence_rows"]}
        self.assertEqual(rows["audit-positive:ResponseComplete"]["correlation_id"], CORRELATION)
        self.assertEqual(rows["audit-denied:ResponseComplete"]["correlation_id"], CORRELATION)
        self.assertEqual(rows["audit-negative:ResponseComplete"]["correlation_id"], "")
        profiles = {row["source_id"]: row for row in result["profile_records"]}
        for key, method in (("audit-positive:ResponseComplete", "source_native"), ("audit-denied:ResponseComplete", "explicit")):
            links = [link for link in profiles[key]["links"] if link["type"] == "operational_correlation"]
            self.assertEqual(links[0]["evidence_method"], method)
        self.assertFalse(any(link["type"] == "operational_correlation" for link in profiles["audit-negative:ResponseComplete"]["links"]))
        self.assertTrue(result["summary"]["oci_digest_check"]["matched"])
        self.assertIn(POLICY, profiles["audit-positive:ResponseComplete"]["source_digest"]["canonicalization"])

    def test_wrong_principal_403_is_not_bound_even_when_valid_control_exists(self):
        records = control_records()
        wrong = audit("audit-other-denial", correlation=None, code=403)
        wrong.pop("requestObject")
        records.append(wrong)
        result = extractor.extract_records(records, **options())
        row = next(row for row in result["evidence_rows"] if row["source_id"].startswith("audit-other-denial"))
        self.assertEqual(row["correlation_id"], "")
        self.assertFalse(result["summary"]["oci_digest_check"]["performed"])

    def test_response_only_correlation_cannot_pass_as_no_id_control(self):
        records = control_records()
        records[2]["responseObject"] = copy.deepcopy(records[2]["requestObject"])
        records[2]["responseObject"]["metadata"]["annotations"] = {"eacp.io/correlation-id": CORRELATION}
        with self.assertRaisesRegex(HardeningError, "no-ID"):
            extractor.extract_records(records, **options())

    def test_combined_body_linkage_preserves_response_links_and_original_source_digest(self):
        records = control_records()
        records[0]["responseObject"] = copy.deepcopy(records[0]["requestObject"])
        records[0]["requestObject"]["metadata"]["annotations"] = {}
        original = copy.deepcopy(records)
        result = extractor.extract_records(records, **options(), expected_subject_digest=DIGEST, observed_subject_digest=DIGEST)
        profile = next(row for row in result["profile_records"] if row["source_id"].startswith("audit-positive"))
        links = [link for link in profile["links"] if link["type"] == "operational_correlation"]
        self.assertEqual((links[0]["value"], links[0]["evidence_method"]), (CORRELATION, "source_native"))
        public = next(row for row in result["public_records"] if row["auditID"] == "audit-positive")
        self.assertEqual(profile["source_digest"]["value"], hashlib.sha256(canonical_bytes(public)).hexdigest())
        self.assertEqual(public["requestObject"]["metadata"]["annotations"], {})
        self.assertEqual(records, original)

    def test_combined_body_identity_and_linkage_conflicts_reject(self):
        for key in ("uid", "correlation"):
            records = control_records()
            records[0]["responseObject"] = copy.deepcopy(records[0]["requestObject"])
            if key == "uid":
                records[0]["responseObject"]["metadata"]["uid"] = "different-object-uid"
            else:
                records[0]["responseObject"]["metadata"]["annotations"]["eacp.io/correlation-id"] = "different-correlation"
            with self.subTest(key=key), self.assertRaises(HardeningError):
                extractor.extract_records(records, **options())

    def test_native_403_is_not_misclassified_as_adapter_explicit(self):
        for declared in (CORRELATION, "different-native-correlation"):
            records = control_records()
            records[1]["responseObject"] = {"metadata": {"annotations": {"eacp.io/correlation-id": declared}}}
            with self.subTest(declared=declared), self.assertRaisesRegex(HardeningError, "native correlation"):
                extractor.extract_records(records, **options())

    def test_positive_on_an_unrelated_target_cannot_justify_adapter_join(self):
        records = control_records()
        records[0]["objectRef"]["name"] = "unrelated-deployment"
        records[0]["requestObject"]["metadata"]["name"] = "unrelated-deployment"
        with self.assertRaisesRegex(HardeningError, "declared adapter target"):
            extractor.extract_records(records, **options())

    def test_failed_controls_and_mismatched_digest_reject(self):
        for index in (0, 1, 2):
            records = control_records()
            records.pop(index)
            with self.assertRaises(HardeningError):
                extractor.extract_records(records, **options())
        records = control_records()
        records[2]["requestObject"]["metadata"]["annotations"]["eacp.io/correlation-id"] = CORRELATION
        with self.assertRaises(HardeningError):
            extractor.extract_records(records, **options())
        with self.assertRaises(HardeningError):
            extractor.extract_records(control_records(), **options(), expected_subject_digest=DIGEST, observed_subject_digest="sha256:" + "b" * 64)

    def test_duplicate_identity_and_query_only_namespace_reject(self):
        records = control_records()
        with self.assertRaises(HardeningError):
            extractor.extract_records(records + [records[0]], **options())
        records[0]["objectRef"].pop("namespace")
        records[0]["requestURI"] = "/api/v1/namespaces/fixture-namespace/pods?" + CANARY
        with self.assertRaises(HardeningError) as caught:
            extractor.extract_records(records, **options())
        self.assertNotIn(CANARY, str(caught.exception))

    def test_unscoped_and_outside_namespace_records_are_counted_without_retention(self):
        records = control_records()
        outside = audit("outside")
        outside["objectRef"]["namespace"] = "another-namespace"
        outside["requestObject"]["data"] = {CANARY: CANARY}
        records.extend([outside, {"kind": "Event", "requestURI": "/healthz?token=" + CANARY},
                        {"objectRef": {"resource": "nodes"}, "extra": CANARY}])
        result = extractor.extract_records(records, **options())
        self.assertEqual(result["summary"]["records"], 3)
        self.assertEqual(result["privacy_report"]["excluded_scope_records"], 1)
        self.assertEqual(result["privacy_report"]["excluded_unscoped_records"], 2)
        self.assertNotIn(CANARY, canonical_bytes(result).decode())

    def test_write_outputs_minimized_checksums_and_existing_destination(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "audit.jsonl"
            records = control_records()
            records[0]["requestURI"] = "https://user:" + CANARY + "@invalid/path?token=" + CANARY
            source.write_text("".join(json.dumps(record) + "\n" for record in records), encoding="utf-8")
            output = root / "public"
            extractor.write_outputs(source, output, **options())
            for path in output.iterdir():
                self.assertNotIn(CANARY, path.read_text(encoding="utf-8"))
            for line in (output / "SHA256SUMS").read_text().splitlines():
                digest, name = line.split("  ")
                self.assertEqual(hashlib.sha256((output / name).read_bytes()).hexdigest(), digest)
            with self.assertRaises(HardeningError):
                extractor.write_outputs(source, output, **options())

    def test_failure_does_not_create_partial_publication(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "bad.jsonl"
            source.write_text(json.dumps(audit()) + "\n", encoding="utf-8")
            output = root / "public"
            with self.assertRaises(HardeningError):
                extractor.write_outputs(source, output, **options())
            self.assertFalse(output.exists())
            source.write_text(CANARY, encoding="utf-8")
            with self.assertRaises(HardeningError) as caught:
                extractor.write_outputs(source, output, **options())
            self.assertNotIn(CANARY, str(caught.exception))


if __name__ == "__main__":
    unittest.main()
